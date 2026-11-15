using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Remediation;

/// <summary>
/// Изолированный карантин. Файл не удаляется безвозвратно: его содержимое переносится в защищённый
/// каталог в XOR-преобразованном виде (контейнер нельзя случайно запустить, и он не совпадает
/// с сигнатурами), а всё необходимое для отката записывается в <c>quarantine_manifest.json</c>.
/// Перед любым действием выполняется проверка белого списка: подписанные системные файлы Windows
/// изолировать запрещено.
/// </summary>
public sealed class QuarantineManager : IDisposable
{
    private const int BufferSize = 1 << 16;
    private const int KeyLength = 32;
    private const string ContainerExtension = ".qnt";

    private static readonly JsonSerializerOptions ManifestJson = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private readonly IWhitelistProvider _whitelist;
    private readonly string _directory;
    private readonly string _manifestPath;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public QuarantineManager(IWhitelistProvider whitelist, QuarantineOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(whitelist);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(options.QuarantineDirectory);
        _whitelist = whitelist;
        _directory = Path.GetFullPath(options.QuarantineDirectory);
        _manifestPath = Path.Combine(_directory, QuarantineOptions.ManifestFileName);
        _time = timeProvider ?? TimeProvider.System;
    }

    public void Dispose() => _gate.Dispose();

    public string QuarantineDirectory => _directory;

    public string ManifestPath => _manifestPath;

    /// <summary>Все записи манифеста (включая уже восстановленные), от новых к старым.</summary>
    public async Task<IReadOnlyList<QuarantineRecord>> ListAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var manifest = await LoadManifestAsync(cancellationToken).ConfigureAwait(false);
            return manifest.Entries.OrderByDescending(e => e.QuarantinedAtUtc).ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Изолирует файл. При <paramref name="dryRun"/> выполняются только проверки (существование,
    /// белый список) — файл и манифест не изменяются.
    /// </summary>
    public async Task<QuarantineResult> QuarantineAsync(
        string path, string reason, bool dryRun = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(reason);

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new QuarantineResult(QuarantineStatus.Failed, $"Некорректный путь: {ex.Message}");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await QuarantineCoreAsync(fullPath, reason, dryRun, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new QuarantineResult(QuarantineStatus.Failed, $"Не удалось изолировать '{fullPath}': {ex.Message}");
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<QuarantineResult> QuarantineCoreAsync(string fullPath, string reason, bool dryRun, CancellationToken ct)
    {
        var info = new FileInfo(fullPath);
        if (!info.Exists)
        {
            return new QuarantineResult(QuarantineStatus.NotFound,
                Directory.Exists(fullPath) ? $"'{fullPath}' — каталог; изолируются только файлы." : $"Файл не найден: {fullPath}");
        }

        if (IsInsideQuarantine(fullPath))
        {
            return new QuarantineResult(QuarantineStatus.Failed, "Файл уже находится в каталоге карантина.");
        }

        // Самозащита: файлы ядра ОС и каталоги самого Sentinel не изолируются ни при каких вердиктах.
        if (Scanning.SelfProtection.IsProtectedFile(fullPath, _directory))
        {
            return new QuarantineResult(QuarantineStatus.BlockedByWhitelist,
                $"Изоляция запрещена: '{fullPath}' — критический файл Windows или каталог Sentinel (самозащита).");
        }

        // Жёсткий запрет: белый список проверяется до любых изменений файла или его атрибутов.
        var decision = _whitelist.Evaluate(fullPath);
        if (decision.IsWhitelisted)
        {
            return new QuarantineResult(QuarantineStatus.BlockedByWhitelist,
                $"Изоляция запрещена: '{fullPath}' — доверенный системный файл ({decision.Reason}).");
        }

        if (info.LinkTarget is not null)
        {
            return new QuarantineResult(QuarantineStatus.Failed,
                $"'{fullPath}' — символическая ссылка на '{info.LinkTarget}'; изолируйте целевой файл.");
        }

        if (dryRun)
        {
            return new QuarantineResult(QuarantineStatus.WouldQuarantine, $"Будет изолирован: {fullPath}");
        }

        EnsureDirectory();
        var manifest = await LoadManifestAsync(ct).ConfigureAwait(false);

        var originalAttributes = info.Attributes;
        var originalMode = OperatingSystem.IsWindows() ? (UnixFileMode?)null : File.GetUnixFileMode(fullPath);
        var lastWrite = info.LastWriteTimeUtc;
        var size = info.Length;

        var id = Guid.NewGuid().ToString("N");
        var storedName = id + ContainerExtension;
        var storedPath = Path.Combine(_directory, storedName);
        var key = CreateKey();

        // Снятие защитных атрибутов: без этого файл нельзя ни переместить, ни удалить.
        var attributesChanged = false;
        var stripped = originalAttributes & ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);
        if (stripped != originalAttributes)
        {
            File.SetAttributes(fullPath, stripped == 0 ? FileAttributes.Normal : stripped);
            attributesChanged = true;
        }

        var containerCreated = false;
        var manifestSaved = false;
        try
        {
            string sha256;
            await using (var source = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, BufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var target = CreateContainer(storedPath))
            {
                containerCreated = true;
                sha256 = await TransformAsync(source, target, key, hashInput: true, ct).ConfigureAwait(false);
                await target.FlushAsync(ct).ConfigureAwait(false);
                target.Flush(flushToDisk: true);
            }

            // Контрольное чтение: исходный файл удаляется только после того, как контейнер
            // гарантированно декодируется обратно в те же байты.
            var verify = await DecodeHashAsync(storedPath, key, ct).ConfigureAwait(false);
            if (!string.Equals(verify, sha256, StringComparison.Ordinal))
            {
                throw new IOException("Контрольная проверка контейнера карантина не пройдена (SHA-256 не совпал).");
            }

            var record = new QuarantineRecord
            {
                Id = id,
                OriginalPath = fullPath,
                OriginalAttributes = originalAttributes,
                OriginalUnixMode = originalMode,
                OriginalLastWriteTimeUtc = lastWrite,
                Size = size,
                Sha256 = sha256,
                QuarantinedAtUtc = _time.GetUtcNow().UtcDateTime,
                Reason = reason,
                XorKey = Convert.ToBase64String(key),
                StoredFileName = storedName,
            };

            manifest.Entries.Add(record);
            await SaveManifestAsync(manifest, ct).ConfigureAwait(false);
            manifestSaved = true;

            File.Delete(fullPath);
            return new QuarantineResult(QuarantineStatus.Quarantined, $"Изолирован: {fullPath} → {storedName}", record);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            // Откат: исходный файл остаётся на месте в прежнем состоянии, следов в карантине нет.
            if (manifestSaved)
            {
                manifest.Entries.RemoveAll(e => e.Id == id);
                await SaveManifestAsync(manifest, CancellationToken.None).ConfigureAwait(false);
            }

            if (containerCreated)
            {
                TryDelete(storedPath);
            }

            if (attributesChanged && File.Exists(fullPath))
            {
                File.SetAttributes(fullPath, originalAttributes);
            }

            if (ex is OperationCanceledException)
            {
                throw;
            }

            return new QuarantineResult(QuarantineStatus.Failed, $"Не удалось изолировать '{fullPath}': {ex.Message}");
        }
    }

    /// <summary>
    /// Полное восстановление файла на исходное место: обратное XOR-преобразование, сверка SHA-256
    /// с манифестом, возврат исходных атрибутов и времени изменения. <paramref name="id"/> —
    /// полный идентификатор записи или его уникальный префикс (не короче 6 символов).
    /// </summary>
    public async Task<RestoreResult> RestoreAsync(string id, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await RestoreCoreAsync(id.Trim(), overwrite, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or FormatException or NotSupportedException)
        {
            return new RestoreResult(RestoreStatus.Failed, $"Не удалось восстановить запись '{id}': {ex.Message}");
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<RestoreResult> RestoreCoreAsync(string id, bool overwrite, CancellationToken ct)
    {
        var manifest = await LoadManifestAsync(ct).ConfigureAwait(false);
        var matches = manifest.Entries
            .Where(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase)
                || (id.Length >= 6 && e.Id.StartsWith(id, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        if (matches.Length == 0)
        {
            return new RestoreResult(RestoreStatus.NotFound, $"Запись карантина '{id}' не найдена.");
        }

        if (matches.Length > 1)
        {
            return new RestoreResult(RestoreStatus.NotFound, $"Префикс '{id}' неоднозначен: подходит записей — {matches.Length}.");
        }

        var record = matches[0];
        if (record.State == QuarantineState.Restored)
        {
            return new RestoreResult(RestoreStatus.AlreadyRestored, $"Запись {record.Id} уже восстановлена.", record);
        }

        // Имя контейнера берётся из манифеста, но обязано оставаться внутри каталога карантина.
        var storedPath = Path.GetFullPath(Path.Combine(_directory, record.StoredFileName));
        if (!IsInsideQuarantine(storedPath) || !File.Exists(storedPath))
        {
            return new RestoreResult(RestoreStatus.Failed, $"Контейнер карантина '{record.StoredFileName}' отсутствует.", record);
        }

        if (!overwrite && (File.Exists(record.OriginalPath) || Directory.Exists(record.OriginalPath)))
        {
            return new RestoreResult(RestoreStatus.TargetExists,
                $"На исходном месте уже существует объект: {record.OriginalPath}", record);
        }

        var key = Convert.FromBase64String(record.XorKey);
        if (key.Length == 0)
        {
            return new RestoreResult(RestoreStatus.Failed, "В манифесте отсутствует ключ преобразования.", record);
        }

        var targetDirectory = Path.GetDirectoryName(record.OriginalPath);
        if (!string.IsNullOrEmpty(targetDirectory))
        {
            Directory.CreateDirectory(targetDirectory);
        }

        // Декодирование во временный файл рядом с целью: на исходное место попадают только проверенные данные.
        var tempPath = record.OriginalPath + ".sentinel-restore-" + record.Id[..8];
        try
        {
            string sha256;
            await using (var source = new FileStream(storedPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var target = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize, FileOptions.Asynchronous))
            {
                sha256 = await TransformAsync(source, target, key, hashInput: false, ct).ConfigureAwait(false);
                await target.FlushAsync(ct).ConfigureAwait(false);
                target.Flush(flushToDisk: true);
            }

            if (!string.Equals(sha256, record.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                TryDelete(tempPath);
                return new RestoreResult(RestoreStatus.HashMismatch,
                    $"SHA-256 восстановленных данных ({sha256}) не совпадает с манифестом ({record.Sha256}); файл не возвращён.", record);
            }

            File.Move(tempPath, record.OriginalPath, overwrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            TryDelete(tempPath);
            if (ex is OperationCanceledException)
            {
                throw;
            }

            return new RestoreResult(RestoreStatus.Failed, $"Не удалось восстановить '{record.OriginalPath}': {ex.Message}", record);
        }

        File.SetLastWriteTimeUtc(record.OriginalPath, record.OriginalLastWriteTimeUtc);
        if (!OperatingSystem.IsWindows() && record.OriginalUnixMode is { } mode)
        {
            File.SetUnixFileMode(record.OriginalPath, mode);
        }

        File.SetAttributes(record.OriginalPath, record.OriginalAttributes);

        var restored = record with { State = QuarantineState.Restored, RestoredAtUtc = _time.GetUtcNow().UtcDateTime };
        manifest.Entries[manifest.Entries.IndexOf(record)] = restored;
        await SaveManifestAsync(manifest, ct).ConfigureAwait(false);
        TryDelete(storedPath);

        return new RestoreResult(RestoreStatus.Restored, $"Восстановлен: {record.OriginalPath}", restored);
    }

    // ---- XOR-преобразование ----------------------------------------------------

    /// <summary>
    /// Обратимое преобразование: каждый байт складывается по модулю 2 с байтом ключа по позиции.
    /// Все байты ключа ненулевые, поэтому ни один байт файла (включая сигнатуру «MZ») не остаётся прежним.
    /// </summary>
    internal static void Xor(Span<byte> data, ReadOnlySpan<byte> key, long position)
    {
        var k = (int)(position % key.Length);
        for (var i = 0; i < data.Length; i++)
        {
            data[i] ^= key[k];
            if (++k == key.Length)
            {
                k = 0;
            }
        }
    }

    private static byte[] CreateKey()
    {
        var key = RandomNumberGenerator.GetBytes(KeyLength);
        for (var i = 0; i < key.Length; i++)
        {
            while (key[i] == 0)
            {
                key[i] = RandomNumberGenerator.GetBytes(1)[0];
            }
        }

        return key;
    }

    /// <summary>
    /// Копирует поток с XOR-преобразованием и возвращает SHA-256 «открытой» стороны:
    /// входа при кодировании (<paramref name="hashInput"/>) или выхода при декодировании.
    /// </summary>
    private static async Task<string> TransformAsync(Stream source, Stream target, byte[] key, bool hashInput, CancellationToken ct)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[BufferSize];
        long position = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            if (hashInput)
            {
                sha.AppendData(buffer, 0, read);
            }

            Xor(buffer.AsSpan(0, read), key, position);
            if (!hashInput)
            {
                sha.AppendData(buffer, 0, read);
            }

            await target.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            position += read;
        }

        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    private static async Task<string> DecodeHashAsync(string storedPath, byte[] key, CancellationToken ct)
    {
        await using var source = new FileStream(storedPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await TransformAsync(source, Stream.Null, key, hashInput: false, ct).ConfigureAwait(false);
    }

    // ---- Каталог и манифест ----------------------------------------------------

    private static FileStream CreateContainer(string storedPath)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            BufferSize = BufferSize,
            Options = FileOptions.Asynchronous,
        };
        if (!OperatingSystem.IsWindows())
        {
            // Контейнер никогда не получает бит исполнения.
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        return new FileStream(storedPath, options);
    }

    private void EnsureDirectory()
    {
        if (Directory.Exists(_directory))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(_directory);
            ProtectWindowsDirectory(_directory);
        }
        else
        {
            Directory.CreateDirectory(_directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    /// <summary>
    /// Закрывает каталог карантина: наследование ACL отключается, доступ остаётся только у SYSTEM,
    /// администраторов и текущего пользователя; каталог помечается скрытым и системным.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void ProtectWindowsDirectory(string directory)
    {
        var info = new DirectoryInfo(directory);
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            void Allow(IdentityReference identity) => security.AddAccessRule(new FileSystemAccessRule(
                identity, FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));

            Allow(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            Allow(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            using (var current = WindowsIdentity.GetCurrent())
            {
                if (current.User is { } user)
                {
                    Allow(user);
                }
            }

            info.SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or IdentityNotMappedException)
        {
            // Нет права менять ACL (например, каталог на FAT) — карантин остаётся работоспособным
            // с унаследованными правами; содержимое в любом случае XOR-преобразовано.
        }

        info.Attributes |= FileAttributes.Hidden | FileAttributes.System | FileAttributes.NotContentIndexed;
    }

    private bool IsInsideQuarantine(string fullPath) =>
        fullPath.StartsWith(_directory + Path.DirectorySeparatorChar, PathComparison);

    private async Task<Manifest> LoadManifestAsync(CancellationToken ct)
    {
        if (!File.Exists(_manifestPath))
        {
            return new Manifest();
        }

        await using var stream = new FileStream(_manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.Asynchronous);
        var manifest = await JsonSerializer.DeserializeAsync<Manifest>(stream, ManifestJson, ct).ConfigureAwait(false);
        return manifest ?? new Manifest();
    }

    /// <summary>Атомарная запись: во временный файл с последующей заменой — манифест не бывает «полузаписанным».</summary>
    private async Task SaveManifestAsync(Manifest manifest, CancellationToken ct)
    {
        EnsureDirectory();
        var temp = _manifestPath + ".tmp";
        await using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize, FileOptions.Asynchronous))
        {
            await JsonSerializer.SerializeAsync(stream, manifest, ManifestJson, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, _manifestPath, overwrite: true);
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Очистка «по возможности»: основная операция уже завершена или откатывается.
        }
    }

    internal sealed class Manifest
    {
        public int Version { get; set; } = 1;

        public List<QuarantineRecord> Entries { get; set; } = [];
    }
}
