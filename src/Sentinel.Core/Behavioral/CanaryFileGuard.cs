using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Sentinel.Core.Behavioral;

/// <summary>Шаблон файла-приманки: расширение и валидный заголовок формата.</summary>
public sealed record CanaryTemplate(string Extension, byte[] Header);

/// <summary>Событие вмешательства в файл-приманку (изменение, перезапись, шифрование, переименование, удаление).</summary>
public sealed record CanaryTamperEvent(string Path, string Reason);

/// <summary>
/// Файлы-приманки (canary) в пользовательских каталогах. Приманки имеют валидные заголовки форматов и предрассчитанный
/// SHA-256; их пути регистрируются во внутреннем реестре, чтобы штатный сканер их игнорировал. Любое внешнее изменение,
/// перезапись, переименование или удаление приманки — сигнал шифровальщика (вес +85). Нетронутые приманки удаляются при остановке.
/// </summary>
public sealed class CanaryFileGuard
{
    /// <summary>Вес события вмешательства в приманку в баллах риска.</summary>
    public const int TamperScore = 85;

    private const int BufferSize = 65536;

    private static readonly CanaryTemplate[] Templates =
    [
        new(".docx", [0x50, 0x4B, 0x03, 0x04]),                        // ZIP (OOXML)
        new(".xlsx", [0x50, 0x4B, 0x03, 0x04]),
        new(".pdf", "%PDF-1.5\n%âãÏÓ\n"u8.ToArray()),
        new(".txt", "Sentinel integrity canary. Do not modify.\r\n"u8.ToArray()),
    ];

    private readonly ConcurrentDictionary<string, string> _canaries = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _prefix;

    public CanaryFileGuard(string? namePrefix = null) => _prefix = namePrefix ?? "~$sentinel_integrity";

    /// <summary>Зарегистрированные пути приманок.</summary>
    public IReadOnlyCollection<string> Paths => _canaries.Keys.ToArray();

    public int Count => _canaries.Count;

    /// <summary>Создаёт приманки в указанных каталогах (по одной на шаблон). Возвращает пути успешно созданных файлов.</summary>
    public IReadOnlyList<string> Deploy(IEnumerable<string> directories)
    {
        ArgumentNullException.ThrowIfNull(directories);
        var created = new List<string>();
        foreach (var directory in directories.Where(d => !string.IsNullOrWhiteSpace(d)))
        {
            if (!Directory.Exists(directory))
            {
                continue;
            }

            foreach (var template in Templates)
            {
                var path = Path.Combine(directory, _prefix + template.Extension);
                try
                {
                    using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
                    {
                        stream.Write(template.Header);
                    }

                    SetHiddenBestEffort(path);
                    _canaries[Path.GetFullPath(path)] = ComputeHash(path);
                    created.Add(path);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Каталог недоступен для записи (например, в WinRE) — приманка просто не ставится.
                }
            }
        }

        return created;
    }

    /// <summary>Является ли путь зарегистрированной приманкой (штатный сканер должен их пропускать).</summary>
    public bool IsCanary(string? path) =>
        !string.IsNullOrEmpty(path) && _canaries.ContainsKey(Path.GetFullPath(path));

    /// <summary>
    /// Проверяет, не вмешались ли в приманку. Возвращает событие, если файл исчез или его содержимое изменилось
    /// (сравнение SHA-256 с эталоном). Для не-приманок возвращает <c>null</c>.
    /// </summary>
    public CanaryTamperEvent? Inspect(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        var full = Path.GetFullPath(path);
        if (!_canaries.TryGetValue(full, out var expected))
        {
            return null;
        }

        if (!File.Exists(full))
        {
            return new CanaryTamperEvent(full, "Файл-приманка удалён или переименован.");
        }

        try
        {
            return string.Equals(ComputeHash(full), expected, StringComparison.Ordinal)
                ? null
                : new CanaryTamperEvent(full, "Содержимое файла-приманки изменено (возможно шифрование).");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new CanaryTamperEvent(full, "Файл-приманка заблокирован сторонним процессом.");
        }
    }

    /// <summary>Удаляет только нетронутые приманки (при штатном отключении функции или остановке службы).</summary>
    public void RemoveUntouched()
    {
        foreach (var (path, expected) in _canaries.ToArray())
        {
            try
            {
                if (File.Exists(path) && string.Equals(ComputeHash(path), expected, StringComparison.Ordinal))
                {
                    File.Delete(path);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // приманка занята — оставляем как есть
            }

            _canaries.TryRemove(path, out _);
        }
    }

    private static string ComputeHash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, BufferSize, FileOptions.SequentialScan);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[BufferSize];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(sha.GetHashAndReset());
    }

    private static void SetHiddenBestEffort(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetAttributes(path, FileAttributes.Hidden);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // не критично
        }
    }
}
