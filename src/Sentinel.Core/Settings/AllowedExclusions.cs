using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.Audit.Config;

namespace Sentinel.Core.Settings;

/// <summary>
/// Пользовательский белый список (<c>allowed_exclusions.json</c>): пути и процессы, которые владелец
/// системы явно разрешил. Объекты из списка не изолируются и не завершаются, а совпадающие с ним
/// исключения Defender не удаляются при <c>audit-config --remediate</c>.
/// Системный белый список (подписанные файлы Windows) этим файлом не затрагивается.
/// </summary>
public sealed record AllowedExclusions
{
    public static AllowedExclusions Empty { get; } = new();

    /// <summary>Разрешённые файлы и каталоги (каталог покрывает всё своё содержимое; допустимы <c>*</c> и <c>?</c>).</summary>
    public IReadOnlyList<string> Paths { get; init; } = [];

    /// <summary>Разрешённые процессы: имя образа (<c>tool.exe</c>) или полный путь.</summary>
    public IReadOnlyList<string> Processes { get; init; } = [];

    public bool IsEmpty => Paths.Count == 0 && Processes.Count == 0;

    /// <summary>Разрешён ли файл (сам путь или каталог, в котором он лежит).</summary>
    public bool IsPathAllowed(string? path) =>
        !string.IsNullOrWhiteSpace(path) && Paths.Any(p => AsPath(p).CoversFile(path));

    /// <summary>Разрешён ли процесс: по списку процессов либо по расположению образа.</summary>
    public bool IsProcessAllowed(string? imageName, string? executablePath) =>
        Processes.Any(p => AsProcess(p).CoversProcess(imageName, executablePath)) || IsPathAllowed(executablePath);

    /// <summary>
    /// Соответствует ли исключение Defender пользовательскому списку. Исключения по расширению
    /// и IP-адресу не разрешаются никогда: они слишком широки, чтобы считать их осознанным выбором.
    /// </summary>
    public bool IsAllowed(DefenderExclusion exclusion)
    {
        ArgumentNullException.ThrowIfNull(exclusion);
        var value = exclusion.ExpandedValue;
        return exclusion.Kind switch
        {
            DefenderExclusionKind.Path => !exclusion.HasWildcard && IsPathAllowed(value),
            DefenderExclusionKind.Process => !exclusion.HasWildcard && (exclusion.IsBareProcessName
                ? Processes.Any(p => AsProcess(p).IsBareProcessName && AsProcess(p).CoversProcess(value, null))
                : IsProcessAllowed(null, value)),
            _ => false,
        };
    }

    public AllowedExclusions WithPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Paths.Contains(path, StringComparer.OrdinalIgnoreCase) ? this : this with { Paths = [.. Paths, path] };
    }

    public AllowedExclusions WithProcess(string process)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(process);
        return Processes.Contains(process, StringComparer.OrdinalIgnoreCase) ? this : this with { Processes = [.. Processes, process] };
    }

    private static DefenderExclusion AsPath(string value) => new(DefenderExclusionKind.Path, value, "allowed_exclusions.json");

    private static DefenderExclusion AsProcess(string value) => new(DefenderExclusionKind.Process, value, "allowed_exclusions.json");
}

/// <summary>Хранилище <c>allowed_exclusions.json</c>: потокобезопасное чтение и атомарная запись.</summary>
public sealed class AllowedExclusionStore
{
    public const string DefaultFileName = "allowed_exclusions.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly object _sync = new();
    private AllowedExclusions? _cached;
    private DateTime _cachedStampUtc;

    public AllowedExclusionStore(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Path = System.IO.Path.GetFullPath(path);
    }

    public string Path { get; }

    public static AllowedExclusionStore ForDataDirectory(string dataDirectory) =>
        new(System.IO.Path.Combine(dataDirectory, DefaultFileName));

    /// <summary>
    /// Текущий список. Отсутствующий файл — пустой список; повреждённый файл — исключение
    /// <see cref="JsonException"/>: молча игнорировать настройки пользователя нельзя.
    /// </summary>
    public AllowedExclusions Load()
    {
        lock (_sync)
        {
            if (!File.Exists(Path))
            {
                _cached = null;
                return AllowedExclusions.Empty;
            }

            var stamp = File.GetLastWriteTimeUtc(Path);
            if (_cached is not null && stamp == _cachedStampUtc)
            {
                return _cached;
            }

            using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var doc = JsonSerializer.Deserialize<Document>(stream, Json) ?? new Document();
            _cached = new AllowedExclusions
            {
                Paths = Clean(doc.Paths),
                Processes = Clean(doc.Processes),
            };
            _cachedStampUtc = stamp;
            return _cached;
        }
    }

    public AllowedExclusions AddPath(string path) => Update(a => a.WithPath(path));

    public AllowedExclusions AddProcess(string process) => Update(a => a.WithProcess(process));

    public AllowedExclusions Update(Func<AllowedExclusions, AllowedExclusions> change)
    {
        ArgumentNullException.ThrowIfNull(change);
        lock (_sync)
        {
            var updated = change(Load());
            Save(updated);
            return updated;
        }
    }

    private void Save(AllowedExclusions value)
    {
        var dir = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var temp = Path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, new Document { Paths = [.. value.Paths], Processes = [.. value.Processes] }, Json);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, Path, overwrite: true);
        _cached = value;
        _cachedStampUtc = File.GetLastWriteTimeUtc(Path);
    }

    private static string[] Clean(List<string>? values) =>
        values is null
            ? []
            : values.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private sealed class Document
    {
        public int Version { get; set; } = 1;

        public List<string>? Paths { get; set; }

        public List<string>? Processes { get; set; }
    }
}
