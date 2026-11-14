using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.Audit.Persistence.Registry;

namespace Sentinel.Core.Remediation;

/// <summary>Что именно было изменено (и чем это отменяется).</summary>
public enum RollbackKind
{
    /// <summary>Значение реестра изменено или удалено.</summary>
    RegistryValue,

    /// <summary>Из файла hosts удалены записи; в копии — полное прежнее содержимое.</summary>
    HostsFile,

    /// <summary>Задача планировщика удалена; в копии — её XML-определение.</summary>
    ScheduledTask,

    /// <summary>Исключение Defender удалено через MSFT_MpPreference.Remove.</summary>
    DefenderExclusion,
}

/// <summary>
/// Запись манифеста отката: резервная копия параметра, изменённого при нейтрализации.
/// Содержит достаточно данных, чтобы вернуть систему в состояние «до».
/// </summary>
public sealed record RollbackEntry
{
    public required string Id { get; init; }
    public DateTime TimestampUtc { get; init; }
    public RollbackKind Kind { get; init; }

    /// <summary>Ключ реестра, путь к hosts, путь задачи или имя свойства MSFT_MpPreference.</summary>
    public required string Target { get; init; }

    /// <summary>Имя значения реестра или значение исключения.</summary>
    public string? Name { get; init; }

    /// <summary>Существовал ли параметр до изменения.</summary>
    public bool PreviousExisted { get; init; }

    public string? PreviousValue { get; init; }
    public RegistryValueKind? PreviousValueKind { get; init; }

    /// <summary>Новое (эталонное) значение; <c>null</c> — параметр удалён.</summary>
    public string? NewValue { get; init; }

    public required string Reason { get; init; }
    public DateTime? UndoneAtUtc { get; init; }
}

/// <summary>Хранилище манифеста отката (<c>rollback_manifest.json</c>) с атомарной записью.</summary>
public sealed class RollbackManifestStore
{
    public const string DefaultFileName = "rollback_manifest.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly object _sync = new();

    public RollbackManifestStore(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Path = System.IO.Path.GetFullPath(path);
    }

    public string Path { get; }

    public IReadOnlyList<RollbackEntry> Load()
    {
        lock (_sync)
        {
            return LoadCore().Entries.ToArray();
        }
    }

    public void Append(RollbackEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        lock (_sync)
        {
            var doc = LoadCore();
            doc.Entries.Add(entry);
            Save(doc);
        }
    }

    public void Replace(RollbackEntry updated)
    {
        ArgumentNullException.ThrowIfNull(updated);
        lock (_sync)
        {
            var doc = LoadCore();
            var index = doc.Entries.FindIndex(e => e.Id == updated.Id);
            if (index < 0)
            {
                throw new InvalidOperationException($"Запись отката '{updated.Id}' отсутствует в манифесте.");
            }

            doc.Entries[index] = updated;
            Save(doc);
        }
    }

    private Document LoadCore()
    {
        if (!File.Exists(Path))
        {
            return new Document();
        }

        using var stream = File.OpenRead(Path);
        return JsonSerializer.Deserialize<Document>(stream, Json) ?? new Document();
    }

    private void Save(Document doc)
    {
        var dir = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var temp = Path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, doc, Json);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, Path, overwrite: true);
    }

    private sealed class Document
    {
        public int Version { get; set; } = 1;

        public List<RollbackEntry> Entries { get; set; } = [];
    }
}
