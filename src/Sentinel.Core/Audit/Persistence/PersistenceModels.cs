using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit.Persistence;

/// <summary>Тип точки персистентности / автозапуска.</summary>
public enum PersistenceKind
{
    RegistryRun,
    RegistryRunOnce,
    WinlogonShell,
    WinlogonUserinit,
    ImageFileExecutionOptions,
    Service,
    ScheduledTask,
    WmiSubscription,
    StartupFolder,
    HostsFile,

    /// <summary>Ключ удаления программы (<c>Uninstall\{GUID}_is1</c>) — улика носителя заражения, автоматически не удаляется.</summary>
    UninstallEntry,
}

/// <summary>
/// Обнаруженная точка автозапуска. Сама по себе может быть легитимной (severity Info),
/// находки (<see cref="Findings"/>) повышают серьёзность при признаках угрозы.
/// </summary>
public sealed record PersistenceEntry
{
    public required PersistenceKind Kind { get; init; }

    /// <summary>Где обнаружено (ключ реестра, путь задачи, файл и т.п.).</summary>
    public required string Location { get; init; }

    /// <summary>Имя записи (имя значения, службы, задачи, файла).</summary>
    public required string Name { get; init; }

    /// <summary>Исходная команда/значение.</summary>
    public string? Command { get; init; }

    /// <summary>Разрешённый путь к целевому исполняемому файлу (если удалось извлечь).</summary>
    public string? ResolvedTarget { get; init; }

    public IReadOnlyList<AuditFinding> Findings { get; init; } = [];
    public FileScanResult? FileScan { get; init; }

    /// <summary>Время последнего изменения ключа реестра или задачи (UTC), если известно — для корреляции по времени.</summary>
    public DateTime? TimestampUtc { get; init; }

    public bool HasFindings => Findings.Count > 0;

    public Severity MaxSeverity => Findings.Count == 0 ? Severity.Info : Findings.Max(f => f.Severity);
}

/// <summary>Итог аудита персистентности.</summary>
public sealed record PersistenceAuditReport(IReadOnlyList<PersistenceEntry> Entries)
{
    /// <summary>Шаги, пропущенные из-за недоступности системной службы (Безопасный режим, WinRE).</summary>
    public IReadOnlyList<Audit.SkippedAuditStep> Skipped { get; init; } = [];

    public int Count => Entries.Count;
    public int FlaggedCount => Entries.Count(e => e.HasFindings);
    public IEnumerable<PersistenceEntry> Flagged => Entries.Where(e => e.HasFindings);
}
