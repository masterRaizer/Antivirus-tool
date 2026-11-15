using Sentinel.Core.Realtime;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Ipc;

public enum ScanMode
{
    /// <summary>Процессы, автозагрузка, конфигурация и каталоги, куда обычно попадает вредоносное ПО.</summary>
    Quick,

    /// <summary>То же плюс все локальные диски.</summary>
    Full,

    /// <summary>Выбранная пользователем папка или файл.</summary>
    Custom,
}

public enum ScanState
{
    Idle,
    Counting,
    Running,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

public enum ReportFormat
{
    Html,
    Json,
}

public sealed record ScanRequest(ScanMode Mode, string? Path = null);

/// <summary>Состояние проверки: рассылается подписчикам по мере продвижения.</summary>
public sealed record ScanProgress
{
    public static ScanProgress Idle { get; } = new();

    public ScanState State { get; init; } = ScanState.Idle;
    public ScanMode Mode { get; init; }

    /// <summary>Текущий этап («Процессы», «Автозагрузка», «Файлы» и т.п.).</summary>
    public string Stage { get; init; } = string.Empty;

    /// <summary>Проверяемый сейчас файл, процесс или ветка реестра.</summary>
    public string CurrentItem { get; init; } = string.Empty;

    public long Scanned { get; init; }

    /// <summary>Всего объектов (0 — ещё не подсчитано).</summary>
    public long Total { get; init; }

    public int Threats { get; init; }
    public double ItemsPerSecond { get; init; }
    public double Percent { get; init; }
    public double ElapsedSeconds { get; init; }

    /// <summary>Идентификатор сохранённого отчёта (после завершения).</summary>
    public string? ReportId { get; init; }

    public string? Message { get; init; }

    public bool IsActive => State is ScanState.Counting or ScanState.Running or ScanState.Paused;
}

public sealed record TelemetrySample(DateTime TimestampUtc, double CpuPercent, double RamPercent, double DiskPercent, long RamUsedBytes, long RamTotalBytes);

public sealed record ServiceStatus
{
    /// <summary><c>service</c> — фоновая служба, <c>standalone</c> — автономный режим приложения.</summary>
    public string Mode { get; init; } = "standalone";

    public string Version { get; init; } = string.Empty;
    public string Platform { get; init; } = string.Empty;
    public DateTime StartedAtUtc { get; init; }
    public bool RealtimeEnabled { get; init; }

    /// <summary>Доступны ли действия над системой (процессы, реестр, Defender) — только в Windows.</summary>
    public bool RemediationAvailable { get; init; }

    public int RulesLoaded { get; init; }
    public long FilesChecked { get; init; }
    public long ProcessesChecked { get; init; }
    public int Quarantined { get; init; }
    public int ThreatsTotal { get; init; }
    public int PendingDecisions { get; init; }
    public IReadOnlyList<string> WatchedDirectories { get; init; } = [];
    public ScanProgress Scan { get; init; } = ScanProgress.Idle;
}

public sealed record ProcessInfo(int Pid, string Name, string? Path, double CpuPercent, Severity? Severity, string? Remarks);

public sealed record QuarantineItem(
    string Id, string OriginalPath, string Sha256, long Size, DateTime QuarantinedAtUtc, string Reason, bool Restored, DateTime? RestoredAtUtc);

public sealed record RollbackItem(
    string Id, DateTime TimestampUtc, string Kind, string Target, string? Name, string? PreviousValue, string? NewValue, string Reason, bool Undone);

public sealed record OperationResult(bool Success, string Message)
{
    public static OperationResult Ok(string message) => new(true, message);

    public static OperationResult Fail(string message) => new(false, message);
}

/// <summary>Строка сводной таблицы автозагрузки: точка автозапуска, служба, задача, запись hosts или исключение Defender.</summary>
public sealed record StartupItem
{
    public required string Key { get; init; }
    public required string Category { get; init; }
    public required string Name { get; init; }
    public string Location { get; init; } = string.Empty;
    public string? Command { get; init; }
    public string? Target { get; init; }
    public string SignatureStatus { get; init; } = "не проверялась";

    /// <summary>Целевой файл проверен и не имеет действительной подписи.</summary>
    public bool NotSigned { get; init; }

    /// <summary>Нестандартная запись (есть находки аудита).</summary>
    public bool Flagged { get; init; }

    public Severity Severity { get; init; }
    public string? Remarks { get; init; }
    public bool CanClean { get; init; }
}

public sealed record StartupSnapshot(IReadOnlyList<StartupItem> Items, DateTime TakenAtUtc, string? Note = null);

public sealed record ReportSummary(
    string Id, DateTime StartedAtUtc, string Title, string Mode, double DurationSeconds, int Checked, int Found, int Quarantined);

public sealed record ReportExport(string FileName, string Content);

/// <summary>
/// Единый контракт движка Sentinel для интерфейса. У него две реализации: локальная
/// (<c>SentinelRuntime</c> — автономный режим и сама служба) и удалённая (<see cref="SentinelIpcClient"/> —
/// подключение к службе по именованному каналу). Приложению безразлично, с какой из них оно работает.
/// </summary>
public interface ISentinelBackend
{
    event Action<ScanProgress>? ScanProgressChanged;

    event Action<TelemetrySample>? TelemetryUpdated;

    event Action<ThreatEvent>? ThreatRaised;

    event Action<ThreatEvent>? ThreatUpdated;

    event Action<ServiceStatus>? StatusChanged;

    Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default);

    Task<OperationResult> SetRealtimeProtectionAsync(bool enabled, CancellationToken cancellationToken = default);

    Task<OperationResult> StartScanAsync(ScanRequest request, CancellationToken cancellationToken = default);

    Task<OperationResult> PauseScanAsync(CancellationToken cancellationToken = default);

    Task<OperationResult> ResumeScanAsync(CancellationToken cancellationToken = default);

    Task<OperationResult> StopScanAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TelemetrySample>> GetTelemetryHistoryAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ThreatEvent>> GetThreatsAsync(CancellationToken cancellationToken = default);

    Task<ThreatEvent> ResolveThreatAsync(string id, ThreatDecision decision, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync(CancellationToken cancellationToken = default);

    Task<OperationResult> RestoreQuarantineAsync(string id, bool overwrite = false, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RollbackItem>> GetRollbackAsync(CancellationToken cancellationToken = default);

    Task<OperationResult> UndoRollbackAsync(string id, CancellationToken cancellationToken = default);

    Task<StartupSnapshot> GetStartupAsync(bool refresh = false, CancellationToken cancellationToken = default);

    Task<OperationResult> CleanStartupItemAsync(string key, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ReportSummary>> GetReportsAsync(CancellationToken cancellationToken = default);

    Task<ReportExport> ExportReportAsync(string id, ReportFormat format, CancellationToken cancellationToken = default);
}
