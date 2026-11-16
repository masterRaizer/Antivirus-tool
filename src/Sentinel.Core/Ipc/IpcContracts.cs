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

    /// <summary>Все подключённые съёмные накопители (флешки, внешние диски) — глубокая проверка всех файлов.</summary>
    Removable,
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

    /// <summary>Размер пула проверки и сколько рабочих сейчас заняты.</summary>
    public int Workers { get; init; }

    public int ActiveWorkers { get; init; }

    /// <summary><c>процессы</c> — изолированные рабочие процессы, <c>потоки</c> — внутрипроцессный пул.</summary>
    public string PoolMode { get; init; } = string.Empty;

    /// <summary>Пропущено по кэшу чистых файлов (не менялись с прошлой проверки).</summary>
    public long CachedSkipped { get; init; }

    /// <summary>Файлы, которые не удалось проверить (ScanError).</summary>
    public long Errors { get; init; }

    /// <summary>Обход каталогов завершён: <see cref="Total"/> окончательный; до этого процент оценочный.</summary>
    public bool EnumerationComplete { get; init; }

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

    /// <summary>Состояние драйвера ядра SentinelDrv (или профиль User-Mode EDR без драйвера).</summary>
    public string KernelDriver { get; init; } = string.Empty;
}

public sealed record ProcessInfo(int Pid, string Name, string? Path, double CpuPercent, Severity? Severity, string? Remarks);

public sealed record QuarantineItem(
    string Id, string OriginalPath, string Sha256, long Size, DateTime QuarantinedAtUtc, string Reason, bool Restored, DateTime? RestoredAtUtc)
{
    /// <summary>Удалён из карантина навсегда.</summary>
    public bool Deleted { get; init; }

    /// <summary>Файл всё ещё в карантине (его можно восстановить или удалить навсегда).</summary>
    public bool IsActive => !Restored && !Deleted;

    public string StateText => Deleted ? "Удалён навсегда" : Restored ? "Восстановлен" : string.Empty;
}

/// <summary>Настройки и базы для раздела «Настройки и базы». Значения ключей не передаются — только признак, что ключ задан.</summary>
public sealed record SettingsSnapshot
{
    public bool HasKasperskyOpenTipApiKey { get; init; }

    public bool HasVirusTotalApiKey { get; init; }

    public bool HasAbuseChAuthKey { get; init; }

    public bool AutoUpdateDatabases { get; init; } = true;

    public bool EnableRansomwareShield { get; init; } = true;

    public bool EnableCanaryFiles { get; init; } = true;

    public bool EnableUsbShield { get; init; } = true;

    public bool BehavioralShadowMode { get; init; }

    public IReadOnlyList<string> AllowedPaths { get; init; } = [];

    public IReadOnlyList<string> AllowedProcesses { get; init; } = [];

    public IReadOnlyList<string> AllowedHashes { get; init; } = [];

    public ThreatIntel.DatabaseStatus Database { get; init; } = new();

    public string DataDirectory { get; init; } = string.Empty;
}

/// <summary>Изменение настроек. Ключ: <c>null</c> — не менять, пустая строка — удалить, иное — новое значение.</summary>
public sealed record SettingsUpdate
{
    public string? KasperskyOpenTipApiKey { get; init; }

    public string? VirusTotalApiKey { get; init; }

    public string? AbuseChAuthKey { get; init; }

    public bool AutoUpdateDatabases { get; init; } = true;

    public bool EnableRansomwareShield { get; init; } = true;

    public bool EnableCanaryFiles { get; init; } = true;

    public bool EnableUsbShield { get; init; } = true;

    public bool BehavioralShadowMode { get; init; }

    public IReadOnlyList<string> AllowedPaths { get; init; } = [];

    public IReadOnlyList<string> AllowedProcesses { get; init; } = [];

    public IReadOnlyList<string> AllowedHashes { get; init; } = [];
}

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

    /// <summary>
    /// Группа для интерфейса: однотипные информационные записи (например, блокировка телеметрии в hosts) сворачиваются в одну группу,
    /// чтобы не заслонять то, что требует внимания.
    /// </summary>
    public string Group => !Flagged ? "3. Штатные записи"
        : Severity == Severity.Info ? $"2. Информация · {Category}"
        : "1. Требуют внимания";
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

    Task<OperationResult> DeleteQuarantineAsync(string id, CancellationToken cancellationToken = default);

    Task<SettingsSnapshot> GetSettingsAsync(CancellationToken cancellationToken = default);

    Task<OperationResult> SaveSettingsAsync(SettingsUpdate update, CancellationToken cancellationToken = default);

    Task<ThreatIntel.DatabaseStatus> UpdateDatabasesAsync(CancellationToken cancellationToken = default);

    Task<Runtime.BehavioralStatus> GetBehavioralStatusAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Protection.UsbFinding>> ScanRemovableAsync(string? pathOrDrive, CancellationToken cancellationToken = default);
}
