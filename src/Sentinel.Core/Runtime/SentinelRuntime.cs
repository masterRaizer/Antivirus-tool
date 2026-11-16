using System.Reflection;
using System.Text.Json;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Remediation;
using Sentinel.Core.Settings;

namespace Sentinel.Core.Runtime;

/// <summary>
/// Локальная реализация <see cref="ISentinelBackend"/>: проверки, защита в реальном времени,
/// очередь решений, карантин, откат, автозагрузка, история отчётов и телеметрия. Один и тот же
/// рантайм работает внутри службы (и публикуется через <see cref="SentinelIpcServer"/>)
/// и внутри приложения в автономном режиме.
/// </summary>
public sealed partial class SentinelRuntime : ISentinelBackend, IAsyncDisposable
{
    private const int TelemetryHistory = 120;
    private const string SettingsFileName = "settings.json";

    private readonly SentinelRuntimeOptions _o;
    private readonly RealtimeEventDispatcher _dispatcher;
    private readonly AllowedExclusionStore _allowed;
    private readonly RollbackManifestStore _rollback;
    private readonly ReportStore _reports;
    private readonly DateTime _startedAtUtc;
    private readonly object _sync = new();
    private readonly Queue<TelemetrySample> _telemetry = new();
    private readonly CancellationTokenSource _lifetime = new();
    private long _filesChecked;
    private long _processesChecked;
    private volatile bool _realtimeEnabled;
    private (long Timestamp, IReadOnlyList<ProcessInfo> Rows)? _processCache;

    public SentinelRuntime(SentinelRuntimeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _o = options;
        Directory.CreateDirectory(options.DataDirectory);
        _allowed = AllowedExclusionStore.ForDataDirectory(options.DataDirectory);
        _rollback = new RollbackManifestStore(options.Engine?.RollbackManifestPath
            ?? Path.Combine(options.DataDirectory, RollbackManifestStore.DefaultFileName));
        _reports = new ReportStore(Path.Combine(options.DataDirectory, "Reports"));
        _dispatcher = new RealtimeEventDispatcher(options.Quarantine, options.Engine, _allowed, options.Dispatcher, options.TimeProvider);
        _dispatcher.ThreatRaised += OnThreatRaised;
        _dispatcher.ThreatUpdated += OnThreatUpdated;
        _startedAtUtc = options.TimeProvider.GetUtcNow().UtcDateTime;
        _realtimeEnabled = LoadRealtimeSetting(options.RealtimeEnabledByDefault);
    }

    public event Action<ScanProgress>? ScanProgressChanged;

    public event Action<TelemetrySample>? TelemetryUpdated;

    public event Action<ThreatEvent>? ThreatRaised;

    public event Action<ThreatEvent>? ThreatUpdated;

    public event Action<ServiceStatus>? StatusChanged;

    /// <summary>Диагностические сообщения фоновых циклов о сбоях и находках (журнал службы, уровень Warning).</summary>
    public event Action<string>? Log;

    /// <summary>Информационные сообщения: подключение/отключение драйвера, синхронизация PID, источники мониторов (уровень Information).</summary>
    public event Action<string>? Info;

    public string DataDirectory => _o.DataDirectory;

    public RealtimeEventDispatcher Dispatcher => _dispatcher;

    public bool RealtimeEnabled => _realtimeEnabled;

    public async ValueTask DisposeAsync()
    {
        await _lifetime.CancelAsync().ConfigureAwait(false);
        Task? scan;
        lock (_sync)
        {
            scan = _scanTask;
        }

        if (scan is not null)
        {
            await scan.ConfigureAwait(false);
        }

        _dispatcher.ThreatRaised -= OnThreatRaised;
        _dispatcher.ThreatUpdated -= OnThreatUpdated;
        DisposeKernelBridge();
        _o.Telemetry.Dispose();
        _o.Quarantine.Dispose();
        _scanCts?.Dispose();
        _pauseGate.Dispose();
        _lifetime.Dispose();
    }

    // ---- Состояние -------------------------------------------------------------

    public async Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var records = await _o.Quarantine.ListAsync(cancellationToken).ConfigureAwait(false);
        var threats = _dispatcher.Snapshot();
        return new ServiceStatus
        {
            Mode = _o.Mode,
            Version = typeof(SentinelRuntime).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
                ?? typeof(SentinelRuntime).Assembly.GetName().Version?.ToString() ?? "0.0",
            Platform = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            StartedAtUtc = _startedAtUtc,
            RealtimeEnabled = _realtimeEnabled,
            RemediationAvailable = _o.Engine is not null,
            RulesLoaded = _o.RulesLoaded,
            FilesChecked = Interlocked.Read(ref _filesChecked),
            ProcessesChecked = Interlocked.Read(ref _processesChecked),
            Quarantined = records.Count(r => r.State == QuarantineState.Quarantined),
            ThreatsTotal = threats.Count,
            PendingDecisions = threats.Count(t => t.Status == ThreatStatus.PendingDecision),
            WatchedDirectories = WatchedDirectories(),
            KernelDriver = GetKernelStatus().Message,
            Scan = CurrentScan,
        };
    }

    public Task<OperationResult> SetRealtimeProtectionAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        _realtimeEnabled = enabled;
        ApplyMonitorState();
        try
        {
            File.WriteAllText(Path.Combine(_o.DataDirectory, SettingsFileName), JsonSerializer.Serialize(new Settings(enabled)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log?.Invoke($"Настройка не сохранена: {ex.Message}");
        }

        PublishStatus();
        return Task.FromResult(OperationResult.Ok(enabled ? "Защита в реальном времени включена." : "Защита в реальном времени приостановлена."));
    }

    // ---- Телеметрия и процессы -------------------------------------------------

    /// <summary>Цикл телеметрии: раз в интервал снимает показатели и рассылает подписчикам.</summary>
    public async Task RunTelemetryAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_o.TelemetryInterval, _o.TimeProvider);
        try
        {
            do
            {
                SampleTelemetry();
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Один замер телеметрии (открыт для тестов и для первого кадра графиков).</summary>
    public TelemetrySample SampleTelemetry()
    {
        var r = _o.Telemetry.Read();
        var sample = new TelemetrySample(_o.TimeProvider.GetUtcNow().UtcDateTime,
            Math.Max(0, r.CpuPercent), Math.Max(0, r.RamPercent), Math.Max(0, r.DiskPercent), r.RamUsedBytes, r.RamTotalBytes);
        lock (_sync)
        {
            _telemetry.Enqueue(sample);
            while (_telemetry.Count > TelemetryHistory)
            {
                _telemetry.Dequeue();
            }
        }

        TelemetryUpdated?.Invoke(sample);
        return sample;
    }

    public Task<IReadOnlyList<TelemetrySample>> GetTelemetryHistoryAsync(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            return Task.FromResult<IReadOnlyList<TelemetrySample>>(_telemetry.ToArray());
        }
    }

    /// <summary>Процессы с замечаниями аудита и самые нагруженные по CPU.</summary>
    public async Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken cancellationToken = default)
    {
        if (_o.Processes is null)
        {
            return [];
        }

        lock (_sync)
        {
            if (_processCache is { } cache && _o.TimeProvider.GetElapsedTime(cache.Timestamp) < TimeSpan.FromSeconds(3))
            {
                return cache.Rows;
            }
        }

        var rows = await Task.Run(BuildProcessRows, cancellationToken).ConfigureAwait(false);
        lock (_sync)
        {
            _processCache = (_o.TimeProvider.GetTimestamp(), rows);
        }

        return rows;
    }

    private ProcessInfo[] BuildProcessRows()
    {
        // Без анализа файлов: список обновляется каждые несколько секунд и должен быть дешёвым.
        var audit = new ProcessAuditor(new ProcessAuditorOptions { AnalyzeExecutable = false }).Audit(_o.Processes!.GetProcesses());
        var top = audit.Entries.Where(e => !e.HasFindings && e.Process.CpuPercent >= 1).OrderByDescending(e => e.Process.CpuPercent).Take(12);
        return audit.Flagged.Concat(top)
            .Select(e => new ProcessInfo(
                e.Process.Pid,
                e.Process.Name,
                e.Process.ExecutablePath,
                Math.Max(0, e.Process.CpuPercent),
                e.HasFindings ? e.Findings.Max(f => f.Severity) : null,
                e.HasFindings ? string.Join("; ", e.Findings.Select(f => f.Title).Distinct()) : null))
            .OrderByDescending(p => p.Severity ?? Signatures.Severity.Info)
            .ThenByDescending(p => p.CpuPercent)
            .ToArray();
    }

    // ---- Угрозы ----------------------------------------------------------------

    public Task<IReadOnlyList<ThreatEvent>> GetThreatsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_dispatcher.Snapshot());

    public Task<ThreatEvent> ResolveThreatAsync(string id, ThreatDecision decision, CancellationToken cancellationToken = default) =>
        _dispatcher.ResolveAsync(id, decision, cancellationToken);

    private void OnThreatRaised(ThreatEvent threat)
    {
        ThreatRaised?.Invoke(threat);
        PublishStatus();
    }

    private void OnThreatUpdated(ThreatEvent threat)
    {
        ThreatUpdated?.Invoke(threat);
        PublishStatus();
    }

    // ---- Карантин и откат ------------------------------------------------------

    public async Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync(CancellationToken cancellationToken = default)
    {
        var records = await _o.Quarantine.ListAsync(cancellationToken).ConfigureAwait(false);
        return records
            .OrderByDescending(r => r.QuarantinedAtUtc)
            .Select(r => new QuarantineItem(r.Id, r.OriginalPath, r.Sha256, r.Size, r.QuarantinedAtUtc, r.Reason,
                r.State == QuarantineState.Restored, r.RestoredAtUtc) { Deleted = r.State == QuarantineState.Deleted })
            .ToArray();
    }

    public async Task<OperationResult> RestoreQuarantineAsync(string id, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        var result = await _o.Quarantine.RestoreAsync(id, overwrite, cancellationToken).ConfigureAwait(false);
        PublishStatus();
        return new OperationResult(result.Success, result.Message);
    }

    public Task<IReadOnlyList<RollbackItem>> GetRollbackAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<RollbackItem>>(_rollback.Load()
            .OrderByDescending(e => e.TimestampUtc)
            .Select(e => new RollbackItem(e.Id, e.TimestampUtc, e.Kind.ToString(), e.Target, e.Name, e.PreviousValue, e.NewValue, e.Reason, e.UndoneAtUtc is not null))
            .ToArray());

    public Task<OperationResult> UndoRollbackAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        if (_o.Engine is null)
        {
            return Task.FromResult(OperationResult.Fail("Отмена изменений конфигурации доступна только в Windows."));
        }

        var action = _o.Engine.Undo(id);
        InvalidateStartup();
        return Task.FromResult(new OperationResult(action.Success, $"{action.Target}: {action.Message}"));
    }

    // ---- Отчёты ----------------------------------------------------------------

    public Task<IReadOnlyList<ReportSummary>> GetReportsAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => _reports.List(), cancellationToken);

    public Task<ReportExport> ExportReportAsync(string id, ReportFormat format, CancellationToken cancellationToken = default) =>
        Task.Run(() => _reports.Export(id, format), cancellationToken);

    // ---- Служебное -------------------------------------------------------------

    private void PublishStatus()
    {
        if (StatusChanged is null)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                StatusChanged?.Invoke(await GetStatusAsync(_lifetime.Token).ConfigureAwait(false));
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or IOException or JsonException)
            {
            }
        });
    }

    private bool LoadRealtimeSetting(bool fallback)
    {
        try
        {
            var path = Path.Combine(_o.DataDirectory, SettingsFileName);
            return File.Exists(path) ? JsonSerializer.Deserialize<Settings>(File.ReadAllText(path))?.RealtimeEnabled ?? fallback : fallback;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return fallback;
        }
    }

    private static IEnumerable<(DefenderExclusion Exclusion, Audit.AuditFinding Finding)> PairExclusions(ConfigAuditReport config)
    {
        // Находки об исключениях создаются аудитором в том же порядке, что и сами исключения.
        var findings = config.ByArea(ConfigArea.DefenderExclusion).ToArray();
        for (var i = 0; i < config.DefenderExclusions.Count && i < findings.Length; i++)
        {
            yield return (config.DefenderExclusions[i], findings[i].Finding);
        }
    }

    private sealed record Settings(bool RealtimeEnabled);
}
