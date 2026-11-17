using Sentinel.Core.Monitoring.Evasion;

namespace Sentinel.Core.Runtime;

/// <summary>Состояние детектора скрытых майнеров для интерфейса и CLI.</summary>
public sealed record MonitorEvasionStatus(
    bool Enabled,
    bool Running,
    long Samples,
    int MonitorOpenings,
    int Findings,
    int HiddenCpuAlerts,
    string? OpenMonitor,
    IReadOnlyList<string> Recent)
{
    public string Describe()
    {
        if (!Enabled)
        {
            return "Детектор скрытых майнеров выключен.";
        }

        if (!Running)
        {
            return "Детектор скрытых майнеров: запускается или недоступен (нужна служба на Windows).";
        }

        var hidden = HiddenCpuAlerts > 0 ? $", скрытая нагрузка: {HiddenCpuAlerts}" : string.Empty;
        var open = OpenMonitor is null ? string.Empty : $"; сейчас открыт {OpenMonitor}";
        return $"Детектор скрытых майнеров: замеров {Samples}, открытий Диспетчера задач и аналогов {MonitorOpenings}, находок {Findings}{hidden}{open}.";
    }
}

/// <summary>Детектор скрытых майнеров, прячущихся от Диспетчера задач (поведенческий щит).</summary>
public sealed partial class SentinelRuntime
{
    private MonitorEvasionWatcher? _evasion;
    private long _evasionConfigCheckedAt = long.MinValue;
    private bool _evasionConfigEnabled = true;

    /// <summary>
    /// Цикл детектора: замер активности всех процессов раз в секунду, находки — через предохранители в диспетчер.
    /// Работает, пока включены защита в реальном времени и переключатель «Скрытые майнеры». До отмены.
    /// </summary>
    public async Task RunMonitorEvasionWatchAsync(CancellationToken cancellationToken)
    {
        if (_o.ActivitySampler is null || _o.EvasionInspector is null)
        {
            Info?.Invoke("Детектор скрытых майнеров недоступен на этой платформе.");
            return;
        }

        using var sampler = _o.ActivitySampler();
        var watcher = CreateMonitorEvasionWatcher(sampler, _o.EvasionInspector);
        _evasion = watcher;
        Info?.Invoke("Детектор скрытых майнеров запущен: нагрузка процессов замеряется раз в секунду, ловятся те, кто прячется от Диспетчера задач.");
        await watcher.RunAsync(IsMonitorEvasionEnabled, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Детектор поверх диспетчера и анализатора рантайма (служба, CLI <c>evasion-watch</c>, тесты).</summary>
    public MonitorEvasionWatcher CreateMonitorEvasionWatcher(IProcessActivitySampler sampler, IEvasionProcessInspector inspector)
    {
        ArgumentNullException.ThrowIfNull(sampler);
        ArgumentNullException.ThrowIfNull(inspector);
        var watcher = new MonitorEvasionWatcher(
            sampler,
            new MonitorEvasionDetector(),
            inspector,
            _dispatcher,
            _o.Analyzer,
            () => _allowed.Load(),
            () => BehaviorConfig().BehavioralShadowMode,
            new MonitorEvasionWatcherOptions
            {
                Dispatcher = _o.Dispatcher,
                ExtraOwnDirectories = [_o.DataDirectory],
                MemoryScanner = _o.MemoryScanner,
            });
        watcher.Detected += outcome =>
        {
            if (outcome.Decision is EvasionDecision.Act or EvasionDecision.AskUser)
            {
                Interlocked.Increment(ref _processesChecked);
                RecordChain($"Evasion: {outcome.Finding.Describe()} Балл {outcome.Score}, решение {outcome.Decision}.");
            }
        };
        watcher.HiddenCpuDetected += hidden => RecordChain($"Evasion: {hidden.Describe()}");
        watcher.Info += message => Info?.Invoke(message);
        watcher.Log += message => Log?.Invoke(message);
        return watcher;
    }

    public MonitorEvasionStatus GetMonitorEvasionStatus()
    {
        var watcher = _evasion;
        var enabled = BehaviorConfig().EnableMonitorEvasionWatch;
        if (watcher is null)
        {
            return new MonitorEvasionStatus(enabled, false, 0, 0, 0, 0, null, []);
        }

        var stats = watcher.Stats;
        return new MonitorEvasionStatus(enabled, true, stats.Samples, stats.MonitorOpenings, stats.Findings, stats.HiddenCpuAlerts,
            stats.OpenMonitor, watcher.Recent);
    }

    /// <summary>Переключатель читается не чаще раза в 5 с: цикл детектора тикает каждую секунду.</summary>
    private bool IsMonitorEvasionEnabled()
    {
        if (!_realtimeEnabled)
        {
            return false;
        }

        var now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _evasionConfigCheckedAt) >= 5000)
        {
            _evasionConfigEnabled = BehaviorConfig().EnableMonitorEvasionWatch;
            Interlocked.Exchange(ref _evasionConfigCheckedAt, now);
        }

        return _evasionConfigEnabled;
    }
}
