using Sentinel.Core.Monitoring;

namespace Sentinel.Core.Runtime;

/// <summary>Мониторинг старта процессов в реальном времени (модуль 8/1).</summary>
public sealed partial class SentinelRuntime
{
    private long _processStartsInspected;

    /// <summary>Сколько событий старта процессов обработано монитором.</summary>
    public long ProcessStartsInspected => Interlocked.Read(ref _processStartsInspected);

    /// <summary>
    /// Цикл монитора старта процессов: события источника (WMI или опрос) проходят предохранители, аудит, поведенческую
    /// корреляцию и диспетчер. При выключенной защите в реальном времени события пропускаются. Работает до отмены.
    /// </summary>
    public async Task RunProcessStartMonitorAsync(CancellationToken cancellationToken)
    {
        IProcessCreationEventSource source;
        var kernel = KernelBridge;
        if (kernel.IsConnected && kernel.GetStatus().ProcessNotifyActive)
        {
            // Телеметрия ядра (PsSetCreateProcessNotifyRoutineEx) с откатом на WMI/опрос при потере драйвера.
            var fromKernel = new Kernel.KernelProcessCreationEventSource(kernel, _o.ProcessStartSource,
                resolveImagePath: pid => OperatingSystem.IsWindows() ? Audit.Process.WindowsProcessProvider.TryGetImagePath(pid) : null);
            fromKernel.Log += message => Info?.Invoke(message);
            source = fromKernel;
        }
        else if (_o.ProcessStartSource is not null)
        {
            source = _o.ProcessStartSource();
        }
        else
        {
            Log?.Invoke("Мониторинг старта процессов недоступен на этой платформе — новые процессы проверяет периодический аудит.");
            return;
        }

        if (OperatingSystem.IsWindows() && source is WindowsProcessCreationEventSource windows)
        {
            windows.Log += message => Info?.Invoke(message);
        }

        await using (source.ConfigureAwait(false))
        {
            var monitor = CreateProcessStartMonitor(source);
            Info?.Invoke($"Мониторинг старта процессов запущен (источник: {(source is Kernel.KernelProcessCreationEventSource ? "драйвер ядра" : "WMI / опрос")}).");
            await monitor.RunAsync(() => _realtimeEnabled, cancellationToken).ConfigureAwait(false);
            await monitor.DrainMemoryRescansAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Монитор старта процессов поверх диспетчера, корреляционного движка и анализатора рантайма.</summary>
    public ProcessStartMonitor CreateProcessStartMonitor(IProcessCreationEventSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var monitor = new ProcessStartMonitor(
            source,
            _dispatcher,
            _correlation.Value,
            _o.Analyzer,
            () => _allowed.Load(),
            () => BehaviorConfig().BehavioralShadowMode,
            new ProcessStartMonitorOptions
            {
                Dispatcher = _o.Dispatcher,
                ExtraOwnDirectories = [_o.DataDirectory],
                Auditor = new Audit.Process.ProcessAuditorOptions { MemoryScanner = _o.MemoryScanner },
            });
        monitor.Inspected += OnProcessStartInspected;
        monitor.MemoryRescanned += outcome =>
        {
            if (outcome.Correlation is { } chain)
            {
                RecordChain($"Memory: {chain.Summary}");
            }

            Log?.Invoke($"Повторная проверка памяти {outcome.Event.ProcessName} (PID {outcome.Event.ProcessId}): "
                + $"{string.Join(", ", outcome.Findings.Select(f => f.Id).Distinct())}, решение {outcome.Decision}, итог {outcome.Threat?.Status.ToString() ?? "-"}.");
        };
        monitor.Log += message => Log?.Invoke(message);
        return monitor;
    }

    private void OnProcessStartInspected(ProcessStartOutcome outcome)
    {
        Interlocked.Increment(ref _processStartsInspected);
        if (outcome.Decision is ProcessStartDecision.Protected or ProcessStartDecision.Allowed)
        {
            return;
        }

        Interlocked.Increment(ref _processesChecked);
        var e = outcome.Event;
        if (outcome.Correlation is { } chain)
        {
            RecordChain($"Process: {chain.Summary}");
        }

        if (outcome.Decision is ProcessStartDecision.Act or ProcessStartDecision.AskUser)
        {
            Log?.Invoke($"Старт процесса {e.ProcessName} (PID {e.ProcessId}, {e.ExecutablePath}): балл {outcome.Score}, "
                + $"решение {outcome.Decision}, итог {outcome.Threat?.Status.ToString() ?? "-"}.");
        }
    }

    /// <summary>Аномалии памяти (PE/сигнатура) передаются в корреляционный движок; BH-05 попадает в журнал цепочек.</summary>
    private void ReportMemoryAnomalies(Audit.Process.ProcessAuditEntry entry)
    {
        if (entry.MemoryScan is not { HasAnomalies: true } memory
            || !memory.Anomalies.Any(a => a.Kind != Auditors.Memory.MemoryAnomalyKind.ImagePatch))
        {
            return;
        }

        var image = entry.Process.ExecutablePath ?? entry.Process.Name;
        var anomaly = string.Join(", ", memory.Anomalies.Select(a => a.Id).Distinct());
        Log?.Invoke($"Память процесса {entry.Process.Name} (PID {entry.Process.Pid}): {anomaly}, балл {memory.Score.Value}.");
        if (_correlation.Value.ReportMemoryAnomaly(image, anomaly) is { } chain)
        {
            RecordChain($"Memory: {chain.Summary}");
        }
    }
}
