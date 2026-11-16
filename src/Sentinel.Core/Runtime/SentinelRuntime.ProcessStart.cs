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
        if (_o.ProcessStartSource is null)
        {
            Log?.Invoke("Мониторинг старта процессов недоступен на этой платформе — новые процессы проверяет периодический аудит.");
            return;
        }

        var source = _o.ProcessStartSource();
        if (OperatingSystem.IsWindows() && source is WindowsProcessCreationEventSource windows)
        {
            windows.Log += message => Log?.Invoke(message);
        }

        await using (source.ConfigureAwait(false))
        {
            var monitor = CreateProcessStartMonitor(source);
            await monitor.RunAsync(() => _realtimeEnabled, cancellationToken).ConfigureAwait(false);
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
            new ProcessStartMonitorOptions { Dispatcher = _o.Dispatcher, ExtraOwnDirectories = [_o.DataDirectory] });
        monitor.Inspected += OnProcessStartInspected;
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
}
