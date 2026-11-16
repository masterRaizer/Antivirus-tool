using System.Management;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Sentinel.Core.Audit.Process;

namespace Sentinel.Core.Monitoring;

/// <summary>
/// Источник событий старта процессов для Windows. Порядок режимов:
/// <list type="number">
/// <item><c>wmi-trace</c> — <c>SELECT * FROM Win32_ProcessStartTrace</c> (мгновенно, требует прав администратора/LocalSystem);</item>
/// <item><c>wmi-instance</c> — <c>__InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'</c>;</item>
/// <item><c>polling</c> — дельта-опрос Toolhelp-снимка раз в секунду (Безопасный режим и WinRE, где WMI недоступен).</item>
/// </list>
/// Путь и командная строка дочитываются через <c>QueryFullProcessImageName</c> и PEB, при отказе — через <c>Win32_Process</c>.
/// Если подписка WMI остановилась во время работы (перезапуск службы winmgmt), источник переходит на опрос.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessCreationEventSource : IProcessCreationEventSource
{
    private const string TraceQuery = "SELECT * FROM Win32_ProcessStartTrace";
    private const string InstanceQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'";

    private readonly Channel<ProcessCreationEvent> _channel = Channel.CreateBounded<ProcessCreationEvent>(
        new BoundedChannelOptions(4096) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

    private readonly TimeSpan _pollingInterval;
    private readonly object _sync = new();
    private ManagementEventWatcher? _watcher;
    private volatile bool _disposed;
    private volatile string _mode = "starting";

    public WindowsProcessCreationEventSource(TimeSpan? pollingInterval = null) =>
        _pollingInterval = pollingInterval ?? TimeSpan.FromSeconds(1);

    public string Mode => _mode;

    /// <summary>Диагностика: смена режима, сбои WMI.</summary>
    public event Action<string>? Log;

    public async IAsyncEnumerable<ProcessCreationEvent> ReadEventsAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (TryStartWatcher(TraceQuery, "wmi-trace", OnTraceEvent) || TryStartWatcher(InstanceQuery, "wmi-instance", OnInstanceEvent))
        {
            while (await WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (_channel.Reader.TryRead(out var created))
                {
                    yield return created;
                }
            }

            if (cancellationToken.IsCancellationRequested || _disposed)
            {
                yield break;
            }

            Log?.Invoke("Подписка WMI на старт процессов остановилась — переход на опрос списка процессов.");
        }
        else
        {
            Log?.Invoke("WMI недоступен (Безопасный режим/WinRE или служба winmgmt остановлена) — мониторинг старта процессов через опрос раз в секунду.");
        }

        _mode = "polling";
        var polling = new PollingProcessCreationEventSource(ListProcesses, Enrich, _pollingInterval);
        polling.Faulted += message => Log?.Invoke(message);
        await foreach (var created in polling.ReadEventsAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return created;
        }
    }

    public ValueTask DisposeAsync()
    {
        _disposed = true;
        StopWatcher();
        _channel.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }

    // ---- WMI -------------------------------------------------------------------

    private bool TryStartWatcher(string query, string mode, EventArrivedEventHandler handler)
    {
        ManagementEventWatcher? watcher = null;
        try
        {
            watcher = new ManagementEventWatcher(new ManagementScope(@"\\.\root\cimv2"), new WqlEventQuery(query));
            watcher.EventArrived += handler;
            watcher.Stopped += OnStopped;
            watcher.Start();
            lock (_sync)
            {
                _watcher = watcher;
            }

            _mode = mode;
            Log?.Invoke($"Мониторинг старта процессов: подписка WMI ({query}).");
            return true;
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or InvalidOperationException)
        {
            Log?.Invoke($"Подписка WMI '{mode}' недоступна: {ex.Message}");
            watcher?.Dispose();
            return false;
        }
    }

    private void OnTraceEvent(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var data = e.NewEvent;
            var pid = ToInt(data["ProcessID"]);
            var parent = ToInt(data["ParentProcessID"]);
            var name = data["ProcessName"] as string ?? string.Empty;
            _channel.Writer.TryWrite(Enrich(pid, parent, name, null, null, FromFileTime(data["TIME_CREATED"])));
        }
        catch (Exception ex) when (ex is ManagementException or COMException or InvalidCastException or OverflowException)
        {
            Log?.Invoke($"Событие Win32_ProcessStartTrace не разобрано: {ex.Message}");
        }
    }

    private void OnInstanceEvent(object sender, EventArrivedEventArgs e)
    {
        try
        {
            if (e.NewEvent["TargetInstance"] is not ManagementBaseObject process)
            {
                return;
            }

            using (process)
            {
                var pid = ToInt(process["ProcessId"]);
                var parent = ToInt(process["ParentProcessId"]);
                var name = process["Name"] as string ?? string.Empty;
                _channel.Writer.TryWrite(Enrich(pid, parent, name, process["ExecutablePath"] as string, process["CommandLine"] as string, null));
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or InvalidCastException or OverflowException)
        {
            Log?.Invoke($"Событие __InstanceCreationEvent не разобрано: {ex.Message}");
        }
    }

    private void OnStopped(object sender, StoppedEventArgs e)
    {
        if (!_disposed)
        {
            _channel.Writer.TryComplete(); // читатель перейдёт на опрос
        }
    }

    private void StopWatcher()
    {
        ManagementEventWatcher? watcher;
        lock (_sync)
        {
            watcher = _watcher;
            _watcher = null;
        }

        if (watcher is null)
        {
            return;
        }

        try
        {
            watcher.Stop();
        }
        catch (Exception ex) when (ex is ManagementException or COMException)
        {
            Log?.Invoke($"Остановка подписки WMI: {ex.Message}");
        }
        finally
        {
            watcher.Dispose();
        }
    }

    private async ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    // ---- Дочитывание подробностей ---------------------------------------------

    private static ProcessIdentity[] ListProcesses() =>
        WindowsProcessProvider.EnumerateBasics().Select(p => new ProcessIdentity(p.Key, p.Value.ParentPid, p.Value.Name)).ToArray();

    private static ProcessCreationEvent Enrich(ProcessIdentity id) => Enrich(id.Pid, id.ParentPid, id.Name, null, null, null);

    private static ProcessCreationEvent Enrich(int pid, int parent, string name, string? path, string? commandLine, DateTimeOffset? reported)
    {
        path = string.IsNullOrEmpty(path) ? WindowsProcessProvider.TryGetImagePath(pid) : path;
        commandLine = string.IsNullOrEmpty(commandLine) ? WindowsProcessProvider.TryGetCommandLine(pid) : commandLine;
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(commandLine))
        {
            var (wmiPath, wmiCommandLine) = QueryWin32Process(pid);
            path = string.IsNullOrEmpty(path) ? wmiPath : path;
            commandLine = string.IsNullOrEmpty(commandLine) ? wmiCommandLine : commandLine;
        }

        // Время из GetProcessTimes совпадает с тем, что видит периодический аудит, — ключ находки один и тот же.
        var started = WindowsProcessProvider.TryGetStartTime(pid) is { } utc
            ? new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc))
            : reported ?? DateTimeOffset.UtcNow;
        if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(path))
        {
            name = Path.GetFileName(path);
        }

        return new ProcessCreationEvent(pid, parent, name, path ?? string.Empty, commandLine ?? string.Empty, started);
    }

    private static (string? Path, string? CommandLine) QueryWin32Process(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\cimv2", $"SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (var item in results)
            {
                using (item)
                {
                    return (item["ExecutablePath"] as string, item["CommandLine"] as string);
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            // процесс уже завершился или WMI недоступен — остаются данные из Win32 API
        }

        return (null, null);
    }

    private static int ToInt(object? value) => value is null ? 0 : unchecked((int)Convert.ToUInt32(value, System.Globalization.CultureInfo.InvariantCulture));

    private static DateTimeOffset? FromFileTime(object? value)
    {
        if (value is null)
        {
            return null;
        }

        var ticks = Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);
        return ticks > 0 ? DateTimeOffset.FromFileTime(ticks).ToUniversalTime() : null;
    }
}
