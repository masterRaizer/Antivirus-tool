using Sentinel.Core.Ipc;
using Sentinel.Core.Runtime;

namespace Sentinel.Service;

/// <summary>
/// Мониторинг пользовательских и системных каталогов в реальном времени
/// (<c>FileSystemWatcher</c> с дебаунсом и отсевом системного шума).
/// </summary>
internal sealed partial class FileMonitorWorker(SentinelRuntime runtime, ILogger<FileMonitorWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogStarted(logger, runtime.RealtimeEnabled);
        await runtime.RunFileMonitorAsync(stoppingToken).ConfigureAwait(false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Файловый монитор запущен (защита в реальном времени: {Enabled}).")]
    private static partial void LogStarted(ILogger logger, bool enabled);
}

/// <summary>Периодический аудит новых процессов, критических точек автозагрузки и исключений конфигурации.</summary>
internal sealed partial class PeriodicAuditWorker(SentinelRuntime runtime, ILogger<PeriodicAuditWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogStarted(logger);
        await runtime.RunPeriodicAuditAsync(stoppingToken).ConfigureAwait(false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Фоновый аудит процессов, автозагрузки и конфигурации запущен.")]
    private static partial void LogStarted(ILogger logger);
}

/// <summary>
/// Мониторинг старта процессов в реальном времени (WMI <c>Win32_ProcessStartTrace</c>, резервно — опрос раз в секунду):
/// командная строка и образ нового процесса проверяются сразу, а не на следующем тике периодического аудита.
/// </summary>
internal sealed partial class ProcessStartMonitorWorker(SentinelRuntime runtime, ILogger<ProcessStartMonitorWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogStarted(logger);
        await runtime.RunProcessStartMonitorAsync(stoppingToken).ConfigureAwait(false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Мониторинг старта процессов запущен.")]
    private static partial void LogStarted(ILogger logger);
}

/// <summary>Фоновое автообновление баз угроз каждые 6 часов (если не отключено в «Настройках и базах»).</summary>
internal sealed class DatabaseUpdateWorker(SentinelRuntime runtime) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runtime.RunDatabaseUpdatesAsync(stoppingToken);
}

/// <summary>Сбор телеметрии (CPU, память, диск) для графиков интерфейса.</summary>
internal sealed class TelemetryWorker(SentinelRuntime runtime) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runtime.RunTelemetryAsync(stoppingToken);
}

/// <summary>Встроенный <see cref="SentinelIpcServer"/>: связь с пользовательским интерфейсом по именованному каналу.</summary>
internal sealed partial class IpcServerWorker(SentinelRuntime runtime, ServiceOptions options, ILogger<IpcServerWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Вне Windows (отладка) канал доступен только текущему пользователю; в службе — интерактивным пользователям.
        var server = new SentinelIpcServer(runtime, new IpcServerOptions
        {
            PipeName = options.PipeName,
            AllowInteractiveUsers = OperatingSystem.IsWindows(),
        });
        await using (server.ConfigureAwait(false))
        {
            server.ConnectionFaulted += message => LogFault(logger, message);
            LogListening(logger, options.PipeName);
            await server.RunAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "IPC-сервер принимает подключения, канал: {Pipe}")]
    private static partial void LogListening(ILogger logger, string pipe);

    [LoggerMessage(Level = LogLevel.Warning, Message = "IPC: {Message}")]
    private static partial void LogFault(ILogger logger, string message);
}

/// <summary>Переносит события рантайма (находки, сбои фоновых циклов) в журнал службы.</summary>
internal sealed partial class RuntimeLogWorker(SentinelRuntime runtime, ILogger<RuntimeLogWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        runtime.Log += OnLog;
        runtime.ThreatRaised += OnThreat;
        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            runtime.Log -= OnLog;
            runtime.ThreatRaised -= OnThreat;
        }
    }

    private void OnLog(string message) => LogRuntime(logger, message);

    private void OnThreat(Sentinel.Core.Realtime.ThreatEvent threat) =>
        LogThreat(logger, threat.Severity.ToString(), threat.Name, threat.Path ?? "-", threat.Reason, threat.Status.ToString());

    [LoggerMessage(Level = LogLevel.Warning, Message = "{Message}")]
    private static partial void LogRuntime(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Находка [{Severity}] {Name} ({Path}): {Reason} → {Status}")]
    private static partial void LogThreat(ILogger logger, string severity, string name, string path, string reason, string status);
}
