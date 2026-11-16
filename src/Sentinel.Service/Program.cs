using Sentinel.Core.Runtime;
using Sentinel.Service;

// Фоновая служба Sentinel. Устанавливается как служба Windows от имени LocalSystem:
//   sc.exe create SentinelService binPath= "C:\Program Files\Sentinel\Sentinel.Service.exe" start= auto obj= LocalSystem
// Запущенная из консоли работает как обычное приложение (Ctrl+C — остановка).
ServiceOptions options;
try
{
    options = ServiceOptions.Parse(args);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    return 2;
}

var builder = Host.CreateApplicationBuilder();
builder.Services.AddWindowsService(o => o.ServiceName = ServiceOptions.ServiceName);
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(_ =>
{
    var runtimeOptions = SentinelRuntimeOptions.CreateDefault("service", options.DataDirectory, options.RulesDirectory);
    if (OperatingSystem.IsWindows())
    {
        DataDirectorySecurity.Harden(runtimeOptions.DataDirectory);
        // Самозащита: убираем у администраторов права на завершение/запись памяти/приостановку собственного процесса службы.
        ProcessSelfProtectionApplier.Harden();
    }

    return new SentinelRuntime(runtimeOptions);
});
builder.Services.AddHostedService<RuntimeLogWorker>();
builder.Services.AddHostedService<TelemetryWorker>();
builder.Services.AddHostedService<FileMonitorWorker>();
builder.Services.AddHostedService<PeriodicAuditWorker>();
builder.Services.AddHostedService<ProcessStartMonitorWorker>();
builder.Services.AddHostedService<IpcServerWorker>();
builder.Services.AddHostedService<DatabaseUpdateWorker>();

using var host = builder.Build();
await host.RunAsync().ConfigureAwait(false);
return 0;
