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

// Рабочие процессы стартуют параллельно: долгий первый аудит автозагрузки не задерживает драйвер ядра и IPC.
builder.Services.Configure<HostOptions>(o =>
{
    o.ServicesStartConcurrently = true;
    o.ServicesStopConcurrently = true;
});

// Диагностический журнал: Sentinel.* — с Information (драйвер ядра, синхронизация PID, мониторы), остальное — с Warning.
var dataDirectory = Path.GetFullPath(options.DataDirectory ?? SentinelRuntimeOptions.DefaultDataDirectory());
builder.Services.AddSingleton<ILoggerProvider>(_ => new FileLoggerProvider(Path.Combine(dataDirectory, "Logs")));
builder.Logging.AddFilter<FileLoggerProvider>(null, LogLevel.Warning);
builder.Logging.AddFilter<FileLoggerProvider>("Sentinel", LogLevel.Information);
if (OperatingSystem.IsWindows())
{
    builder.Logging.AddFilter<Microsoft.Extensions.Logging.EventLog.EventLogLoggerProvider>("Sentinel", LogLevel.Information);
}

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

// Порядок важен: защита дескрипторов ядром и именованный канал поднимаются первыми, долгие аудиты — последними.
builder.Services.AddHostedService<RuntimeLogWorker>();
builder.Services.AddHostedService<ServiceRecoveryWorker>();
builder.Services.AddHostedService<KernelBridgeWorker>();
builder.Services.AddHostedService<IpcServerWorker>();
builder.Services.AddHostedService<ProcessStartMonitorWorker>();
builder.Services.AddHostedService<TelemetryWorker>();
builder.Services.AddHostedService<FileMonitorWorker>();
builder.Services.AddHostedService<PeriodicAuditWorker>();
builder.Services.AddHostedService<DatabaseUpdateWorker>();
builder.Services.AddHostedService<FamilyRecheckWorker>();

using var host = builder.Build();
await host.RunAsync().ConfigureAwait(false);
return 0;
