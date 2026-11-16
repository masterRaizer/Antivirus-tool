using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Service;

/// <summary>
/// Политика восстановления SentinelService после сбоя: перезапуск через 5 с, 30 с и 60 с, сброс счётчика за сутки.
/// Раньше она задавалась таблицей MSI <c>MsiServiceConfigFailureActions</c>, но встроенное действие Windows Installer открывает
/// службу без права <c>SERVICE_START</c>, нужного для <c>SC_ACTION_RESTART</c>, и на части систем получает ACCESS_DENIED →
/// ошибка 1939 → откат установки (1603). Теперь служба, работающая от LocalSystem, выставляет политику себе сама при старте;
/// неудача только журналируется и ни на что не влияет.
/// </summary>
internal static class ServiceRecoveryPolicy
{
    public const uint ResetPeriodSeconds = 86_400;

    /// <summary>Задержки перезапуска после 1-го, 2-го и последующих сбоев.</summary>
    public static IReadOnlyList<TimeSpan> RestartDelays { get; } =
        [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60)];

    /// <summary>Описание политики для журнала и для сверки с <c>sc.exe qfailure SentinelService</c>.</summary>
    public static string Describe() =>
        $"сброс счётчика через {ResetPeriodSeconds} с; перезапуск через {string.Join(" / ", RestartDelays.Select(d => $"{d.TotalSeconds:0} с"))}";
}

/// <summary>Применение <see cref="ServiceRecoveryPolicy"/> к службе через <c>ChangeServiceConfig2</c>.</summary>
[SupportedOSPlatform("windows")]
internal static class ServiceRecoveryConfigurator
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_CHANGE_CONFIG = 0x0002;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_CONFIG_FAILURE_ACTIONS = 2;
    private const uint SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4;
    private const int SC_ACTION_RESTART = 1;

    /// <summary>Выставляет политику восстановления. Исключений не бросает: результат — для журнала.</summary>
    public static (bool Success, string Message) Apply(string serviceName)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return (false, $"OpenSCManager: {LastError()}");
        }

        var actions = IntPtr.Zero;
        try
        {
            // SERVICE_START обязателен для действий SC_ACTION_RESTART (иначе ChangeServiceConfig2 вернёт ERROR_ACCESS_DENIED).
            var service = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_CONFIG);
            if (service == IntPtr.Zero)
            {
                return (false, $"OpenService({serviceName}): {LastError()}");
            }

            try
            {
                var delays = ServiceRecoveryPolicy.RestartDelays;
                var size = Marshal.SizeOf<SC_ACTION>();
                actions = Marshal.AllocHGlobal(size * delays.Count);
                for (var i = 0; i < delays.Count; i++)
                {
                    Marshal.StructureToPtr(new SC_ACTION { Type = SC_ACTION_RESTART, Delay = (uint)delays[i].TotalMilliseconds },
                        actions + (i * size), false);
                }

                var failure = new SERVICE_FAILURE_ACTIONS
                {
                    dwResetPeriod = ServiceRecoveryPolicy.ResetPeriodSeconds,
                    lpRebootMsg = null,
                    lpCommand = null,
                    cActions = (uint)delays.Count,
                    lpsaActions = actions,
                };
                if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, ref failure))
                {
                    return (false, $"ChangeServiceConfig2(FAILURE_ACTIONS): {LastError()}");
                }

                // Перезапуск и при аварийной остановке с ненулевым кодом выхода, а не только при падении процесса.
                var flag = new SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures = 1 };
                if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, ref flag))
                {
                    return (true, $"Политика восстановления выставлена ({ServiceRecoveryPolicy.Describe()}); флаг non-crash не принят: {LastError()}");
                }

                return (true, $"Политика восстановления выставлена: {ServiceRecoveryPolicy.Describe()}.");
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            if (actions != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(actions);
            }

            CloseServiceHandle(scm);
        }
    }

    private static string LastError() => new Win32Exception(Marshal.GetLastPInvokeError()).Message;

    [StructLayout(LayoutKind.Sequential)]
    private struct SC_ACTION
    {
        public int Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_FAILURE_ACTIONS
    {
        public uint dwResetPeriod;
        public string? lpRebootMsg;
        public string? lpCommand;
        public uint cActions;
        public IntPtr lpsaActions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_FAILURE_ACTIONS_FLAG
    {
        public int fFailureActionsOnNonCrashFailures;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ChangeServiceConfig2W")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2W(IntPtr hService, uint dwInfoLevel, ref SERVICE_FAILURE_ACTIONS lpInfo);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ChangeServiceConfig2W")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2W(IntPtr hService, uint dwInfoLevel, ref SERVICE_FAILURE_ACTIONS_FLAG lpInfo);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);
}

/// <summary>При запуске как служба Windows выставляет себе политику восстановления (вместо таблицы MSI).</summary>
internal sealed partial class ServiceRecoveryWorker(ILogger<ServiceRecoveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!OperatingSystem.IsWindows() || !Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService())
        {
            return; // запуск из консоли — службы нет, настраивать нечего
        }

        var (success, message) = ServiceRecoveryConfigurator.Apply(ServiceOptions.ServiceName);
        if (success)
        {
            LogApplied(logger, message);
        }
        else
        {
            LogFailed(logger, message);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Восстановление службы: {Message}")]
    private static partial void LogApplied(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Восстановление службы не настроено (служба работает, автоперезапуск — по sc.exe failure): {Message}")]
    private static partial void LogFailed(ILogger logger, string message);
}
