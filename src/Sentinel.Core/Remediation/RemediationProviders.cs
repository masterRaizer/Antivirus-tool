using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Sentinel.Core.Audit.Config;

namespace Sentinel.Core.Remediation;

/// <summary>Итог одной операции платформенного провайдера.</summary>
public sealed record ProviderResult(bool Success, string? Error = null)
{
    public static ProviderResult Ok { get; } = new(true);

    public static ProviderResult Fail(string error) => new(false, error);
}

/// <summary>Принудительное завершение процесса по PID.</summary>
public interface IProcessTerminator
{
    ProviderResult Terminate(int pid);
}

/// <summary>Изменение задач планировщика: экспорт (резервная копия), удаление и воссоздание.</summary>
public interface IScheduledTaskEditor
{
    /// <summary>XML-определение задачи или <c>null</c>, если задача не найдена/недоступна.</summary>
    string? ExportXml(string taskPath);

    ProviderResult Delete(string taskPath);

    ProviderResult Create(string taskPath, string xml);
}

/// <summary>
/// Изменение списков исключений встроенной защиты Windows
/// (методы <c>Remove</c>/<c>Add</c> WMI-класса <c>MSFT_MpPreference</c>).
/// </summary>
public interface IDefenderPreferenceProvider
{
    ProviderResult RemoveExclusion(DefenderExclusionKind kind, string value);

    /// <summary>Возврат исключения при отмене нейтрализации.</summary>
    ProviderResult AddExclusion(DefenderExclusionKind kind, string value);
}

/// <summary>Завершение процесса через Win32: <c>OpenProcess(PROCESS_TERMINATE)</c> → <c>TerminateProcess</c>.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessTerminator : IProcessTerminator
{
    private const uint PROCESS_TERMINATE = 0x0001;
    private const uint SYNCHRONIZE = 0x00100000;
    private const int ERROR_INVALID_PARAMETER = 87;
    private const uint WAIT_OBJECT_0 = 0;

    private readonly uint _waitMilliseconds;

    public WindowsProcessTerminator(TimeSpan? waitForExit = null) =>
        _waitMilliseconds = (uint)(waitForExit ?? TimeSpan.FromSeconds(5)).TotalMilliseconds;

    public ProviderResult Terminate(int pid)
    {
        var handle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            // Процесса с таким PID уже нет — цель достигнута.
            return error == ERROR_INVALID_PARAMETER
                ? ProviderResult.Ok
                : ProviderResult.Fail($"OpenProcess: {new Win32Exception(error).Message}");
        }

        try
        {
            if (!TerminateProcess(handle, 1))
            {
                return ProviderResult.Fail($"TerminateProcess: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
            }

            return WaitForSingleObject(handle, _waitMilliseconds) == WAIT_OBJECT_0
                ? ProviderResult.Ok
                : ProviderResult.Fail("Процесс не завершился за отведённое время.");
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}

/// <summary>Запуск штатных утилит Windows строго из System32 (без поиска по PATH) с ограничением по времени.</summary>
[SupportedOSPlatform("windows")]
internal static class SystemTool
{
    public static string System32Path(params string[] relative) =>
        Path.Combine([Environment.GetFolderPath(Environment.SpecialFolder.System), .. relative]);

    public static (int ExitCode, string Output, string Error) Run(
        string fileName, IEnumerable<string> arguments, TimeSpan timeout,
        IReadOnlyDictionary<string, string>? environment = null, Encoding? outputEncoding = null)
    {
        using var proc = new System.Diagnostics.Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        if (outputEncoding is not null)
        {
            proc.StartInfo.StandardOutputEncoding = outputEncoding;
        }

        foreach (var a in arguments)
        {
            proc.StartInfo.ArgumentList.Add(a);
        }

        if (environment is not null)
        {
            foreach (var (name, value) in environment)
            {
                proc.StartInfo.Environment[name] = value;
            }
        }

        try
        {
            proc.Start();
            // Оба потока читаются асинхронно, иначе заполненный буфер stderr заблокирует процесс.
            var stdout = proc.StandardOutput.ReadToEndAsync();
            var stderr = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit((int)timeout.TotalMilliseconds))
            {
                try
                {
                    proc.Kill(entireProcessTree: true);
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                {
                    // процесс уже завершился
                }

                return (-1, string.Empty, $"{Path.GetFileName(fileName)}: превышено время ожидания.");
            }

            proc.WaitForExit();
            return (proc.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult().Trim());
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return (-1, string.Empty, ex.Message);
        }
    }
}

/// <summary>
/// Задачи планировщика через штатный <c>schtasks.exe</c>: <c>/Query /XML</c> — резервная копия,
/// <c>/Delete</c> — удаление, <c>/Create /XML</c> — восстановление при отмене.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsScheduledTaskEditor : IScheduledTaskEditor
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private static string Schtasks => SystemTool.System32Path("schtasks.exe");

    public string? ExportXml(string taskPath)
    {
        var (code, output, _) = SystemTool.Run(Schtasks, ["/Query", "/TN", taskPath, "/XML"], Timeout);
        return code == 0 && output.Contains("<Task", StringComparison.OrdinalIgnoreCase) ? output.Trim() : null;
    }

    public ProviderResult Delete(string taskPath)
    {
        var (code, _, error) = SystemTool.Run(Schtasks, ["/Delete", "/TN", taskPath, "/F"], Timeout);
        return code == 0 ? ProviderResult.Ok : ProviderResult.Fail($"schtasks /Delete: {error}");
    }

    public ProviderResult Create(string taskPath, string xml)
    {
        var temp = Path.Combine(Path.GetTempPath(), $"sentinel-task-{Guid.NewGuid():N}.xml");
        try
        {
            File.WriteAllText(temp, xml, Encoding.Unicode); // schtasks ожидает UTF-16
            var (code, _, error) = SystemTool.Run(Schtasks, ["/Create", "/TN", taskPath, "/XML", temp, "/F"], Timeout);
            return code == 0 ? ProviderResult.Ok : ProviderResult.Fail($"schtasks /Create: {error}");
        }
        finally
        {
            File.Delete(temp);
        }
    }
}

/// <summary>
/// Исключения Defender через WMI: метод <c>Remove</c> (и <c>Add</c> для отмены) класса
/// <c>MSFT_MpPreference</c> в пространстве имён <c>root\Microsoft\Windows\Defender</c>, вызываемый
/// средствами CIM. Значение исключения передаётся через переменные окружения, а не подставляется
/// в текст сценария: строки исключений контролирует потенциальный злоумышленник.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDefenderPreferenceProvider : IDefenderPreferenceProvider
{
    public const string WmiNamespace = @"root\Microsoft\Windows\Defender";
    public const string WmiClass = "MSFT_MpPreference";

    private const string Script =
        "$ErrorActionPreference='Stop';" +
        "$a=@{};$a[$env:SENTINEL_MP_PROPERTY]=[string[]]@($env:SENTINEL_MP_VALUE);" +
        "$r=Invoke-CimMethod -Namespace $env:SENTINEL_MP_NAMESPACE -ClassName $env:SENTINEL_MP_CLASS -MethodName $env:SENTINEL_MP_METHOD -Arguments $a;" +
        "exit [int]$r.ReturnValue";

    private readonly TimeSpan _timeout;

    public WindowsDefenderPreferenceProvider(TimeSpan? timeout = null) => _timeout = timeout ?? TimeSpan.FromSeconds(60);

    public ProviderResult RemoveExclusion(DefenderExclusionKind kind, string value) => Invoke("Remove", kind, value);

    public ProviderResult AddExclusion(DefenderExclusionKind kind, string value) => Invoke("Add", kind, value);

    private ProviderResult Invoke(string method, DefenderExclusionKind kind, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        var property = new DefenderExclusion(kind, value, string.Empty).PreferenceProperty;
        var environment = new Dictionary<string, string>
        {
            ["SENTINEL_MP_NAMESPACE"] = WmiNamespace,
            ["SENTINEL_MP_CLASS"] = WmiClass,
            ["SENTINEL_MP_METHOD"] = method,
            ["SENTINEL_MP_PROPERTY"] = property,
            ["SENTINEL_MP_VALUE"] = value,
        };

        var powershell = SystemTool.System32Path("WindowsPowerShell", "v1.0", "powershell.exe");
        var (code, _, error) = SystemTool.Run(
            powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", Script], _timeout, environment);
        return code == 0
            ? ProviderResult.Ok
            : ProviderResult.Fail($"{WmiClass}.{method}({property}) завершился с кодом {code}: {error}");
    }
}
