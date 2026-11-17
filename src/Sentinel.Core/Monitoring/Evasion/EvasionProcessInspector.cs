using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Sentinel.Core.Audit.Process;

namespace Sentinel.Core.Monitoring.Evasion;

/// <summary>Сведения о процессе для оценки находки: командная строка и число USER-объектов (−1 — неизвестно).</summary>
public sealed record EvasionProcessDetails(string? CommandLine, int UserObjects);

/// <summary>Доступ к сведениям о конкретном процессе. Вызывается только для находок и только после <c>CriticalProcessGuard</c>.</summary>
public interface IEvasionProcessInspector
{
    /// <summary>Путь к образу (дескриптор только с <c>PROCESS_QUERY_LIMITED_INFORMATION</c>); <c>null</c> — недоступен.</summary>
    string? GetImagePath(int pid);

    /// <summary>Командная строка и USER-объекты. Вызывать только для процесса, не защищённого <c>CriticalProcessGuard</c>.</summary>
    EvasionProcessDetails Describe(int pid);
}

/// <summary>Windows: путь — <c>QueryFullProcessImageName</c>, командная строка — PEB, окна — <c>GetGuiResources(GR_USEROBJECTS)</c>.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEvasionProcessInspector : IEvasionProcessInspector
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint GrUserObjects = 1;

    public string? GetImagePath(int pid) => WindowsProcessProvider.TryGetImagePath(pid);

    public EvasionProcessDetails Describe(int pid) => new(WindowsProcessProvider.TryGetCommandLine(pid), UserObjects(pid));

    private static int UserObjects(int pid)
    {
        var handle = NativeMethods.OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            return -1;
        }

        try
        {
            var count = NativeMethods.GetGuiResources(handle, GrUserObjects);
            // 0 с ошибкой — сведения недоступны (например, другой сеанс); 0 без ошибки — окон действительно нет.
            return count == 0 && Marshal.GetLastWin32Error() != 0 ? -1 : (int)count;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
    }
}
