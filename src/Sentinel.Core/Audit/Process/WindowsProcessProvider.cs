using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Sentinel.Core.Audit.Process;

/// <summary>
/// Поставщик списка процессов для Windows на основе Win32 API:
/// перечисление — CreateToolhelp32Snapshot; путь к образу — QueryFullProcessImageNameW;
/// командная строка — чтение PEB → RTL_USER_PROCESS_PARAMETERS целевого процесса;
/// загрузка CPU — два замера GetProcessTimes за фиксированный интервал.
/// Никаких заглушек: все данные берутся из ядра. Недоступные поля честно остаются null/−1.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessProvider : IProcessProvider
{
    private readonly TimeSpan _cpuSampleInterval;

    /// <param name="cpuSampleInterval">
    /// Интервал между двумя замерами процессорного времени. <see cref="TimeSpan.Zero"/> — не измерять CPU.
    /// </param>
    public WindowsProcessProvider(TimeSpan? cpuSampleInterval = null)
    {
        _cpuSampleInterval = cpuSampleInterval ?? TimeSpan.FromMilliseconds(300);
    }

    public IReadOnlyList<ProcessSnapshot> GetProcesses()
    {
        var basics = EnumerateBasics();

        Dictionary<int, (long Kernel, long User)>? first = null;
        if (_cpuSampleInterval > TimeSpan.Zero)
        {
            first = SampleProcessTimes(basics.Keys);
            Thread.Sleep(_cpuSampleInterval);
        }

        var second = first is null ? null : SampleProcessTimes(basics.Keys);
        var cpuCount = Math.Max(1, Environment.ProcessorCount);
        var intervalTicks = _cpuSampleInterval.Ticks;

        var result = new List<ProcessSnapshot>(basics.Count);
        foreach (var (pid, info) in basics)
        {
            double cpu = -1;
            if (first is not null && second is not null &&
                first.TryGetValue(pid, out var a) && second.TryGetValue(pid, out var b) && intervalTicks > 0)
            {
                var busy = (b.Kernel - a.Kernel) + (b.User - a.User);
                cpu = Math.Clamp(busy * 100.0 / (intervalTicks * cpuCount), 0, 100);
            }

            result.Add(new ProcessSnapshot
            {
                Pid = pid,
                ParentPid = info.ParentPid,
                Name = info.Name,
                ExecutablePath = TryGetImagePath(pid),
                StartTimeUtc = TryGetStartTime(pid),
                CommandLine = TryGetCommandLine(pid),
                CpuPercent = cpu,
                GpuPercent = -1,
            });
        }

        return result;
    }

    internal static Dictionary<int, (int ParentPid, string Name)> EnumerateBasics()
    {
        var map = new Dictionary<int, (int, string)>();
        var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);
        if (snapshot == NativeMethods.INVALID_HANDLE_VALUE)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateToolhelp32Snapshot завершился ошибкой.");
        }

        try
        {
            var entry = new NativeMethods.PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32>() };
            if (!NativeMethods.Process32First(snapshot, ref entry))
            {
                return map;
            }

            do
            {
                var name = entry.szExeFile ?? string.Empty;
                map[(int)entry.th32ProcessID] = ((int)entry.th32ParentProcessID, name);
            }
            while (NativeMethods.Process32Next(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        return map;
    }

    private static Dictionary<int, (long Kernel, long User)> SampleProcessTimes(IEnumerable<int> pids)
    {
        var map = new Dictionary<int, (long, long)>();
        foreach (var pid in pids)
        {
            var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (handle == IntPtr.Zero)
            {
                continue;
            }

            try
            {
                if (NativeMethods.GetProcessTimes(handle, out _, out _, out var kernel, out var user))
                {
                    map[pid] = (ToTicks(kernel), ToTicks(user));
                }
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        return map;
    }

    private static long ToTicks(NativeMethods.FILETIME ft) => ((long)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;

    internal static DateTime? TryGetStartTime(int pid)
    {
        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            if (!NativeMethods.GetProcessTimes(handle, out var creation, out _, out _, out _))
            {
                return null;
            }

            var ticks = ToTicks(creation);
            return ticks > 0 ? DateTime.FromFileTimeUtc(ticks) : null;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    internal static string? TryGetImagePath(int pid)
    {
        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            const int capacity = 1024;
            var buffer = new char[capacity];
            var size = (uint)capacity;
            return NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref size)
                ? new string(buffer, 0, (int)size)
                : null;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    /// <summary>
    /// Читает командную строку целевого процесса из его PEB. Работает для процессов той же
    /// разрядности, что и аудитор (на x64 — для 64-битных целей). Для недоступных целей (отказ
    /// доступа, иная разрядность) честно возвращает <c>null</c>, а не выдуманные данные.
    /// </summary>
    internal static string? TryGetCommandLine(int pid)
    {
        if (!Environment.Is64BitProcess)
        {
            return null;
        }

        var handle = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var pbi = new NativeMethods.PROCESS_BASIC_INFORMATION();
            var status = NativeMethods.NtQueryInformationProcess(
                handle, 0, ref pbi, (uint)Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out _);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero)
            {
                return null;
            }

            // PEB (x64): +0x20 -> ProcessParameters
            if (!TryReadPointer(handle, pbi.PebBaseAddress + 0x20, out var paramsPtr) || paramsPtr == IntPtr.Zero)
            {
                return null;
            }

            // RTL_USER_PROCESS_PARAMETERS (x64): +0x70 -> CommandLine (UNICODE_STRING)
            var unicode = new NativeMethods.UNICODE_STRING();
            if (!NativeMethods.ReadProcessMemory(handle, paramsPtr + 0x70, ref unicode,
                    (uint)Marshal.SizeOf<NativeMethods.UNICODE_STRING>(), out _))
            {
                return null;
            }

            if (unicode.Length == 0 || unicode.Buffer == IntPtr.Zero || unicode.Length > 0x8000)
            {
                return unicode.Length == 0 ? string.Empty : null;
            }

            var buffer = new byte[unicode.Length];
            if (!NativeMethods.ReadProcessMemory(handle, unicode.Buffer, buffer, unicode.Length, out var read) || read == IntPtr.Zero)
            {
                return null;
            }

            return Encoding.Unicode.GetString(buffer, 0, (int)read);
        }
        catch (Exception ex) when (ex is Win32Exception or OverflowException)
        {
            return null;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private static bool TryReadPointer(IntPtr handle, IntPtr address, out IntPtr value)
    {
        var buffer = new byte[IntPtr.Size];
        value = IntPtr.Zero;
        if (!NativeMethods.ReadProcessMemory(handle, address, buffer, (uint)buffer.Length, out var read) || (int)read != buffer.Length)
        {
            return false;
        }

        value = new IntPtr(BitConverter.ToInt64(buffer, 0));
        return true;
    }

    private static class NativeMethods
    {
        public const uint TH32CS_SNAPPROCESS = 0x00000002;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, [Out] char[] lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetProcessTimes(IntPtr hProcess, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref UNICODE_STRING lpBuffer, uint nSize, out IntPtr lpNumberOfBytesRead);
    }
}

/// <summary>Фабрика поставщика процессов: Windows-реализация или явный отказ на других ОС.</summary>
public static class ProcessProviderFactory
{
    public static IProcessProvider CreateDefault(TimeSpan? cpuSampleInterval = null) =>
        OperatingSystem.IsWindows()
            ? new WindowsProcessProvider(cpuSampleInterval)
            : throw new PlatformNotSupportedException("Перечисление процессов реализовано только для Windows.");

    public static bool IsSupported => OperatingSystem.IsWindows();
}
