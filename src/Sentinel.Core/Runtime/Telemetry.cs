using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Runtime;

/// <summary>Мгновенные показатели нагрузки системы (проценты 0..100; отрицательное — показатель недоступен).</summary>
public sealed record TelemetryReading(double CpuPercent, double RamPercent, double DiskPercent, long RamUsedBytes, long RamTotalBytes);

/// <summary>Источник телеметрии. Загрузка CPU и диска считается между двумя последовательными вызовами.</summary>
public interface ITelemetryProvider : IDisposable
{
    TelemetryReading Read();
}

public static class TelemetryProviderFactory
{
    public static ITelemetryProvider CreateDefault() =>
        OperatingSystem.IsWindows() ? new WindowsTelemetryProvider() : new ProcTelemetryProvider();
}

/// <summary>
/// Телеметрия Windows: CPU — <c>GetSystemTimes</c>, память — <c>GlobalMemoryStatusEx</c>,
/// активность диска — счётчик PDH <c>\PhysicalDisk(_Total)\% Idle Time</c>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsTelemetryProvider : ITelemetryProvider
{
    private const uint PdhFmtDouble = 0x00000200;
    private readonly object _sync = new();
    private ulong _prevIdle;
    private ulong _prevTotal;
    private IntPtr _query;
    private IntPtr _diskCounter;

    public WindowsTelemetryProvider()
    {
        if (NativeMethods.PdhOpenQuery(null, IntPtr.Zero, out _query) == 0)
        {
            if (NativeMethods.PdhAddEnglishCounter(_query, @"\PhysicalDisk(_Total)\% Idle Time", IntPtr.Zero, out _diskCounter) != 0)
            {
                _diskCounter = IntPtr.Zero;
            }
            else
            {
                _ = NativeMethods.PdhCollectQueryData(_query); // первый замер — точка отсчёта
            }
        }
        else
        {
            _query = IntPtr.Zero;
        }

        ReadCpu();
    }

    public TelemetryReading Read()
    {
        lock (_sync)
        {
            var cpu = ReadCpu();
            var status = new NativeMethods.MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<NativeMethods.MEMORYSTATUSEX>() };
            long total = 0, used = 0;
            double ram = -1;
            if (NativeMethods.GlobalMemoryStatusEx(ref status) && status.ullTotalPhys > 0)
            {
                total = (long)status.ullTotalPhys;
                used = (long)(status.ullTotalPhys - status.ullAvailPhys);
                ram = 100.0 * used / total;
            }

            return new TelemetryReading(cpu, ram, ReadDisk(), used, total);
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_query != IntPtr.Zero)
            {
                _ = NativeMethods.PdhCloseQuery(_query);
                _query = IntPtr.Zero;
                _diskCounter = IntPtr.Zero;
            }
        }
    }

    private double ReadCpu()
    {
        if (!NativeMethods.GetSystemTimes(out var idleTime, out var kernelTime, out var userTime))
        {
            return -1;
        }

        // Время ядра включает простой, поэтому занятость = 1 − простой / (ядро + пользователь).
        var idle = idleTime.Value;
        var total = kernelTime.Value + userTime.Value;
        var idleDelta = idle - _prevIdle;
        var totalDelta = total - _prevTotal;
        var first = _prevTotal == 0;
        _prevIdle = idle;
        _prevTotal = total;
        return first || totalDelta == 0 ? 0 : Math.Clamp(100.0 * (1.0 - (double)idleDelta / totalDelta), 0, 100);
    }

    private double ReadDisk()
    {
        if (_query == IntPtr.Zero || _diskCounter == IntPtr.Zero || NativeMethods.PdhCollectQueryData(_query) != 0)
        {
            return -1;
        }

        return NativeMethods.PdhGetFormattedCounterValue(_diskCounter, PdhFmtDouble, IntPtr.Zero, out var value) == 0 && value.CStatus == 0
            ? Math.Clamp(100.0 - value.DoubleValue, 0, 100)
            : -1;
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;

            public readonly ulong Value => ((ulong)dwHighDateTime << 32) | dwLowDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct PDH_FMT_COUNTERVALUE
        {
            [FieldOffset(0)]
            public uint CStatus;

            [FieldOffset(8)]
            public double DoubleValue;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetSystemTimes(out FILETIME idle, out FILETIME kernel, out FILETIME user);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);

        [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhOpenQueryW")]
        public static extern int PdhOpenQuery(string? dataSource, IntPtr userData, out IntPtr query);

        [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhAddEnglishCounterW")]
        public static extern int PdhAddEnglishCounter(IntPtr query, string counterPath, IntPtr userData, out IntPtr counter);

        [DllImport("pdh.dll")]
        public static extern int PdhCollectQueryData(IntPtr query);

        [DllImport("pdh.dll")]
        public static extern int PdhGetFormattedCounterValue(IntPtr counter, uint format, IntPtr type, out PDH_FMT_COUNTERVALUE value);

        [DllImport("pdh.dll")]
        public static extern int PdhCloseQuery(IntPtr query);
    }
}

/// <summary>Телеметрия Linux из procfs (<c>/proc/stat</c>, <c>/proc/meminfo</c>, <c>/proc/diskstats</c>) — для разработки и тестов.</summary>
public sealed class ProcTelemetryProvider : ITelemetryProvider
{
    private readonly string _root;
    private readonly TimeProvider _time;
    private readonly object _sync = new();
    private (long Idle, long Total)? _prevCpu;
    private (long IoMs, long Timestamp)? _prevDisk;

    public ProcTelemetryProvider(string procRoot = "/proc", TimeProvider? timeProvider = null)
    {
        _root = procRoot;
        _time = timeProvider ?? TimeProvider.System;
    }

    public TelemetryReading Read()
    {
        lock (_sync)
        {
            var (used, total) = ReadMemory();
            return new TelemetryReading(ReadCpu(), total > 0 ? 100.0 * used / total : -1, ReadDisk(), used, total);
        }
    }

    public void Dispose()
    {
    }

    internal static (long Idle, long Total)? ParseCpu(string? statLine)
    {
        if (statLine is null || !statLine.StartsWith("cpu ", StringComparison.Ordinal))
        {
            return null;
        }

        var parts = statLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        long total = 0, idle = 0;
        for (var i = 1; i < parts.Length && i <= 8; i++)
        {
            if (!long.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                return null;
            }

            total += value;
            if (i is 4 or 5)
            {
                idle += value; // idle + iowait
            }
        }

        return (idle, total);
    }

    /// <summary>Суммарное время ввода-вывода (мс) по целым дискам; разделы и виртуальные устройства пропускаются.</summary>
    internal static long ParseDiskIoMs(IEnumerable<string> lines)
    {
        long sum = 0;
        foreach (var line in lines)
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 13 || !IsWholeDisk(parts[2]))
            {
                continue;
            }

            if (long.TryParse(parts[12], NumberStyles.None, CultureInfo.InvariantCulture, out var ms))
            {
                sum += ms;
            }
        }

        return sum;
    }

    private static bool IsWholeDisk(string name)
    {
        if (name.StartsWith("nvme", StringComparison.Ordinal) || name.StartsWith("mmcblk", StringComparison.Ordinal))
        {
            return !name.Contains('p', StringComparison.Ordinal) || name.LastIndexOf('p') < 4;
        }

        return (name.StartsWith("sd", StringComparison.Ordinal) || name.StartsWith("vd", StringComparison.Ordinal)
                || name.StartsWith("hd", StringComparison.Ordinal) || name.StartsWith("xvd", StringComparison.Ordinal))
            && !char.IsDigit(name[^1]);
    }

    private double ReadCpu()
    {
        var current = ParseCpu(ReadLines("stat").FirstOrDefault());
        if (current is null)
        {
            return -1;
        }

        var previous = _prevCpu;
        _prevCpu = current;
        if (previous is null || current.Value.Total <= previous.Value.Total)
        {
            return 0;
        }

        var total = current.Value.Total - previous.Value.Total;
        var idle = current.Value.Idle - previous.Value.Idle;
        return Math.Clamp(100.0 * (total - idle) / total, 0, 100);
    }

    private (long Used, long Total) ReadMemory()
    {
        long total = 0, available = 0;
        foreach (var line in ReadLines("meminfo"))
        {
            if (line.StartsWith("MemTotal:", StringComparison.Ordinal))
            {
                total = ParseKb(line);
            }
            else if (line.StartsWith("MemAvailable:", StringComparison.Ordinal))
            {
                available = ParseKb(line);
            }
        }

        return (Math.Max(0, total - available), total);
    }

    private double ReadDisk()
    {
        var lines = ReadLines("diskstats");
        if (lines.Length == 0)
        {
            return -1;
        }

        var current = (IoMs: ParseDiskIoMs(lines), Timestamp: _time.GetTimestamp());
        var previous = _prevDisk;
        _prevDisk = current;
        if (previous is null)
        {
            return 0;
        }

        var elapsedMs = _time.GetElapsedTime(previous.Value.Timestamp, current.Timestamp).TotalMilliseconds;
        return elapsedMs <= 0 ? 0 : Math.Clamp(100.0 * (current.IoMs - previous.Value.IoMs) / elapsedMs, 0, 100);
    }

    private static long ParseKb(string line)
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var kb) ? kb * 1024 : 0;
    }

    private string[] ReadLines(string file)
    {
        try
        {
            return File.ReadAllLines(Path.Combine(_root, file));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
