using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Monitoring.Evasion;

/// <summary>
/// Замер активности всех процессов одним вызовом <c>NtQuerySystemInformation(SystemProcessInformation)</c>: PID, родитель,
/// имя образа, время создания и накопленное время ядра и пользователя. Дескрипторы процессов не открываются вообще —
/// поэтому замер безопасен и для процессов под защитой <c>CriticalProcessGuard</c>. Общая занятость процессоров —
/// <c>SystemProcessorPerformanceInformation</c>. Буфер переиспользуется между замерами и растёт при
/// <c>STATUS_INFO_LENGTH_MISMATCH</c>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessActivitySampler : IProcessActivitySampler
{
    private const int SystemProcessInformation = 5;
    private const int SystemProcessorPerformanceInformation = 8;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const int ProcessorPerformanceEntrySize = 48;
    private const int MaxBufferSize = 64 * 1024 * 1024;

    // SYSTEM_PROCESS_INFORMATION: одинаковые смещения для x86 и x64 до ImageName включительно.
    private const int NextEntryOffsetField = 0;
    private const int CreateTimeField = 32;
    private const int UserTimeField = 40;
    private const int KernelTimeField = 48;
    private const int ImageNameField = 56;

    private readonly object _sync = new();
    private readonly WindowsGpuUsageReader _gpu = new();
    private IntPtr _buffer;
    private int _bufferSize = 512 * 1024;
    private bool _disposed;

    public ActivitySnapshot Capture()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var clock = Stopwatch.GetElapsedTime(0);
            var processes = QueryProcesses();
            var gpu = _gpu.Read();
            if (gpu is not null)
            {
                for (var i = 0; i < processes.Count; i++)
                {
                    var p = processes[i];
                    processes[i] = p with { GpuPercent = gpu.GetValueOrDefault(p.Pid, 0) };
                }
            }

            var system = QuerySystemTimes(out var processors);
            return new ActivitySnapshot(clock, DateTimeOffset.UtcNow, processes, processors > 0 ? processors : Environment.ProcessorCount, system);
        }
    }

    private List<ProcessActivitySample> QueryProcesses()
    {
        while (true)
        {
            if (_buffer == IntPtr.Zero)
            {
                _buffer = Marshal.AllocHGlobal(_bufferSize);
            }

            var status = NativeMethods.NtQuerySystemInformation(SystemProcessInformation, _buffer, _bufferSize, out var needed);
            if (status == StatusInfoLengthMismatch)
            {
                // Процессы появляются между вызовами — берём с запасом.
                var next = Math.Max(_bufferSize * 2, needed + (needed / 4));
                if (next > MaxBufferSize)
                {
                    throw new InvalidOperationException("Список процессов не помещается в 64 МБ.");
                }

                Marshal.FreeHGlobal(_buffer);
                _buffer = IntPtr.Zero;
                _bufferSize = next;
                continue;
            }

            if (status < 0)
            {
                throw new Win32Exception(NativeMethods.RtlNtStatusToDosError(status), $"NtQuerySystemInformation вернул 0x{status:X8}.");
            }

            return Parse(_buffer, needed > 0 ? Math.Min(needed, _bufferSize) : _bufferSize);
        }
    }

    private static List<ProcessActivitySample> Parse(IntPtr buffer, int length)
    {
        // Смещения после UNICODE_STRING зависят от разрядности: BasePriority, затем UniqueProcessId и родитель (HANDLE).
        var unicodeStringSize = IntPtr.Size == 8 ? 16 : 8;
        var basePriorityField = ImageNameField + unicodeStringSize;
        var pidField = basePriorityField + IntPtr.Size;
        var parentField = pidField + IntPtr.Size;

        var result = new List<ProcessActivitySample>(512);
        var offset = 0;
        while (offset + parentField + IntPtr.Size <= length)
        {
            var entry = buffer + offset;
            var pid = (int)Marshal.ReadIntPtr(entry, pidField);
            var parent = (int)Marshal.ReadIntPtr(entry, parentField);
            var create = Marshal.ReadInt64(entry, CreateTimeField);
            var cpu = Marshal.ReadInt64(entry, UserTimeField) + Marshal.ReadInt64(entry, KernelTimeField);
            var nameLength = (ushort)Marshal.ReadInt16(entry, ImageNameField);
            var namePointer = Marshal.ReadIntPtr(entry, ImageNameField + (IntPtr.Size == 8 ? 8 : 4));
            var name = pid == 0
                ? "System Idle Process"
                : namePointer == IntPtr.Zero || nameLength == 0 ? "System" : Marshal.PtrToStringUni(namePointer, nameLength / 2);
            result.Add(new ProcessActivitySample(pid, parent, name, create, cpu));

            var next = Marshal.ReadInt32(entry, NextEntryOffsetField);
            if (next <= 0)
            {
                break;
            }

            offset += next;
        }

        return result;
    }

    private static SystemCpuTimes? QuerySystemTimes(out int processors)
    {
        processors = 0;
        // До 64 логических процессоров в группе; ProcessorCount может быть занижен ограничением сходства процесса.
        var count = Math.Max(64, Environment.ProcessorCount);
        var size = count * ProcessorPerformanceEntrySize;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var status = NativeMethods.NtQuerySystemInformation(SystemProcessorPerformanceInformation, buffer, size, out var written);
            if (status < 0 || written < ProcessorPerformanceEntrySize)
            {
                return null;
            }

            processors = written / ProcessorPerformanceEntrySize;
            long busy = 0, dpc = 0, interrupt = 0;
            for (var i = 0; i < processors; i++)
            {
                var entry = buffer + (i * ProcessorPerformanceEntrySize);
                var idle = Marshal.ReadInt64(entry, 0);
                var kernel = Marshal.ReadInt64(entry, 8); // включает время простоя
                var user = Marshal.ReadInt64(entry, 16);
                busy += kernel - idle + user;
                dpc += Marshal.ReadInt64(entry, 24);
                interrupt += Marshal.ReadInt64(entry, 32);
            }

            return new SystemCpuTimes(busy, dpc, interrupt);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Причина, по которой нагрузка видеокарты недоступна (<c>null</c> — замеряется).</summary>
    public string? GpuUnavailable => _gpu.Unavailable;

    public void Dispose()
    {
        lock (_sync)
        {
            _gpu.Dispose();
            if (_buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_buffer);
                _buffer = IntPtr.Zero;
            }

            _disposed = true;
        }
    }

    private static class NativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(int systemInformationClass, IntPtr systemInformation, int systemInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int RtlNtStatusToDosError(int status);
    }
}
