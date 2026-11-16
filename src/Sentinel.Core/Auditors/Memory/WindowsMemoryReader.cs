using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Auditors.Memory;

/// <summary>
/// Чтение памяти процесса средствами Win32: дескриптор открывается с минимальными правами
/// <c>PROCESS_QUERY_INFORMATION | PROCESS_VM_READ</c> (0x0410) на время одного вызова и всегда закрывается в <c>finally</c>;
/// регионы — <c>VirtualQueryEx</c>, данные — <c>ReadProcessMemory</c> в переданный буфер (не более 64 КБ за вызов),
/// частичное чтение (<c>ERROR_PARTIAL_COPY</c>) возвращает прочитанную часть. Страницы <c>PAGE_GUARD</c>/<c>PAGE_NOACCESS</c>
/// не читаются: обращение к сторожевой странице изменило бы состояние стека целевого процесса.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsMemoryReader : IMemoryReader
{
    public const int MaxChunkBytes = 64 * 1024;

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const int ERROR_PARTIAL_COPY = 299;

    /// <summary>Предел числа регионов (защита от бесконечного обхода повреждённого адресного пространства).</summary>
    private const int MaxRegions = 200_000;

    public IReadOnlyList<MemoryRegionInfo> EnumerateRegions(int processId)
    {
        var handle = Open(processId);
        if (handle == IntPtr.Zero)
        {
            return [];
        }

        try
        {
            var regions = new List<MemoryRegionInfo>();
            var size = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            nint address = 0;
            while (regions.Count < MaxRegions && VirtualQueryEx(handle, address, out var mbi, size) != 0)
            {
                var regionSize = (long)(ulong)mbi.RegionSize;
                if (regionSize <= 0)
                {
                    break;
                }

                regions.Add(new MemoryRegionInfo(mbi.BaseAddress, regionSize, mbi.State, mbi.Type, mbi.Protect, mbi.AllocationProtect));
                var next = (long)mbi.BaseAddress + regionSize;
                if (next <= (long)address || next > nint.MaxValue)
                {
                    break; // конец пользовательского адресного пространства
                }

                address = (nint)next;
            }

            return regions;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    public int ReadMemory(int processId, nint address, Span<byte> buffer)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }

        if (buffer.Length > MaxChunkBytes)
        {
            buffer = buffer[..MaxChunkBytes];
        }

        var handle = Open(processId);
        if (handle == IntPtr.Zero)
        {
            return 0;
        }

        try
        {
            var ok = ReadProcessMemory(handle, address, ref MemoryMarshal.GetReference(buffer), (nuint)buffer.Length, out var read);
            if (ok)
            {
                return (int)read;
            }

            // Часть страниц региона выгружена/освобождена между VirtualQueryEx и чтением — отдаём прочитанное.
            return Marshal.GetLastPInvokeError() == ERROR_PARTIAL_COPY ? (int)read : 0;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static IntPtr Open(int processId) =>
        processId <= 4 ? IntPtr.Zero : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)processId);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nuint VirtualQueryEx(IntPtr hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, nint lpBaseAddress, ref byte lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);
}
