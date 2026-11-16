namespace Sentinel.Core.Auditors.Memory;

/// <summary>Константы Win32 для описания регионов виртуальной памяти (<c>MEMORY_BASIC_INFORMATION</c>).</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores",
    Justification = "Имена совпадают с константами Win32 из winnt.h — так их проще сверять с документацией VirtualQueryEx.")]
public static class MemoryConstants
{
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_FREE = 0x10000;

    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_MAPPED = 0x40000;
    public const uint MEM_IMAGE = 0x1000000;

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;

    /// <summary>Биты защиты, разрешающие исполнение.</summary>
    public const uint ExecuteMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    /// <summary>Биты защиты «запись + исполнение» (RWX / WCX).</summary>
    public const uint WriteExecuteMask = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
}

/// <summary>Описание одного региона виртуальной памяти процесса.</summary>
/// <param name="BaseAddress">Начало региона.</param>
/// <param name="RegionSize">Размер в байтах.</param>
/// <param name="State"><c>MEM_COMMIT</c> / <c>MEM_RESERVE</c> / <c>MEM_FREE</c>.</param>
/// <param name="Type"><c>MEM_PRIVATE</c> / <c>MEM_MAPPED</c> / <c>MEM_IMAGE</c>.</param>
/// <param name="Protect">Текущая защита страниц.</param>
/// <param name="AllocationProtect">Защита, заданная при выделении.</param>
public readonly record struct MemoryRegionInfo(nint BaseAddress, long RegionSize, uint State, uint Type, uint Protect, uint AllocationProtect)
{
    public bool IsCommitted => State == MemoryConstants.MEM_COMMIT;

    public bool IsPrivate => Type == MemoryConstants.MEM_PRIVATE;

    public bool IsImage => Type == MemoryConstants.MEM_IMAGE;

    /// <summary>Страницы нельзя читать без побочных эффектов: <c>PAGE_GUARD</c> (сработает исключение в процессе) или <c>PAGE_NOACCESS</c>.</summary>
    public bool IsUnreadable => (Protect & MemoryConstants.PAGE_GUARD) != 0 || (Protect & 0xFF) == MemoryConstants.PAGE_NOACCESS || Protect == 0;

    public bool IsWriteExecute => (Protect & MemoryConstants.WriteExecuteMask) != 0;

    public bool WasAllocatedWriteExecute => (AllocationProtect & MemoryConstants.WriteExecuteMask) != 0;

    public bool IsExecutable => (Protect & MemoryConstants.ExecuteMask) != 0;
}

/// <summary>
/// Доступ к памяти чужого процесса только на чтение. Реализация для Windows — <see cref="WindowsMemoryReader"/>
/// (<c>VirtualQueryEx</c>/<c>ReadProcessMemory</c>); в тестах — синтетические регионы. Вызывать только после
/// <see cref="Protection.CriticalProcessGuard"/>: это делает <see cref="MemoryIntegrityScanner"/>.
/// </summary>
public interface IMemoryReader
{
    /// <summary>Регионы адресного пространства процесса; пусто — процесс недоступен или завершился.</summary>
    IReadOnlyList<MemoryRegionInfo> EnumerateRegions(int processId);

    /// <summary>
    /// Читает фрагмент памяти в переданный буфер (вызывающий передаёт не более 64 КБ). Возвращает число прочитанных байт,
    /// при частичном чтении (<c>ERROR_PARTIAL_COPY</c>) — прочитанную часть, при отказе — 0.
    /// </summary>
    int ReadMemory(int processId, nint address, Span<byte> buffer);

    /// <summary>
    /// Файл, отображённый в регион образа (<c>MEM_IMAGE</c>), — путь в форме ядра (<c>\Device\HarddiskVolumeN\…</c>) или <c>null</c>.
    /// Нужен, чтобы отличать штатный RWX-патч рантайма .NET (<c>clr.dll</c>/<c>coreclr.dll</c>) от патча стороннего образа.
    /// </summary>
    string? GetMappedFileName(int processId, nint address);
}
