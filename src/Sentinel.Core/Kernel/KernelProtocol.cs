using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Sentinel.Core.Kernel;

/// <summary>
/// Протокол Ring 3 ↔ Ring 0 с драйвером <c>SentinelDrv.sys</c>. Значения повторяют <c>driver/SentinelDrv/SentinelDrv.h</c>
/// байт в байт (структуры упакованы по 1 байту, только типы фиксированного размера); тесты сверяют размеры и смещения.
/// </summary>
public static class KernelProtocol
{
    public const uint ProtocolVersion = 1;

    public const string DeviceName = @"\Device\SentinelDrv";
    public const string DevicePath = @"\\.\SentinelDrv";
    public const string ServiceName = "SentinelDrv";

    public const uint DeviceType = 0x8A53;
    public const uint MethodBuffered = 0;
    public const uint FileReadData = 0x0001;
    public const uint FileWriteData = 0x0002;

    /// <summary><c>CTL_CODE(SENTINEL_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA)</c>.</summary>
    public const uint IoctlGetStatus = 0x8A536000;

    /// <summary><c>CTL_CODE(SENTINEL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)</c>; только LocalSystem.</summary>
    public const uint IoctlSetProtectedPids = 0x8A53A004;

    /// <summary><c>CTL_CODE(SENTINEL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)</c>.</summary>
    public const uint IoctlReadEvents = 0x8A536008;

    public const int MaxProtectedPids = 64;
    public const int ImagePathChars = 260;
    public const int CommandLineChars = 512;

    public const int StatusSize = 48;
    public const int ProtectedPidsSize = 8 + (4 * MaxProtectedPids);
    public const int EventBatchHeaderSize = 16;
    public const int ProcessEventSize = 32 + (2 * ImagePathChars) + (2 * CommandLineChars);
    public const int ImagePathOffset = 32;
    public const int CommandLineOffset = ImagePathOffset + (2 * ImagePathChars);

    /// <summary>Сколько событий забирать за один <c>IOCTL_SENTINEL_READ_EVENTS</c>.</summary>
    public const int DefaultReadBatch = 32;

    public const uint StatusFlagObCallbacks = 0x1;
    public const uint StatusFlagProcessNotify = 0x2;

    public const uint EventProcessCreate = 1;
    public const uint EventProcessExit = 2;
    public const uint EventFlagImageTruncated = 0x1;
    public const uint EventFlagCommandTruncated = 0x2;
    public const uint EventFlagWasProtected = 0x4;

    /// <summary>
    /// Коды Win32 ответа <c>DeviceIoControl</c>, означающие остановку или выгрузку драйвера: <c>ERROR_FILE_NOT_FOUND</c> (2),
    /// <c>ERROR_INVALID_HANDLE</c> (6), <c>ERROR_NOT_READY</c> (21), <c>ERROR_GEN_FAILURE</c> (31), <c>ERROR_NO_SUCH_DEVICE</c> (433),
    /// <c>ERROR_OPERATION_ABORTED</c> (995), <c>ERROR_DEVICE_NOT_CONNECTED</c> (1167). Дескриптор при них закрывается немедленно.
    /// </summary>
    public static bool IsDriverGoneError(int win32Error) => win32Error is 2 or 6 or 21 or 31 or 433 or 995 or 1167;

    /// <summary>Макрос <c>CTL_CODE</c> из <c>winioctl.h</c>.</summary>
    public static uint CtlCode(uint deviceType, uint function, uint method, uint access) =>
        (deviceType << 16) | (access << 14) | (function << 2) | method;

    /// <summary>Буфер <c>SENTINEL_PROTECTED_PIDS</c> (264 байта): версия, число и до 64 PID.</summary>
    public static byte[] EncodeProtectedPids(IReadOnlyCollection<int> processIds)
    {
        ArgumentNullException.ThrowIfNull(processIds);
        if (processIds.Count > MaxProtectedPids)
        {
            throw new ArgumentException($"Драйвер принимает не более {MaxProtectedPids} PID.", nameof(processIds));
        }

        var buffer = new byte[ProtectedPidsSize];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(0), ProtocolVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(4), (uint)processIds.Count);
        var offset = 8;
        foreach (var pid in processIds)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(pid, nameof(processIds));
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), (uint)pid);
            offset += 4;
        }

        return buffer;
    }

    /// <summary>Разбор <c>SENTINEL_STATUS</c>. Короткий буфер или чужая версия протокола — <see cref="KernelProtocolException"/>.</summary>
    public static KernelDriverStatus DecodeStatus(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < StatusSize)
        {
            throw new KernelProtocolException($"SENTINEL_STATUS: получено {buffer.Length} байт, ожидается {StatusSize}.");
        }

        var native = MemoryMarshal.Read<StatusNative>(buffer);
        if (native.ProtocolVersion != ProtocolVersion)
        {
            throw new KernelProtocolException($"Версия протокола драйвера {native.ProtocolVersion}, служба ожидает {ProtocolVersion}.");
        }

        var version = new Version((int)(native.DriverVersion >> 16) & 0xFF, (int)(native.DriverVersion >> 8) & 0xFF, (int)native.DriverVersion & 0xFF);
        var ob = (native.Flags & StatusFlagObCallbacks) != 0;
        var notify = (native.Flags & StatusFlagProcessNotify) != 0;
        return new KernelDriverStatus(true, KernelDriverStatus.KernelMode,
            $"Kernel driver SentinelDrv {version} connected (handle protection: {(ob ? "on" : "off")}, process telemetry: {(notify ? "on" : "off")}).")
        {
            ProtocolVersion = native.ProtocolVersion,
            DriverVersion = version,
            ObCallbacksActive = ob,
            ProcessNotifyActive = notify,
            ProtectedPidCount = (int)native.ProtectedPidCount,
            ProcessEventsTotal = native.ProcessEventsTotal,
            EventsDropped = native.EventsDropped,
            HandleStripsTotal = native.HandleStripsTotal,
            EventsQueued = (int)native.EventsQueued,
        };
    }

    /// <summary>Разбор ответа <c>IOCTL_SENTINEL_READ_EVENTS</c>: заголовок <c>SENTINEL_EVENT_BATCH</c> и события.</summary>
    public static IReadOnlyList<KernelProcessEvent> DecodeEvents(ReadOnlySpan<byte> buffer, out int remaining)
    {
        if (buffer.Length < EventBatchHeaderSize)
        {
            throw new KernelProtocolException($"SENTINEL_EVENT_BATCH: получено {buffer.Length} байт, ожидается не менее {EventBatchHeaderSize}.");
        }

        var version = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        if (version != ProtocolVersion)
        {
            throw new KernelProtocolException($"Версия протокола пакета событий {version}, служба ожидает {ProtocolVersion}.");
        }

        var count = BinaryPrimitives.ReadUInt32LittleEndian(buffer[4..]);
        remaining = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(buffer[8..]), int.MaxValue);
        if (count > (uint)((buffer.Length - EventBatchHeaderSize) / ProcessEventSize))
        {
            throw new KernelProtocolException($"Пакет событий объявляет {count} событий, а в буфере {buffer.Length} байт.");
        }

        var events = new KernelProcessEvent[count];
        for (var i = 0; i < count; i++)
        {
            events[i] = DecodeEvent(buffer.Slice(EventBatchHeaderSize + (i * ProcessEventSize), ProcessEventSize));
        }

        return events;
    }

    /// <summary>Разбор одного <c>SENTINEL_PROCESS_EVENT</c> (1576 байт).</summary>
    public static KernelProcessEvent DecodeEvent(ReadOnlySpan<byte> e)
    {
        if (e.Length < ProcessEventSize)
        {
            throw new KernelProtocolException($"SENTINEL_PROCESS_EVENT: получено {e.Length} байт, ожидается {ProcessEventSize}.");
        }

        var kind = BinaryPrimitives.ReadUInt32LittleEndian(e);
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
        var fileTime = BinaryPrimitives.ReadInt64LittleEndian(e[16..]);
        var imageChars = Math.Min((int)BinaryPrimitives.ReadUInt16LittleEndian(e[24..]), ImagePathChars);
        var commandChars = Math.Min((int)BinaryPrimitives.ReadUInt16LittleEndian(e[26..]), CommandLineChars);

        return new KernelProcessEvent(
            kind == EventProcessExit ? KernelProcessEventKind.Exit : KernelProcessEventKind.Create,
            (int)BinaryPrimitives.ReadUInt32LittleEndian(e[4..]),
            (int)BinaryPrimitives.ReadUInt32LittleEndian(e[8..]),
            fileTime > 0 ? DateTimeOffset.FromFileTime(fileTime).ToUniversalTime() : DateTimeOffset.UnixEpoch,
            Encoding.Unicode.GetString(e.Slice(ImagePathOffset, imageChars * 2)),
            Encoding.Unicode.GetString(e.Slice(CommandLineOffset, commandChars * 2)))
        {
            Flags = flags,
        };
    }

    /// <summary>Раскладка <c>SENTINEL_STATUS</c> (Pack = 1, 48 байт) — для чтения ответа драйвера как есть.</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct StatusNative
    {
        public uint ProtocolVersion;
        public uint DriverVersion;
        public uint Flags;
        public uint ProtectedPidCount;
        public ulong ProcessEventsTotal;
        public ulong EventsDropped;
        public ulong HandleStripsTotal;
        public uint EventsQueued;
        public uint Reserved;
    }
}

/// <summary>Ответ драйвера не соответствует протоколу (короткий буфер, другая версия).</summary>
public sealed class KernelProtocolException : Exception
{
    public KernelProtocolException()
    {
    }

    public KernelProtocolException(string message)
        : base(message)
    {
    }

    public KernelProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
