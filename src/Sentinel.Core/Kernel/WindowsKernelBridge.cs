using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core.Kernel;

/// <summary>
/// Связь с <c>SentinelDrv.sys</c> через <c>\\.\SentinelDrv</c>: <c>CreateFile</c> (<see cref="SafeFileHandle"/>) и
/// <c>DeviceIoControl</c> (METHOD_BUFFERED). Отсутствие драйвера (<c>ERROR_FILE_NOT_FOUND</c>/<c>ERROR_PATH_NOT_FOUND</c>),
/// отказ в доступе (<c>ERROR_ACCESS_DENIED</c>) или другая версия протокола — профиль User-Mode через
/// <see cref="NullKernelBridge"/>, без исключений. Если драйвер остановили во время работы, мост переходит в профиль
/// User-Mode сам (Fail-Open).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsKernelBridge : IKernelBridge
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint FILE_SHARE_WRITE = 0x2;
    private const uint OPEN_EXISTING = 3;

    private const int ERROR_FILE_NOT_FOUND = 2;
    private const int ERROR_PATH_NOT_FOUND = 3;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_PRIVILEGE_NOT_HELD = 1314;

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_STOPPED = 1;
    private const uint SERVICE_STOP_PENDING = 3;

    private readonly object _sync = new();
    private readonly IReadOnlyDictionary<string, string> _devices;
    private SafeFileHandle? _handle;
    private string? _lostReason;

    private WindowsKernelBridge(SafeFileHandle handle)
    {
        _handle = handle;
        _devices = DosDeviceMap();
    }

    public bool IsConnected
    {
        get
        {
            lock (_sync)
            {
                return _handle is { IsInvalid: false, IsClosed: false };
            }
        }
    }

    public bool CheckConnection()
    {
        if (!IsConnected)
        {
            return false;
        }

        // Пока дескриптор открыт, Windows не вызывает DriverUnload, а IOCTL продолжают выполняться — поэтому состояние
        // службы драйвера спрашиваем у SCM и отпускаем устройство, как только его начали останавливать.
        if (QueryDriverServiceState() is SERVICE_STOP_PENDING or SERVICE_STOPPED)
        {
            Disconnect($"driver service {KernelProtocol.ServiceName} is stopping");
            return false;
        }

        return IsConnected;
    }

    /// <summary>Открывает устройство драйвера; при неудаче возвращает <see cref="NullKernelBridge"/> с причиной.</summary>
    public static IKernelBridge Open()
    {
        var handle = CreateFileW(KernelProtocol.DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            return new NullKernelBridge(error switch
            {
                ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND => KernelDriverStatus.NotLoadedMessage,
                ERROR_ACCESS_DENIED => $"{KernelDriverStatus.NotLoadedMessage} (access to {KernelProtocol.DevicePath} denied: run as Administrator or LocalSystem)",
                _ => $"{KernelDriverStatus.NotLoadedMessage} (CreateFile {KernelProtocol.DevicePath}: {new Win32Exception(error).Message})",
            });
        }

        var bridge = new WindowsKernelBridge(handle);
        var status = bridge.GetStatus();
        if (!status.Loaded)
        {
            bridge.Dispose();
            return new NullKernelBridge(status.Message);
        }

        return bridge;
    }

    public KernelDriverStatus GetStatus()
    {
        var output = new byte[KernelProtocol.StatusSize];
        if (!Invoke(KernelProtocol.IoctlGetStatus, null, output, out var returned, out var error))
        {
            return KernelDriverStatus.UserMode(error);
        }

        try
        {
            return KernelProtocol.DecodeStatus(output.AsSpan(0, returned));
        }
        catch (KernelProtocolException ex)
        {
            Disconnect(ex.Message);
            return KernelDriverStatus.UserMode($"{KernelDriverStatus.NotLoadedMessage} ({ex.Message})");
        }
    }

    public KernelOperationResult SetProtectedProcesses(IReadOnlyCollection<int> processIds)
    {
        ArgumentNullException.ThrowIfNull(processIds);
        var input = KernelProtocol.EncodeProtectedPids(processIds);
        return Invoke(KernelProtocol.IoctlSetProtectedPids, input, null, out _, out var error)
            ? KernelOperationResult.Ok($"Драйверу передано защищаемых PID: {processIds.Count}.")
            : KernelOperationResult.Fail(error);
    }

    public IReadOnlyList<KernelProcessEvent> ReadEvents(int maxEvents = KernelProtocol.DefaultReadBatch)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEvents, 1);
        var output = new byte[KernelProtocol.EventBatchHeaderSize + (Math.Min(maxEvents, 256) * KernelProtocol.ProcessEventSize)];
        if (!Invoke(KernelProtocol.IoctlReadEvents, null, output, out var returned, out _))
        {
            return [];
        }

        try
        {
            return KernelProtocol.DecodeEvents(output.AsSpan(0, returned), out _)
                .Select(e => e with { ImagePath = NtPath.ToWin32(e.ImagePath, _devices) })
                .ToArray();
        }
        catch (KernelProtocolException ex)
        {
            Disconnect(ex.Message);
            return [];
        }
    }

    public void Dispose() => Disconnect(null);

    private bool Invoke(uint code, byte[]? input, byte[]? output, out int returned, out string error)
    {
        returned = 0;
        SafeFileHandle? handle;
        lock (_sync)
        {
            handle = _handle;
        }

        if (handle is null || handle.IsClosed || handle.IsInvalid)
        {
            error = $"{KernelDriverStatus.NotLoadedMessage} ({_lostReason ?? "connection closed"})";
            return false;
        }

        var ok = DeviceIoControl(handle, code, input, input?.Length ?? 0, output, output?.Length ?? 0, out returned, IntPtr.Zero);
        if (ok)
        {
            error = string.Empty;
            return true;
        }

        var code32 = Marshal.GetLastPInvokeError();
        var message = new Win32Exception(code32).Message;
        if (KernelProtocol.IsDriverGoneError(code32))
        {
            // Драйвер остановлен или выгружен — Fail-Open: дальше работаем в профиле User-Mode.
            Disconnect($"driver connection lost: {message}");
            error = $"{KernelDriverStatus.NotLoadedMessage} (driver connection lost: {message})";
            return false;
        }

        error = code32 == ERROR_PRIVILEGE_NOT_HELD
            ? "Драйвер принимает список защищаемых PID только от LocalSystem (службы Sentinel)."
            : $"DeviceIoControl 0x{code:X8}: {message}";
        return false;
    }

    private void Disconnect(string? reason)
    {
        SafeFileHandle? handle;
        lock (_sync)
        {
            handle = _handle;
            _handle = null;
            _lostReason ??= reason;
        }

        handle?.Dispose();
    }

    /// <summary>Состояние службы ядра SentinelDrv по данным SCM; <c>null</c> — служба не найдена или SCM недоступен.</summary>
    private static uint? QueryDriverServiceState()
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var service = OpenServiceW(scm, KernelProtocol.ServiceName, SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                return QueryServiceStatus(service, out var status) ? status.dwCurrentState : null;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    /// <summary>Карта «\Device\HarddiskVolumeN» → «C:» для путей образов из ядра.</summary>
    private static Dictionary<string, string> DosDeviceMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var buffer = new char[1024];
        foreach (var drive in DriveInfo.GetDrives())
        {
            var letter = drive.Name.TrimEnd('\\');
            if (QueryDosDeviceW(letter, buffer, buffer.Length) > 0)
            {
                var target = new string(buffer, 0, Array.IndexOf(buffer, '\0') is var end and >= 0 ? end : buffer.Length);
                if (target.Length > 0)
                {
                    map.TryAdd(target, letter);
                }
            }
        }

        return map;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode, byte[]? lpInBuffer, int nInBufferSize,
        byte[]? lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, IntPtr lpOverlapped);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int QueryDosDeviceW(string lpDeviceName, [Out] char[] lpTargetPath, int ucchMax);
}
