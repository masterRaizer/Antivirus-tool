using Sentinel.Core.Monitoring;

namespace Sentinel.Core.Kernel;

/// <summary>Состояние связи с драйвером ядра.</summary>
/// <param name="Loaded">Драйвер загружен и ответил по протоколу.</param>
/// <param name="Mode"><see cref="KernelMode"/> или <see cref="UserModeProfile"/>.</param>
/// <param name="Message">Сообщение для журнала и <c>sentinel kernel-status</c>.</param>
public sealed record KernelDriverStatus(bool Loaded, string Mode, string Message)
{
    public const string KernelMode = "kernel";
    public const string UserModeProfile = "user-mode";

    /// <summary>Штатное сообщение, когда драйвер не установлен или не запущен.</summary>
    public const string NotLoadedMessage = "Kernel driver not loaded, running in User-Mode EDR profile";

    public uint ProtocolVersion { get; init; }

    public Version? DriverVersion { get; init; }

    /// <summary>Защита дескрипторов (<c>ObRegisterCallbacks</c>) зарегистрирована.</summary>
    public bool ObCallbacksActive { get; init; }

    /// <summary>Телеметрия старта процессов (<c>PsSetCreateProcessNotifyRoutineEx</c>) зарегистрирована.</summary>
    public bool ProcessNotifyActive { get; init; }

    public int ProtectedPidCount { get; init; }

    public ulong ProcessEventsTotal { get; init; }

    public ulong EventsDropped { get; init; }

    /// <summary>Сколько раз драйвер снял опасные права у посторонних дескрипторов на защищаемые процессы.</summary>
    public ulong HandleStripsTotal { get; init; }

    public int EventsQueued { get; init; }

    public static KernelDriverStatus UserMode(string? reason = null) =>
        new(false, UserModeProfile, string.IsNullOrWhiteSpace(reason) ? NotLoadedMessage : reason);
}

public enum KernelProcessEventKind
{
    Create,
    Exit,
}

/// <summary>Событие процесса из кольцевого буфера драйвера.</summary>
public sealed record KernelProcessEvent(
    KernelProcessEventKind Kind,
    int ProcessId,
    int ParentProcessId,
    DateTimeOffset TimestampUtc,
    string ImagePath,
    string CommandLine)
{
    public uint Flags { get; init; }

    /// <summary>Завершившийся процесс был в списке защищаемых (драйвер исключил его PID из списка).</summary>
    public bool WasProtected => (Flags & KernelProtocol.EventFlagWasProtected) != 0;

    /// <summary>Событие старта в формате общего конвейера <see cref="ProcessStartMonitor"/>.</summary>
    public ProcessCreationEvent ToCreationEvent(Func<string, string>? normalizePath = null)
    {
        var path = (normalizePath ?? NtPath.ToWin32)(ImagePath);
        var name = path.Length == 0 ? string.Empty : path[(path.Replace('/', '\\').LastIndexOf('\\') + 1)..];
        return new ProcessCreationEvent(ProcessId, ParentProcessId, name, path, CommandLine, TimestampUtc);
    }
}

public sealed record KernelOperationResult(bool Success, string Message)
{
    public static KernelOperationResult Ok(string message) => new(true, message);

    public static KernelOperationResult Fail(string message) => new(false, message);
}

/// <summary>
/// Мост к драйверу ядра <c>SentinelDrv.sys</c>. Реализации не бросают исключений при отсутствии или потере драйвера:
/// политика Fail-Open — служба продолжает работать в профиле User-Mode EDR (<see cref="NullKernelBridge"/>).
/// </summary>
public interface IKernelBridge : IDisposable
{
    /// <summary>Драйвер доступен (устройство открыто и протокол совпал).</summary>
    bool IsConnected { get; }

    /// <summary>
    /// Проверка живости: если драйвер останавливают (<c>sc stop SentinelDrv</c>) или он выгружен, мост сразу закрывает
    /// дескриптор устройства — иначе открытый дескриптор держит драйвер в <c>STOP_PENDING</c> — и возвращает <c>false</c>.
    /// </summary>
    bool CheckConnection();

    KernelDriverStatus GetStatus();

    /// <summary>Заменяет список защищаемых PID (не более <see cref="KernelProtocol.MaxProtectedPids"/>).</summary>
    KernelOperationResult SetProtectedProcesses(IReadOnlyCollection<int> processIds);

    /// <summary>Забирает до <paramref name="maxEvents"/> событий из кольцевого буфера драйвера.</summary>
    IReadOnlyList<KernelProcessEvent> ReadEvents(int maxEvents = KernelProtocol.DefaultReadBatch);
}

/// <summary>Профиль User-Mode EDR: драйвера нет (Linux, Windows без установленного или запущенного SentinelDrv).</summary>
public sealed class NullKernelBridge(string? reason = null) : IKernelBridge
{
    private readonly KernelDriverStatus _status = KernelDriverStatus.UserMode(reason);

    public bool IsConnected => false;

    public bool CheckConnection() => false;

    public KernelDriverStatus GetStatus() => _status;

    public KernelOperationResult SetProtectedProcesses(IReadOnlyCollection<int> processIds) =>
        KernelOperationResult.Fail($"{_status.Message}: защита дескрипторов ядром недоступна.");

    public IReadOnlyList<KernelProcessEvent> ReadEvents(int maxEvents = KernelProtocol.DefaultReadBatch) => [];

    public void Dispose()
    {
    }
}

/// <summary>Мост для текущей ОС: на Windows — попытка открыть <c>\\.\SentinelDrv</c>, иначе профиль User-Mode.</summary>
public static class KernelBridgeFactory
{
    public static IKernelBridge CreateDefault() => OperatingSystem.IsWindows()
        ? WindowsKernelBridge.Open()
        : new NullKernelBridge($"{KernelDriverStatus.NotLoadedMessage} (kernel driver is Windows-only)");
}

/// <summary>
/// Пути ядра → пути Win32. Ядро (<c>PS_CREATE_NOTIFY_INFO.ImageFileName</c>, <c>SeLocateProcessImageName</c>) отдаёт
/// <c>\SystemRoot\System32\conhost.exe</c>, <c>\??\C:\…</c> или <c>\Device\HarddiskVolumeN\…</c>; аудит процессов сравнивает
/// пути со штатными каталогами (<c>C:\Windows\System32</c>), поэтому без нормализации легитимные системные процессы выглядели бы
/// как маскировка (<c>PROC-IMPERSONATION</c>).
/// </summary>
public static class NtPath
{
    private static readonly string[] UncPrefixes = [@"\??\UNC\", @"\\?\UNC\"];
    private static readonly string[] DosPrefixes = [@"\??\", @"\\?\", @"\\.\", @"\DosDevices\", @"\GLOBAL??\"];

    /// <summary>Каталог Windows для <c>\SystemRoot\</c>: текущей ОС, вне Windows — <c>C:\Windows</c>.</summary>
    public static string DefaultWindowsDirectory
    {
        get
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return string.IsNullOrEmpty(windows) ? @"C:\Windows" : windows.TrimEnd('\\', '/');
        }
    }

    /// <summary>Путь в форме ядра или Win32 → путь Win32; уже нормальный путь возвращается как есть.</summary>
    public static string ToWin32(string? path) => ToWin32(path, null);

    /// <param name="devices">Карта «\Device\HarddiskVolume3» → «C:» (из <c>QueryDosDevice</c>); <c>null</c> — без замены устройств.</param>
    /// <param name="windowsDirectory">Подстановка для <c>\SystemRoot\</c>; по умолчанию <see cref="DefaultWindowsDirectory"/>.</param>
    public static string ToWin32(string? path, IReadOnlyDictionary<string, string>? devices, string? windowsDirectory = null)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        const string systemRoot = @"\SystemRoot\";
        if (path.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
        {
            return (windowsDirectory ?? DefaultWindowsDirectory).TrimEnd('\\', '/') + @"\" + path[systemRoot.Length..];
        }

        foreach (var prefix in UncPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return @"\\" + path[prefix.Length..];
            }
        }

        foreach (var prefix in DosPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && path.Length > prefix.Length + 1 && path[prefix.Length + 1] == ':')
            {
                return path[prefix.Length..];
            }
        }

        if (devices is not null && path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var (device, drive) in devices)
            {
                if (path.StartsWith(device + @"\", StringComparison.OrdinalIgnoreCase))
                {
                    return drive + path[device.Length..];
                }
            }
        }

        return path;
    }

    /// <summary>Путь уже в форме Win32 (<c>C:\…</c> или UNC <c>\\server\share</c>), а не в форме ядра.</summary>
    public static bool IsWin32(string? path) =>
        !string.IsNullOrEmpty(path)
        && ((path.Length > 2 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] is '\\' or '/')
            || (path.StartsWith(@"\\", StringComparison.Ordinal) && !path.StartsWith(@"\\?\", StringComparison.Ordinal)
                && !path.StartsWith(@"\\.\", StringComparison.Ordinal)));
}
