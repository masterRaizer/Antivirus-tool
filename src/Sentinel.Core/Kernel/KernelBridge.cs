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

/// <summary>Пути ядра (<c>\??\C:\…</c>, <c>\Device\HarddiskVolumeN\…</c>) → пути Win32 (<c>C:\…</c>).</summary>
public static class NtPath
{
    /// <summary>
    /// <c>\??\C:\x</c> и <c>\\?\C:\x</c> → <c>C:\x</c>; <c>\??\UNC\srv\share</c> → <c>\\srv\share</c>; префикс устройства
    /// заменяется по карте <paramref name="devices"/> («\Device\HarddiskVolume3» → «C:»), если она передана.
    /// </summary>
    public static string ToWin32(string path) => ToWin32(path, null);

    public static string ToWin32(string path, IReadOnlyDictionary<string, string>? devices)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        foreach (var prefix in new[] { @"\??\UNC\", @"\\?\UNC\" })
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return @"\\" + path[prefix.Length..];
            }
        }

        foreach (var prefix in new[] { @"\??\", @"\\?\", @"\\.\" })
        {
            if (path.StartsWith(prefix, StringComparison.Ordinal))
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
}
