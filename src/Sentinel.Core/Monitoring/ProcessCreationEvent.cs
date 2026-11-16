namespace Sentinel.Core.Monitoring;

/// <summary>
/// Событие старта процесса. Поля, которые источник не смог получить (процесс уже завершился, нет доступа),
/// — пустые строки, а не <c>null</c>: формат один для WMI, опроса и будущего драйвера (<c>IKernelBridge</c>).
/// </summary>
/// <param name="ProcessId">Идентификатор нового процесса.</param>
/// <param name="ParentProcessId">Идентификатор родителя (0 — неизвестен).</param>
/// <param name="ProcessName">Имя образа, например <c>powershell.exe</c>.</param>
/// <param name="ExecutablePath">Полный путь к образу (<c>QueryFullProcessImageName</c>) или пусто.</param>
/// <param name="CommandLine">Командная строка или пусто.</param>
/// <param name="TimestampUtc">
/// Время создания процесса. Windows-источник берёт его из <c>GetProcessTimes</c>, чтобы ключ находки совпадал
/// с периодическим аудитом процессов (диспетчер не создаёт дубль).
/// </param>
public sealed record ProcessCreationEvent(
    int ProcessId,
    int ParentProcessId,
    string ProcessName,
    string ExecutablePath,
    string CommandLine,
    DateTimeOffset TimestampUtc);

/// <summary>
/// Источник событий старта процессов: WMI (<c>Win32_ProcessStartTrace</c>), дельта-опрос списка процессов
/// или (в будущем) драйвер ядра. Логика реакции (<see cref="ProcessStartMonitor"/>) от источника не зависит
/// и тестируется на Linux с подставным источником.
/// </summary>
public interface IProcessCreationEventSource : IAsyncDisposable
{
    /// <summary>Активный режим источника для журнала и интерфейса: <c>wmi-trace</c>, <c>wmi-instance</c>, <c>polling</c>…</summary>
    string Mode { get; }

    /// <summary>Поток событий до отмены. Повторный вызов после завершения перечисления не поддерживается.</summary>
    IAsyncEnumerable<ProcessCreationEvent> ReadEventsAsync(CancellationToken cancellationToken);
}

/// <summary>Минимальная идентичность процесса для дельта-опроса (без открытия дескрипторов).</summary>
public readonly record struct ProcessIdentity(int Pid, int ParentPid, string Name);

/// <summary>Источник событий старта процессов для текущей ОС.</summary>
public static class ProcessCreationEventSourceFactory
{
    public static bool IsSupported => OperatingSystem.IsWindows();

    /// <summary>WMI-источник с резервным опросом (только Windows).</summary>
    public static IProcessCreationEventSource CreateDefault() => OperatingSystem.IsWindows()
        ? new WindowsProcessCreationEventSource()
        : throw new PlatformNotSupportedException("Мониторинг старта процессов реализован только для Windows.");
}
