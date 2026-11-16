using Sentinel.Core.Protection;

namespace Sentinel.Core.Remediation;

/// <summary>Итог приостановки или возобновления потоков процесса (или дерева процессов).</summary>
/// <param name="Success">Хотя бы один поток приостановлен (возобновлён) и операция не запрещена самозащитой.</param>
/// <param name="ProcessId">Процесс (корень дерева), к которому относится операция.</param>
/// <param name="SuspendedThreadCount">Сколько потоков приостановлено (для возобновления — возобновлено).</param>
/// <param name="FailedThreadCount">Потоки, которые не удалось открыть или приостановить (например, <c>ERROR_ACCESS_DENIED</c>).</param>
/// <param name="AffectedProcessIds">Процессы, у которых приостановлен хотя бы один поток.</param>
/// <param name="SkippedBySelfDefense">Отказ барьера самозащиты: дескрипторы не открывались.</param>
/// <param name="FailureReason">Причина отказа или частичного выполнения.</param>
public sealed record ContainmentResult(
    bool Success,
    int ProcessId,
    int SuspendedThreadCount,
    int FailedThreadCount,
    IReadOnlyList<int> AffectedProcessIds,
    bool SkippedBySelfDefense,
    string? FailureReason)
{
    public static ContainmentResult SelfDefense(int processId, string reason) => new(false, processId, 0, 0, [], true, reason);

    public static ContainmentResult Failed(int processId, string reason, int failedThreads = 0) =>
        new(false, processId, 0, failedThreads, [], false, reason);
}

/// <summary>
/// Изоляция потоков подтверждённой угрозы перед завершением и карантином: приостановка не даёт сторожевым потокам
/// (watchdog) перезапустить процесс или удерживать образ, пока дерево завершается. Каждая реализация первым шагом
/// вызывает <see cref="ContainmentBarrier"/> — системные процессы и Sentinel не приостанавливаются никогда.
/// </summary>
public interface IProcessContainment
{
    /// <param name="executablePath">Путь к образу: без него системное имя защищается всегда (защита от ошибочной заморозки).</param>
    ContainmentResult SuspendProcess(int processId, string? processName = null, string? executablePath = null);

    /// <summary>Возобновляет только потоки, приостановленные этой реализацией (чужие счётчики приостановки не трогаются).</summary>
    ContainmentResult ResumeProcess(int processId);

    /// <summary>Приостанавливает корень и всех потомков; защищённые потомки пропускаются.</summary>
    ContainmentResult SuspendProcessTree(int rootProcessId, string? rootProcessName = null, string? rootExecutablePath = null);
}

/// <summary>Барьер самозащиты для любой реализации <see cref="IProcessContainment"/>: проверяется до открытия дескрипторов.</summary>
public static class ContainmentBarrier
{
    /// <summary>Причина отказа (процесс защищён) или <c>null</c>, если приостановка допустима.</summary>
    public static string? Check(int processId, string? processName, string? executablePath)
    {
        if (processId <= 4)
        {
            return $"PID {processId} — ядро системы: приостановка запрещена.";
        }

        if (processId == Environment.ProcessId)
        {
            return "Собственный процесс Sentinel: приостановка запрещена.";
        }

        return CriticalProcessGuard.IsProtectedProcess(processId, processName, executablePath)
            ? $"'{processName ?? executablePath ?? processId.ToString(System.Globalization.CultureInfo.InvariantCulture)}' — "
                + "критический процесс Windows или компонент Sentinel (CriticalProcessGuard): приостановка запрещена."
            : null;
    }
}

/// <summary>Реализация по умолчанию (не Windows, тесты, драйвер недоступен): ничего не приостанавливает и не падает.</summary>
public sealed class NullProcessContainment : IProcessContainment
{
    public static NullProcessContainment Instance { get; } = new();

    private const string Unsupported = "Изоляция потоков недоступна на этой платформе.";

    public ContainmentResult SuspendProcess(int processId, string? processName = null, string? executablePath = null) =>
        ContainmentBarrier.Check(processId, processName, executablePath) is { } denied
            ? ContainmentResult.SelfDefense(processId, denied)
            : ContainmentResult.Failed(processId, Unsupported);

    public ContainmentResult ResumeProcess(int processId) => new(true, processId, 0, 0, [], false, null);

    public ContainmentResult SuspendProcessTree(int rootProcessId, string? rootProcessName = null, string? rootExecutablePath = null) =>
        SuspendProcess(rootProcessId, rootProcessName, rootExecutablePath);
}

/// <summary>
/// RAII-область приостановки: всё, что приостановлено через неё и не отмечено завершённым, возобновляется в
/// <see cref="Dispose"/> — при исключении или неудачном завершении процессы не остаются «замороженными».
/// </summary>
public sealed class ProcessSuspensionScope : IDisposable
{
    private readonly IProcessContainment _containment;
    private readonly List<int> _suspended = [];
    private readonly HashSet<int> _terminated = [];
    private readonly List<int> _resumed = [];
    private bool _disposed;

    public ProcessSuspensionScope(IProcessContainment containment)
    {
        ArgumentNullException.ThrowIfNull(containment);
        _containment = containment;
    }

    public int SuspendedThreadCount { get; private set; }

    public int FailedThreadCount { get; private set; }

    public IReadOnlyList<int> SuspendedProcessIds => _suspended;

    /// <summary>Процессы, возобновлённые при закрытии области (не были завершены).</summary>
    public IReadOnlyList<int> ResumedProcessIds => _resumed;

    public ContainmentResult Suspend(int processId, string? processName = null, string? executablePath = null) =>
        Track(_containment.SuspendProcess(processId, processName, executablePath));

    public ContainmentResult SuspendTree(int rootProcessId, string? rootProcessName = null, string? rootExecutablePath = null) =>
        Track(_containment.SuspendProcessTree(rootProcessId, rootProcessName, rootExecutablePath));

    /// <summary>Процесс завершён — возобновлять его не нужно.</summary>
    public void MarkTerminated(int processId) => _terminated.Add(processId);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var pid in _suspended.Where(p => !_terminated.Contains(p)))
        {
            _containment.ResumeProcess(pid);
            _resumed.Add(pid);
        }
    }

    private ContainmentResult Track(ContainmentResult result)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SuspendedThreadCount += result.SuspendedThreadCount;
        FailedThreadCount += result.FailedThreadCount;
        foreach (var pid in result.AffectedProcessIds)
        {
            if (!_suspended.Contains(pid))
            {
                _suspended.Add(pid);
            }
        }

        return result;
    }
}
