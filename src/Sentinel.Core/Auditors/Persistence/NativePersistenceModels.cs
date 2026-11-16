namespace Sentinel.Core.Auditors.Persistence;

/// <summary>Состояние службы по данным диспетчера управления службами (SCM).</summary>
public enum ServiceRunState
{
    Unknown = 0,
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7,
}

/// <summary>
/// Сырая запись службы/драйвера: конфигурация из <c>HKLM\SYSTEM\CurrentControlSet\Services</c>
/// плюс (если доступно) живое состояние из SCM. Путь <see cref="ImagePath"/> приводится к виду как в реестре,
/// без раскрытия переменных окружения; нормализация выполняется парсером.
/// </summary>
public sealed record RawServiceRecord(
    string Name,
    string? ImagePath,
    int Start,
    int Type,
    string? ObjectName)
{
    /// <summary><c>Parameters\ServiceDll</c> — DLL, загружаемая внутри группы <c>svchost.exe</c>.</summary>
    public string? ServiceDll { get; init; }

    /// <summary>Команда, выполняемая при сбое службы (recovery action <c>RunCommand</c>).</summary>
    public string? FailureCommand { get; init; }

    public ServiceRunState State { get; init; } = ServiceRunState.Unknown;

    public int? ProcessId { get; init; }

    /// <summary>Автозапуск: <c>Boot</c>(0), <c>System</c>(1), <c>Auto</c>(2).</summary>
    public bool IsAutoStart => Start is >= 0 and <= 2;

    /// <summary>Тип — драйвер ядра (1) или файловой системы (2).</summary>
    public bool IsDriver => Type is 1 or 2;
}

/// <summary>Действие задачи планировщика типа <c>Exec</c>.</summary>
public sealed record RawExecAction(string Command, string? Arguments, string? WorkingDirectory);

/// <summary>
/// Действие типа <c>ComHandler</c>: идентификатор COM-класса и (если удалось разрешить через реестр)
/// путь к его серверу (<c>InprocServer32</c> / <c>LocalServer32</c>).
/// </summary>
public sealed record RawComHandler(string ClassId, string? Data, string? ResolvedServerPath);

/// <summary>
/// Сырая запись задачи планировщика: данные XML с диска и признак присутствия в
/// <c>TaskCache\Tree</c>. Расхождения диск/реестр выявляет <see cref="ScheduledTaskReconciler"/>.
/// </summary>
public sealed record RawScheduledTaskRecord(string Name, string RegistryPath)
{
    public bool? EnabledXml { get; init; }

    public bool Hidden { get; init; }

    public string? UserId { get; init; }

    public string? RunLevel { get; init; }

    public IReadOnlyList<RawExecAction> ExecActions { get; init; } = [];

    public IReadOnlyList<RawComHandler> ComHandlers { get; init; } = [];

    /// <summary>XML-файл задачи присутствует в <c>System32\Tasks</c> (и доступен для чтения).</summary>
    public bool PresentOnDisk { get; init; }

    /// <summary>Задача зарегистрирована в <c>TaskCache\Tree</c>.</summary>
    public bool PresentInTaskCache { get; init; }

    /// <summary>Задача из штатного пространства Windows (<c>\Microsoft\Windows\</c>).</summary>
    public bool IsMicrosoftBuiltIn =>
        Name.StartsWith(@"Microsoft\Windows\", StringComparison.OrdinalIgnoreCase)
        || Name.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Сырой элемент персистентности из реестра (Run, IFEO, SafeBoot, AppInit_DLLs, Winlogon).</summary>
public sealed record RawRegistryPersistenceItem(string Area, string Location, string Name, string? Value);

/// <summary>Источник конфигурации служб (SCM + реестр на Windows, фикстуры в тестах).</summary>
public interface IServiceRegistrySource
{
    IReadOnlyList<RawServiceRecord> GetServices();
}

/// <summary>Источник задач планировщика (XML с диска + сверка с TaskCache на Windows, фикстуры в тестах).</summary>
public interface IScheduledTaskSource
{
    IReadOnlyList<RawScheduledTaskRecord> GetTasks();

    /// <summary>Имена задач, зарегистрированных в <c>TaskCache\Tree</c> (для выявления Ghost Tasks).</summary>
    IReadOnlyList<string> GetTaskCacheNames();
}
