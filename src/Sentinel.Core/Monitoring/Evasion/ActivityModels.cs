namespace Sentinel.Core.Monitoring.Evasion;

/// <summary>
/// Процесс в одном замере активности: накопленное процессорное время (ядро + пользователь) в единицах 100 нс.
/// Ключ процесса — PID вместе с временем создания: повторно выданный PID не смешивается с завершившимся процессом.
/// <see cref="GpuPercent"/> — нагрузка процесса на видеокарту за последний интервал, 0–100 % (−1 — неизвестно).
/// </summary>
public sealed record ProcessActivitySample(int Pid, int ParentPid, string Name, long CreateTimeTicks, long CpuTimeTicks, double GpuPercent = -1);

/// <summary>Ресурс, нагрузку на который прятал процесс.</summary>
public enum ActivityResource
{
    /// <summary>Процессор (нагрузка в ядрах).</summary>
    Cpu,

    /// <summary>Видеокарта (нагрузка в долях: 1,0 — 100 %): GPU-майнеры.</summary>
    Gpu,
}

/// <summary>
/// Накопленные времена всех логических процессоров (100 нс): занятость (ядро − простой + пользователь), а также
/// время обработки DPC и прерываний, которое не начисляется ни одному процессу.
/// </summary>
public sealed record SystemCpuTimes(long BusyTicks, long DpcTicks, long InterruptTicks);

/// <summary>
/// Один замер: монотонное время замера (<see cref="Clock"/> — только для интервалов), время UTC для журнала,
/// процессы и, если доступно, общая загрузка процессоров.
/// </summary>
public sealed record ActivitySnapshot(
    TimeSpan Clock,
    DateTimeOffset TimestampUtc,
    IReadOnlyList<ProcessActivitySample> Processes,
    int ProcessorCount,
    SystemCpuTimes? System = null);

/// <summary>Источник замеров активности процессов (Windows — <c>NtQuerySystemInformation</c>, тесты — подставные данные).</summary>
public interface IProcessActivitySampler : IDisposable
{
    /// <summary>Снимает один замер. Не открывает дескрипторы процессов.</summary>
    ActivitySnapshot Capture();
}

/// <summary>Вид уклонения от средств мониторинга.</summary>
public enum EvasionKind
{
    /// <summary>
    /// Полный цикл: устойчивая нагрузка → открыт мониторинг → нагрузка пропала → мониторинг закрыт → нагрузка вернулась.
    /// Самый сильный признак скрытого майнера.
    /// </summary>
    HideAndResume,

    /// <summary>Нагрузка пропала сразу после открытия мониторинга и не вернулась в окне ожидания.</summary>
    HiddenWhileMonitorOpen,

    /// <summary>Процесс с устойчивой нагрузкой завершился сразу после открытия мониторинга.</summary>
    ExitOnMonitor,
}

/// <summary>Находка детектора уклонения: кто, от какого средства мониторинга и насколько резко прятался.</summary>
public sealed record MonitorEvasionFinding
{
    public required EvasionKind Kind { get; init; }

    public required int Pid { get; init; }

    public int ParentPid { get; init; }

    public required string Name { get; init; }

    /// <summary>Что прятал процесс: нагрузку на процессор или на видеокарту.</summary>
    public ActivityResource Resource { get; init; } = ActivityResource.Cpu;

    /// <summary>Время создания процесса (FILETIME, 100 нс) — вместе с PID однозначно задаёт процесс.</summary>
    public long CreateTimeTicks { get; init; }

    /// <summary>Средство мониторинга, на которое отреагировал процесс (например, <c>Taskmgr.exe</c>).</summary>
    public required string Monitor { get; init; }

    /// <summary>
    /// Средняя нагрузка до открытия мониторинга: для процессора — в ядрах (1,0 — одно ядро загружено полностью),
    /// для видеокарты — в долях (1,0 — 100 %).
    /// </summary>
    public double BaselineCores { get; init; }

    /// <summary>Коэффициент вариации нагрузки до открытия: чем меньше, тем ровнее (майнер держит постоянную нагрузку).</summary>
    public double BaselineVariation { get; init; }

    /// <summary>Средняя нагрузка, пока процесс «прятался», в тех же единицах, что и <see cref="BaselineCores"/>.</summary>
    public double QuietCores { get; init; }

    /// <summary>Через сколько после появления мониторинга пропала нагрузка (или завершился процесс).</summary>
    public TimeSpan Reaction { get; init; }

    /// <summary>Через сколько после закрытия мониторинга нагрузка вернулась (только <see cref="EvasionKind.HideAndResume"/>).</summary>
    public TimeSpan? ResumeDelay { get; init; }

    /// <summary>Сколько подтверждённых полных циклов «спрятался — вернулся» у образа с этим именем за последние сутки (с текущим).</summary>
    public int CycleCount { get; init; }

    /// <summary>Сколько раз образ с этим именем завершался при открытии мониторинга за последние сутки (с текущим).</summary>
    public int ExitCount { get; init; }

    public DateTimeOffset MonitorOpenedUtc { get; init; }

    public DateTimeOffset? MonitorClosedUtc { get; init; }

    /// <summary>Короткое описание для журнала и карточки находки.</summary>
    public string Describe()
    {
        var gpu = Resource == ActivityResource.Gpu;
        var unit = gpu ? "% видеокарты" : "% ядра";
        var baseline = $"{BaselineCores * 100:0}{unit}";
        var reaction = $"{Reaction.TotalSeconds:0.#} с";
        var text = Kind switch
        {
            EvasionKind.HideAndResume =>
                $"держал нагрузку {baseline}, через {reaction} после запуска {Monitor} снизил её до {QuietCores * 100:0}{unit}, "
                + $"а через {ResumeDelay?.TotalSeconds ?? 0:0.#} с после закрытия {Monitor} снова нагрузил {(gpu ? "видеокарту" : "процессор")}",
            EvasionKind.HiddenWhileMonitorOpen =>
                $"держал нагрузку {baseline} и через {reaction} после запуска {Monitor} снизил её до {QuietCores * 100:0}{unit}",
            _ => $"держал нагрузку {baseline} и завершился через {reaction} после запуска {Monitor}",
        };
        var history = CycleCount > 1 || ExitCount > 1
            ? $" Повторений за сутки: циклов {CycleCount}, завершений {ExitCount}."
            : string.Empty;
        return $"{Name} (PID {Pid}) {text}.{history}";
    }
}

/// <summary>
/// Процессорное время, которое тратит система, но не показывает ни один видимый процесс: признак процесса, скрытого
/// руткитом из списка процессов (такой майнер не виден ни в Диспетчере задач, ни в обычном перечислении).
/// </summary>
public sealed record HiddenCpuFinding(DateTimeOffset DetectedUtc, double HiddenCores, int ProcessorCount, TimeSpan Duration)
{
    public string Describe() =>
        $"Около {HiddenCores:0.0} из {ProcessorCount} логических процессоров заняты {Duration.TotalSeconds:0} с подряд, "
        + "но эта нагрузка не принадлежит ни одному видимому процессу (возможен процесс, скрытый руткитом).";
}

/// <summary>Итог обработки одного замера детектором.</summary>
public sealed record EvasionObservation(
    IReadOnlyList<MonitorEvasionFinding> Findings,
    HiddenCpuFinding? HiddenCpu,
    bool MonitorOpen,
    string? MonitorName)
{
    public static EvasionObservation Quiet(bool open, string? monitor) => new([], null, open, monitor);
}
