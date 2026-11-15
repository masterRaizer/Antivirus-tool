using Sentinel.Core.Signatures;

namespace Sentinel.Core.Realtime;

public enum ThreatKind
{
    File,
    Process,
    Persistence,
    DefenderExclusion,
}

public enum ThreatStatus
{
    /// <summary>Зафиксировано без действий (низкая критичность).</summary>
    Detected,

    /// <summary>Спорный объект: ожидается решение пользователя (изолировать или добавить в исключения).</summary>
    PendingDecision,
    Quarantined,
    Terminated,
    Cleaned,

    /// <summary>Пользователь добавил объект в разрешённые исключения.</summary>
    Allowed,

    /// <summary>Действие запрещено системным белым списком.</summary>
    Blocked,
    Skipped,
    Failed,
}

/// <summary>Решение пользователя по спорной находке.</summary>
public enum ThreatDecision
{
    /// <summary>Нейтрализовать: изолировать файл, завершить процесс, откатить параметр.</summary>
    Quarantine,

    /// <summary>Добавить в разрешённые исключения (<c>allowed_exclusions.json</c>).</summary>
    Allow,
}

/// <summary>
/// Событие защиты: одна находка с итогом реакции. Плоская неизменяемая запись — передаётся
/// по IPC как есть и отображается карточкой в разделе «Угрозы и события».
/// </summary>
public sealed record ThreatEvent
{
    public required string Id { get; init; }
    public ThreatKind Kind { get; init; }
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? Sha256 { get; init; }
    public double? Entropy { get; init; }
    public string SignatureStatus { get; init; } = "не проверялась";

    /// <summary>Точная причина срабатывания: правила, эвристики, коды находок.</summary>
    public required string Reason { get; init; }

    public string Description { get; init; } = string.Empty;
    public Severity Severity { get; init; }
    public DateTime DetectedAtUtc { get; init; }

    /// <summary>Источник: <c>realtime</c>, <c>scan</c>, <c>audit</c>.</summary>
    public string Source { get; init; } = "realtime";

    public ThreatStatus Status { get; init; }
    public string? ActionMessage { get; init; }
    public int? ProcessId { get; init; }
    public string? QuarantineId { get; init; }

    /// <summary>Можно ли ещё принять решение по находке.</summary>
    public bool IsActionable => Status is ThreatStatus.PendingDecision or ThreatStatus.Detected or ThreatStatus.Failed;
}

public sealed class DispatcherOptions
{
    /// <summary>«Опасное сразу»: находки не ниже этого уровня нейтрализуются автоматически.</summary>
    public Severity AutoThreshold { get; init; } = Severity.High;

    /// <summary>«Спорное спросить»: находки не ниже этого уровня (и ниже автоматического) ждут решения пользователя.</summary>
    public Severity AskThreshold { get; init; } = Severity.Medium;

    /// <summary>Сколько событий хранится в журнале (самые старые закрытые вытесняются).</summary>
    public int MaxHistory { get; init; } = 2000;
}
