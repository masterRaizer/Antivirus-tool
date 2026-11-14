using System.Globalization;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit;

/// <summary>Область, к которой относится находка аудита.</summary>
public enum AuditArea
{
    Process,
    Persistence,
    Config,
}

/// <summary>
/// Одна находка аудита: устойчивый код, серьёзность (переиспользуется шкала <see cref="Severity"/>
/// из сигнатурного движка), заголовок, описание и упорядоченный список доказательств (пары ключ/значение).
/// Находки неизменяемы и детерминированы — пригодны для JSON-вывода и сравнения в тестах.
/// </summary>
public sealed record AuditFinding(
    string Id,
    Severity Severity,
    string Title,
    string Description,
    IReadOnlyList<Evidence> Evidence)
{
    public static AuditFinding Create(string id, Severity severity, string title, string description, params Evidence[] evidence) =>
        new(id, severity, title, description, evidence);
}

/// <summary>Пара «поле — значение» как доказательство находки (например, «путь» → «C:\Temp\x.exe»).</summary>
public sealed record Evidence(string Key, string Value)
{
    public static Evidence Of(string key, string? value) => new(key, value ?? "<null>");

    public static Evidence Of(string key, int value) => new(key, value.ToString(CultureInfo.InvariantCulture));
}
