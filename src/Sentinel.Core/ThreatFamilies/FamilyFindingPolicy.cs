using Sentinel.Core.Audit;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.ThreatFamilies;

/// <summary>
/// Поведенческие находки семейств майнеров/загрузчиков (задача-маскировка, Run на неподписанный exe, командная строка майнера,
/// бэкдор-порт и т.п.) сами по себе не запускают автоматическую нейтрализацию в службе: разрушительные действия — только после
/// подтверждения пользователя (в интерфейсе или <c>sentinel family-clean --confirm</c>). Если высокая критичность складывается из
/// независимых признаков (сигнатура/хеш файла, подмена Winlogon и т.п.), действует прежняя политика.
/// </summary>
public static class FamilyFindingPolicy
{
    private static readonly HashSet<string> BehavioralIds = new(StringComparer.Ordinal)
    {
        "PERS-TASK-DOWNLOAD-EXEC", "PERS-RUN-DOWNLOAD-EXEC", "PERS-FAMILY-IOC", "PERS-DECEPTIVE-NAME", "PERS-FAKE-MICROSOFT",
        "PERS-RUN-USERWRITABLE-UNSIGNED", "PERS-UNINSTALL-FORGED-GUID",
        MinerCommandLineAnalyzer.FindingId, "PROC-NET-IOC", "PROC-NET-POOLPORT", "PROC-BACKDOOR-LISTEN", "PROC-DROPPER-CHILD",
        "PROC-DECEPTIVE-NAME", "PROC-FAKE-MICROSOFT", "PROC-FAMILY-IOC",
    };

    /// <summary>Причина отложить решение до пользователя или <c>null</c> — действует обычная политика по критичности.</summary>
    public static string? DecisionReason(IReadOnlyList<AuditFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var severe = findings.Where(f => f.Severity >= Severity.High).ToList();
        if (severe.Count == 0 || !severe.All(f => BehavioralIds.Contains(f.Id)))
        {
            return null;
        }

        return "поведенческие признаки семейства майнеров/загрузчиков (" + string.Join(", ", severe.Select(f => f.Id).Distinct())
            + "); чистка — после подтверждения: «sentinel family-clean --confirm» или кнопка в интерфейсе";
    }
}
