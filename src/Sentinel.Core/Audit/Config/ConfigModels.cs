using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit.Config;

/// <summary>Область проверки целостности конфигурации безопасности.</summary>
public enum ConfigArea
{
    DefenderExclusion,
    FirewallRule,
    RootCertificate,
    SystemProxy,

    /// <summary>Политики и настройки, отключающие встроенную защиту.</summary>
    DefenderPolicy,
}

/// <summary>Находка аудита конфигурации с указанием области.</summary>
public sealed record ConfigFinding(ConfigArea Area, AuditFinding Finding)
{
    public Severity Severity => Finding.Severity;
}

/// <summary>Итог аудита целостности конфигурации безопасности.</summary>
public sealed record ConfigAuditReport(IReadOnlyList<ConfigFinding> Findings)
{
    /// <summary>
    /// Все исключения встроенной защиты, найденные в реестре. Передаются в
    /// <see cref="ExclusionPriorityScanner"/> для приоритетной глубокой проверки файлов и процессов.
    /// </summary>
    public IReadOnlyList<DefenderExclusion> DefenderExclusions { get; init; } = [];

    /// <summary>Разрешающие правила брандмауэра, замаскированные под системные (для плейбука нейтрализации и отката).</summary>
    public IReadOnlyList<FirewallRule> MasqueradingFirewallRules { get; init; } = [];

    /// <summary>Шаги, пропущенные из-за недоступности системной службы (Безопасный режим, WinRE).</summary>
    public IReadOnlyList<SkippedAuditStep> Skipped { get; init; } = [];

    public int Count => Findings.Count;

    public IEnumerable<ConfigFinding> ByArea(ConfigArea area) => Findings.Where(f => f.Area == area);

    public int CountOf(ConfigArea area) => Findings.Count(f => f.Area == area);
}
