using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit.Config;

/// <summary>Область проверки целостности конфигурации безопасности.</summary>
public enum ConfigArea
{
    DefenderExclusion,
    FirewallRule,
    RootCertificate,
    SystemProxy,
}

/// <summary>Находка аудита конфигурации с указанием области.</summary>
public sealed record ConfigFinding(ConfigArea Area, AuditFinding Finding)
{
    public Severity Severity => Finding.Severity;
}

/// <summary>Итог аудита целостности конфигурации безопасности.</summary>
public sealed record ConfigAuditReport(IReadOnlyList<ConfigFinding> Findings)
{
    public int Count => Findings.Count;

    public IEnumerable<ConfigFinding> ByArea(ConfigArea area) => Findings.Where(f => f.Area == area);

    public int CountOf(ConfigArea area) => Findings.Count(f => f.Area == area);
}
