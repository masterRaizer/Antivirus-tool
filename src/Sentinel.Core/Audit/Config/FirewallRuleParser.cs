namespace Sentinel.Core.Audit.Config;

/// <summary>
/// Разобранное правило брандмауэра Windows (из значения реестра FirewallRules).
/// Формат — поля вида <c>Key=Value</c>, разделённые '|'.
/// </summary>
public sealed record FirewallRule
{
    public required string Name { get; init; }
    public bool Allow { get; init; }
    public bool Enabled { get; init; }
    public string? Direction { get; init; }
    public string? AppPath { get; init; }
    public string? Protocol { get; init; }
    public string? LocalPort { get; init; }
    public string? RemoteAddress { get; init; }
    public string? DisplayName { get; init; }

    public bool IsInbound => string.Equals(Direction, "In", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Разбор строкового представления правила брандмауэра. Платформонезависим и тестируется на Linux.
/// </summary>
public static class FirewallRuleParser
{
    public static FirewallRule Parse(string valueName, string? ruleString)
    {
        ArgumentNullException.ThrowIfNull(valueName);
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(ruleString))
        {
            foreach (var part in ruleString.Split('|', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = part.IndexOf('=', StringComparison.Ordinal);
                if (eq <= 0)
                {
                    continue;
                }

                var key = part[..eq].Trim();
                var value = part[(eq + 1)..].Trim();
                fields[key] = value;
            }
        }

        return new FirewallRule
        {
            Name = valueName,
            Allow = fields.TryGetValue("Action", out var action) && string.Equals(action, "Allow", StringComparison.OrdinalIgnoreCase),
            Enabled = !fields.TryGetValue("Active", out var active) || string.Equals(active, "TRUE", StringComparison.OrdinalIgnoreCase),
            Direction = fields.GetValueOrDefault("Dir"),
            AppPath = fields.GetValueOrDefault("App"),
            Protocol = fields.GetValueOrDefault("Protocol"),
            LocalPort = fields.GetValueOrDefault("LPort"),
            RemoteAddress = fields.GetValueOrDefault("RA4") ?? fields.GetValueOrDefault("RA6"),
            DisplayName = fields.GetValueOrDefault("Name"),
        };
    }
}
