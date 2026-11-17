using System.Runtime.Versioning;
using Sentinel.Core.Audit.Config;

namespace Sentinel.Core.Remediation;

/// <summary>Изменение правил брандмауэра Windows: удаление поддельных, восстановление при откате, блокировка IOC.</summary>
public interface IFirewallRuleEditor
{
    /// <summary>Удаляет правило по его идентификатору (имя значения в <c>FirewallRules</c>, оно же <c>-Name</c> в NetSecurity).</summary>
    ProviderResult RemoveRule(string ruleId);

    /// <summary>Воссоздаёт удалённое разрешающее правило по сохранённой строке реестра.</summary>
    ProviderResult RestoreRule(string ruleId, string rawValue);

    /// <summary>Добавляет правило, запрещающее исходящие соединения на указанные адреса.</summary>
    ProviderResult AddOutboundBlockRule(string ruleId, IReadOnlyList<string> remoteAddresses);
}

/// <summary>
/// Правила брандмауэра через модуль NetSecurity (<c>Remove-NetFirewallRule</c>, <c>New-NetFirewallRule</c>) штатного
/// powershell.exe из System32. Значения передаются переменными окружения, а не текстом сценария: имя правила и путь программы
/// контролирует вредонос.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewallRuleEditor : IFirewallRuleEditor
{
    private const string RemoveScript =
        "$ErrorActionPreference='Stop';Remove-NetFirewallRule -Name $env:SENTINEL_FW_ID";

    private const string RestoreScript =
        "$ErrorActionPreference='Stop';" +
        "$p=@{Name=$env:SENTINEL_FW_ID;DisplayName=$env:SENTINEL_FW_DISPLAY;Direction=$env:SENTINEL_FW_DIR;Action='Allow';Profile=($env:SENTINEL_FW_PROFILE -split ',')};" +
        "if($env:SENTINEL_FW_APP){$p.Program=$env:SENTINEL_FW_APP};" +
        "if($env:SENTINEL_FW_PROTO){$p.Protocol=$env:SENTINEL_FW_PROTO};" +
        "if($env:SENTINEL_FW_LPORT){$p.LocalPort=($env:SENTINEL_FW_LPORT -split ',')};" +
        "if($env:SENTINEL_FW_RA){$p.RemoteAddress=($env:SENTINEL_FW_RA -split ',')};" +
        "New-NetFirewallRule @p | Out-Null";

    private const string BlockScript =
        "$ErrorActionPreference='Stop';" +
        "New-NetFirewallRule -Name $env:SENTINEL_FW_ID -DisplayName $env:SENTINEL_FW_ID -Direction Outbound -Action Block -Profile Any " +
        "-RemoteAddress ($env:SENTINEL_FW_RA -split ',') | Out-Null";

    private readonly TimeSpan _timeout;

    public WindowsFirewallRuleEditor(TimeSpan? timeout = null) => _timeout = timeout ?? TimeSpan.FromSeconds(60);

    public ProviderResult RemoveRule(string ruleId) =>
        Run(RemoveScript, new Dictionary<string, string> { ["SENTINEL_FW_ID"] = ruleId });

    public ProviderResult RestoreRule(string ruleId, string rawValue)
    {
        var rule = FirewallRuleParser.Parse(ruleId, rawValue);
        var profiles = rule.AllProfiles ? "Any" : string.Join(",", rule.Profiles);
        var protocol = rule.Protocol switch
        {
            "6" => "TCP",
            "17" => "UDP",
            "1" => "ICMPv4",
            "58" => "ICMPv6",
            _ => rule.Protocol ?? string.Empty,
        };
        return Run(RestoreScript, new Dictionary<string, string>
        {
            ["SENTINEL_FW_ID"] = ruleId,
            ["SENTINEL_FW_DISPLAY"] = rule.DisplayName ?? ruleId,
            ["SENTINEL_FW_DIR"] = rule.IsInbound ? "Inbound" : "Outbound",
            ["SENTINEL_FW_PROFILE"] = profiles,
            ["SENTINEL_FW_APP"] = rule.AppPath ?? string.Empty,
            ["SENTINEL_FW_PROTO"] = protocol,
            ["SENTINEL_FW_LPORT"] = rule.LocalPort ?? string.Empty,
            ["SENTINEL_FW_RA"] = rule.RemoteAddress ?? string.Empty,
        });
    }

    public ProviderResult AddOutboundBlockRule(string ruleId, IReadOnlyList<string> remoteAddresses) =>
        Run(BlockScript, new Dictionary<string, string>
        {
            ["SENTINEL_FW_ID"] = ruleId,
            ["SENTINEL_FW_RA"] = string.Join(",", remoteAddresses),
        });

    private ProviderResult Run(string script, IReadOnlyDictionary<string, string> environment)
    {
        var powershell = SystemTool.System32Path("WindowsPowerShell", "v1.0", "powershell.exe");
        var (code, _, error) = SystemTool.Run(
            powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], _timeout, environment);
        return code == 0 ? ProviderResult.Ok : ProviderResult.Fail($"NetSecurity завершился с кодом {code}: {error}");
    }
}
