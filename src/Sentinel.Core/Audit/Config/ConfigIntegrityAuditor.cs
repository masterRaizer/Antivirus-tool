using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit.Config;

/// <summary>
/// Аудитор целостности конфигурации безопасности: исключения встроенной защиты (Windows Defender),
/// разрешающие правила брандмауэра, нештатные корневые сертификаты и настройки системного прокси.
/// Источники инъектируются (реестр, хранилище сертификатов), поэтому логика тестируется на Linux.
/// </summary>
public sealed class ConfigIntegrityAuditor
{
    private static readonly string[] DefenderExclusionRoots =
    [
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions",
        @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
    ];

    private static readonly string[] ExclusionKinds = ["Paths", "Processes", "Extensions"];

    private const string FirewallRulesKey =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    private static readonly (RegistryHive Hive, string Key)[] ProxyKeys =
    [
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings"),
        (RegistryHive.LocalMachine, @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"),
    ];

    private static readonly string[] DangerousExtensions =
    [
        "exe", "dll", "sys", "ps1", "bat", "cmd", "vbs", "js", "scr", "com", "jar", "hta",
    ];

    private readonly ConfigIntegrityAuditorOptions _options;
    private readonly IRegistryProvider? _registry;
    private readonly ICertificateStoreProvider? _certificates;

    public ConfigIntegrityAuditor(
        ConfigIntegrityAuditorOptions? options = null,
        IRegistryProvider? registry = null,
        ICertificateStoreProvider? certificates = null)
    {
        _options = options ?? new ConfigIntegrityAuditorOptions();
        _registry = registry;
        _certificates = certificates;
    }

    public ConfigAuditReport Audit()
    {
        var findings = new List<ConfigFinding>();
        if (_registry is not null)
        {
            AuditDefenderExclusions(findings);
            AuditFirewall(findings);
            AuditProxy(findings);
        }

        if (_certificates is not null)
        {
            AuditRootCertificates(findings);
        }

        return new ConfigAuditReport(findings);
    }

    // ---- Исключения Windows Defender ------------------------------------------

    private void AuditDefenderExclusions(List<ConfigFinding> findings)
    {
        foreach (var root in DefenderExclusionRoots)
        {
            foreach (var kind in ExclusionKinds)
            {
                var key = new RegistryKeyPath(RegistryHive.LocalMachine, root + "\\" + kind);
                foreach (var value in _registry!.GetValues(key))
                {
                    var target = value.Name;
                    var (severity, note) = ClassifyExclusion(kind, target);
                    findings.Add(new ConfigFinding(ConfigArea.DefenderExclusion, AuditFinding.Create(
                        "CFG-DEFENDER-EXCL", severity,
                        $"Исключение встроенной защиты ({kind})",
                        $"Из проверки исключён {kind switch { "Paths" => "путь", "Processes" => "процесс", _ => "тип файлов" }} '{target}'. {note}",
                        Evidence.Of("kind", kind),
                        Evidence.Of("target", target),
                        Evidence.Of("key", key.ToString()))));
                }
            }
        }
    }

    private static (Severity Severity, string Note) ClassifyExclusion(string kind, string target)
    {
        if (string.Equals(kind, "Extensions", StringComparison.OrdinalIgnoreCase))
        {
            var ext = target.TrimStart('.', '*').ToLowerInvariant();
            return DangerousExtensions.Contains(ext)
                ? (Severity.High, "Исключён опасный тип исполняемых файлов — серьёзная брешь.")
                : (Severity.Medium, "Исключение по расширению ослабляет защиту.");
        }

        if (IsBroadPath(target))
        {
            return (Severity.High, "Исключён корень диска/слишком широкий путь — защита фактически отключена для области.");
        }

        if (PathClassifier.IsUserWritableLocation(target))
        {
            return (Severity.High, "Исключён каталог с правом записи пользователя — типичный приём сокрытия вредоноса.");
        }

        return (Severity.Medium, "Нештатное исключение ослабляет защиту.");
    }

    private static bool IsBroadPath(string target)
    {
        var norm = target.Replace('/', '\\').Trim().TrimEnd('\\');
        // "C:", "C:\", "\", "*" или одиночный компонент диска.
        if (norm.Length <= 3 && (norm.EndsWith(':') || norm.Contains('*', StringComparison.Ordinal) || norm.Length == 0))
        {
            return true;
        }

        return norm is "*" || norm.EndsWith(":\\*", StringComparison.Ordinal) || norm.EndsWith(':');
    }

    // ---- Правила брандмауэра ---------------------------------------------------

    private void AuditFirewall(List<ConfigFinding> findings)
    {
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, FirewallRulesKey);
        foreach (var value in _registry!.GetValues(key))
        {
            var rule = FirewallRuleParser.Parse(value.Name, value.Value);
            if (!rule.Allow || !rule.Enabled || string.IsNullOrWhiteSpace(rule.AppPath))
            {
                continue;
            }

            var appInUserWritable = PathClassifier.IsUserWritableLocation(rule.AppPath)
                && !PathClassifier.IsInTrustedDirectory(rule.AppPath, _options.TrustedBinaryDirectories);
            if (!appInUserWritable)
            {
                continue;
            }

            var severity = rule.IsInbound ? Severity.High : Severity.Medium;
            findings.Add(new ConfigFinding(ConfigArea.FirewallRule, AuditFinding.Create(
                "CFG-FW-ALLOW", severity,
                rule.IsInbound ? "Разрешающее входящее правило для подозрительного файла" : "Разрешающее исходящее правило для подозрительного файла",
                $"Правило брандмауэра '{rule.DisplayName ?? rule.Name}' разрешает {(rule.IsInbound ? "входящий" : "исходящий")} трафик для '{rule.AppPath}' из каталога с правом записи пользователя.",
                Evidence.Of("rule", rule.DisplayName ?? rule.Name),
                Evidence.Of("app", rule.AppPath),
                Evidence.Of("dir", rule.Direction),
                Evidence.Of("protocol", rule.Protocol))));
        }
    }

    // ---- Системный прокси ------------------------------------------------------

    private void AuditProxy(List<ConfigFinding> findings)
    {
        foreach (var (hive, keyPath) in ProxyKeys)
        {
            var key = new RegistryKeyPath(hive, keyPath);
            if (!_registry!.KeyExists(key))
            {
                continue;
            }

            var proxyEnable = _registry.GetValue(key, "ProxyEnable")?.Value;
            var proxyServer = _registry.GetValue(key, "ProxyServer")?.Value;
            if (string.Equals(proxyEnable, "1", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(proxyServer))
            {
                findings.Add(new ConfigFinding(ConfigArea.SystemProxy, AuditFinding.Create(
                    "CFG-PROXY-SERVER", Severity.Medium,
                    "Включён системный прокси",
                    $"Трафик направляется через прокси '{proxyServer}'. Принудительный прокси может использоваться для перехвата трафика.",
                    Evidence.Of("key", key.ToString()),
                    Evidence.Of("proxy", proxyServer))));
            }

            var autoConfig = _registry.GetValue(key, "AutoConfigURL")?.Value;
            if (!string.IsNullOrWhiteSpace(autoConfig))
            {
                var remote = autoConfig.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    || autoConfig.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
                findings.Add(new ConfigFinding(ConfigArea.SystemProxy, AuditFinding.Create(
                    "CFG-PROXY-PAC", remote ? Severity.High : Severity.Medium,
                    "Задан сценарий автонастройки прокси (PAC)",
                    $"AutoConfigURL = '{autoConfig}'. PAC-сценарий может незаметно перенаправлять трафик через узел злоумышленника.",
                    Evidence.Of("key", key.ToString()),
                    Evidence.Of("pac", autoConfig))));
            }
        }
    }

    // ---- Корневые сертификаты --------------------------------------------------

    private void AuditRootCertificates(List<ConfigFinding> findings)
    {
        foreach (var cert in _certificates!.GetRootCertificates())
        {
            if (cert.IsExpired(_options.Now))
            {
                findings.Add(Cert("CFG-CERT-EXPIRED", Severity.Low,
                    "Просроченный корневой сертификат",
                    $"В доверенном хранилище остаётся просроченный корень (до {cert.NotAfter:yyyy-MM-dd}): {cert.Subject}.", cert));
            }

            if (!cert.SelfSigned)
            {
                findings.Add(Cert("CFG-CERT-NONROOT", Severity.Medium,
                    "Несамоподписанный сертификат в хранилище корней",
                    $"Сертификат в хранилище доверенных корней не является самоподписанным (издатель: {cert.Issuer}) — нетипично для корневого CA.", cert));
            }
            else if (!cert.HasOrganization)
            {
                findings.Add(Cert("CFG-CERT-NOORG", Severity.Medium,
                    "Подозрительный корневой сертификат без организации",
                    $"Самоподписанный корень '{cert.Subject}' не содержит поля организации (O=) — характерно для сертификатов перехвата (MITM).", cert));
            }

            if (cert.IsWeakRsa(_options.MinRsaKeyBits))
            {
                findings.Add(Cert("CFG-CERT-WEAKKEY", Severity.Medium,
                    "Слабый ключ корневого сертификата",
                    $"Корневой сертификат '{cert.Subject}' использует RSA-ключ длиной {cert.KeyBits} бит (< {_options.MinRsaKeyBits}).", cert));
            }
        }
    }

    private static ConfigFinding Cert(string id, Severity severity, string title, string description, CertificateInfo cert) =>
        new(ConfigArea.RootCertificate, AuditFinding.Create(id, severity, title, description,
            Evidence.Of("subject", cert.Subject),
            Evidence.Of("issuer", cert.Issuer),
            Evidence.Of("thumbprint", cert.Thumbprint),
            Evidence.Of("key", $"{cert.KeyAlgorithm} {cert.KeyBits}")));
}
