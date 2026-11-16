using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;
using Sentinel.Core.Trust;
using Sentinel.Core.Signatures;
using Sentinel.Core.ThreatFamilies;

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

    private static readonly (string SubKey, DefenderExclusionKind Kind)[] ExclusionKinds =
    [
        ("Paths", DefenderExclusionKind.Path),
        ("Processes", DefenderExclusionKind.Process),
        ("Extensions", DefenderExclusionKind.Extension),
        ("IpAddresses", DefenderExclusionKind.IpAddress),
    ];

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
    private readonly IDefenderExclusionSource? _defender;
    private readonly FileAnalyzer? _analyzer;

    public ConfigIntegrityAuditor(
        ConfigIntegrityAuditorOptions? options = null,
        IRegistryProvider? registry = null,
        ICertificateStoreProvider? certificates = null,
        IDefenderExclusionSource? defenderExclusions = null,
        FileAnalyzer? analyzer = null)
    {
        _analyzer = analyzer;
        _options = options ?? new ConfigIntegrityAuditorOptions();
        _registry = registry;
        _certificates = certificates;
        _defender = defenderExclusions;
    }

    public ConfigAuditReport Audit()
    {
        var findings = new List<ConfigFinding>();
        var exclusions = new List<DefenderExclusion>();
        var skipped = new List<SkippedAuditStep>();
        var masquerading = new List<FirewallRule>();
        if (_registry is not null || _defender is not null)
        {
            AuditStepGuard.Run("Исключения Defender", () => AuditDefenderExclusions(findings, exclusions), skipped);
        }

        if (_registry is not null)
        {
            AuditStepGuard.Run("Политики Defender", () => AuditDefenderPolicies(findings), skipped);
            AuditStepGuard.Run("Правила брандмауэра", () => AuditFirewall(findings, masquerading), skipped);
            AuditStepGuard.Run("Системный прокси", () => AuditProxy(findings), skipped);
        }

        if (_certificates is not null)
        {
            AuditStepGuard.Run("Корневые сертификаты", () => AuditRootCertificates(findings), skipped);
        }

        return new ConfigAuditReport(findings) { DefenderExclusions = exclusions, Skipped = skipped, MasqueradingFirewallRules = masquerading };
    }

    // ---- Исключения Windows Defender ------------------------------------------

    private void AuditDefenderExclusions(List<ConfigFinding> findings, List<DefenderExclusion> exclusions)
    {
        var seen = new HashSet<(DefenderExclusionKind, string)>();
        if (_registry is not null)
        {
            for (var r = 0; r < DefenderExclusionRoots.Length; r++)
            {
                foreach (var (subKey, kind) in ExclusionKinds)
                {
                    var key = new RegistryKeyPath(RegistryHive.LocalMachine, DefenderExclusionRoots[r] + "\\" + subKey);
                    foreach (var value in _registry.GetValues(key))
                    {
                        if (!string.IsNullOrWhiteSpace(value.Name))
                        {
                            seen.Add((kind, value.Name.Trim().Trim('"').ToLowerInvariant()));
                            AddExclusion(findings, exclusions, new DefenderExclusion(kind, value.Name, key.ToString(), FromPolicy: r > 0), subKey);
                        }
                    }
                }
            }
        }

        // Действующие настройки Defender (WMI MSFT_MpPreference): исключения, которых нет в прочитанных ветках реестра.
        if (_defender is not null)
        {
            IReadOnlyList<DefenderExclusion> fromWmi;
            try
            {
                fromWmi = _defender.GetExclusions();
            }
            catch (Exception ex) when (AuditStepGuard.IsUnavailable(ex))
            {
                fromWmi = []; // WMI/Defender остановлены (Безопасный режим, WinRE): остаются данные реестра
            }

            foreach (var exclusion in fromWmi)
            {
                if (seen.Add((exclusion.Kind, exclusion.Value.Trim().Trim('"').ToLowerInvariant())))
                {
                    var subKey = ExclusionKinds.First(k => k.Kind == exclusion.Kind).SubKey;
                    AddExclusion(findings, exclusions, exclusion, subKey);
                }
            }
        }
    }

    private static void AddExclusion(List<ConfigFinding> findings, List<DefenderExclusion> exclusions, DefenderExclusion exclusion, string subKey)
    {
        var (kind, target) = (exclusion.Kind, exclusion.Value);
        exclusions.Add(exclusion);
        var (severity, note) = ClassifyExclusion(kind, target);
        var what = kind switch
        {
            DefenderExclusionKind.Path => "путь",
            DefenderExclusionKind.Process => "процесс",
            DefenderExclusionKind.Extension => "тип файлов",
            _ => "IP-адрес",
        };
        findings.Add(new ConfigFinding(ConfigArea.DefenderExclusion, AuditFinding.Create(
            "CFG-DEFENDER-EXCL", severity,
            $"Исключение встроенной защиты ({subKey})",
            $"Из проверки исключён {what} '{target}'. {note}",
            Evidence.Of("kind", subKey),
            Evidence.Of("target", target),
            Evidence.Of("key", exclusion.SourceKey))));
    }

    private static (Severity Severity, string Note) ClassifyExclusion(DefenderExclusionKind kind, string target)
    {
        if (kind == DefenderExclusionKind.IpAddress)
        {
            return (Severity.Medium, "Трафик этого адреса не проверяется сетевой защитой.");
        }

        if (kind == DefenderExclusionKind.Process && InterpreterHeuristics.IsInterpreter(ImageName(target)))
        {
            return (Severity.High, "Исключён интерпретатор/скриптовый хост — всё, что он запускает и открывает, не проверяется.");
        }

        if (kind == DefenderExclusionKind.Extension)
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

    private static string ImageName(string target)
    {
        var t = target.Trim().Trim('"');
        var idx = t.LastIndexOfAny(['\\', '/']);
        return idx < 0 ? t : t[(idx + 1)..];
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

    private void AuditFirewall(List<ConfigFinding> findings, List<FirewallRule> masquerading)
    {
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, FirewallRulesKey);
        // Одно приложение обычно имеет отдельные правила для TCP и UDP: карточка создаётся один раз на (имя правила, путь программы).
        var seen = new HashSet<(string, string)>();
        foreach (var value in _registry!.GetValues(key))
        {
            var rule = FirewallRuleParser.Parse(value.Name, value.Value);
            if (!rule.Allow || !rule.Enabled || string.IsNullOrWhiteSpace(rule.AppPath))
            {
                continue;
            }

            if (CheckMasquerade(rule) is { } masquerade)
            {
                masquerading.Add(rule);
                findings.Add(masquerade);
                continue;
            }

            var appInUserWritable = PathClassifier.IsUserWritableLocation(rule.AppPath)
                && !PathClassifier.IsInTrustedDirectory(rule.AppPath, _options.TrustedBinaryDirectories);
            if (!appInUserWritable)
            {
                continue;
            }

            var ruleName = rule.DisplayName ?? rule.Name;
            if (!seen.Add((ruleName.ToLowerInvariant(), PathClassifier.Normalize(rule.AppPath))))
            {
                continue;
            }

            var verdict = ClassifyFirewallApp(rule.AppPath);
            if (verdict.Severity is null)
            {
                continue; // подписанная программа доверенного издателя, разрешённая пользователем либо уже удалённая
            }

            var severity = verdict.Severity.Value;
            var inbound = rule.IsInbound ? "входящий" : "исходящий";
            findings.Add(new ConfigFinding(ConfigArea.FirewallRule, AuditFinding.Create(
                "CFG-FW-ALLOW", severity,
                severity == Severity.Info
                    ? "Разрешающее правило брандмауэра для пользовательской программы"
                    : (rule.IsInbound ? "Разрешающее входящее правило для подозрительного файла" : "Разрешающее исходящее правило для подозрительного файла"),
                $"Правило брандмауэра '{ruleName}' разрешает {inbound} трафик для '{rule.AppPath}' из каталога с правом записи пользователя. {verdict.Note}".Trim(),
                Evidence.Of("rule", ruleName),
                Evidence.Of("app", rule.AppPath),
                Evidence.Of("dir", rule.Direction),
                Evidence.Of("protocol", rule.Protocol))));
        }
    }

    // ---- Политики, отключающие Defender ----------------------------------------

    private const string DefenderPolicyRoot = @"SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string DefenderRoot = @"SOFTWARE\Microsoft\Windows Defender";

    /// <summary>(подключ, значение, «опасное» значение, пояснение). Подключ пустой — сам корень.</summary>
    private static readonly (string SubKey, string Value, string Bad, string Meaning)[] DefenderSwitches =
    [
        ("", "DisableAntiSpyware", "1", "Защитник отключён полностью"),
        ("", "DisableAntiVirus", "1", "антивирусная защита отключена"),
        ("", "DisableRoutinelyTakingAction", "1", "Защитник не принимает мер против угроз"),
        ("Real-Time Protection", "DisableRealtimeMonitoring", "1", "защита в реальном времени отключена"),
        ("Real-Time Protection", "DisableBehaviorMonitoring", "1", "поведенческий мониторинг отключён"),
        ("Real-Time Protection", "DisableOnAccessProtection", "1", "проверка при доступе отключена"),
        ("Real-Time Protection", "DisableIOAVProtection", "1", "проверка скачанных файлов отключена"),
        ("Real-Time Protection", "DisableScanOnRealtimeEnable", "1", "проверка процессов при включении защиты отключена"),
        ("Spynet", "SpynetReporting", "0", "облачная защита (MAPS) отключена"),
        ("Spynet", "SubmitSamplesConsent", "2", "отправка образцов запрещена"),
        ("Spynet", "DisableBlockAtFirstSeen", "1", "блокировка при первом появлении отключена"),
    ];

    private void AuditDefenderPolicies(List<ConfigFinding> findings)
    {
        foreach (var (root, isPolicy) in new[] { (DefenderPolicyRoot, true), (DefenderRoot, false) })
        {
            foreach (var (subKey, valueName, bad, meaning) in DefenderSwitches)
            {
                var key = new RegistryKeyPath(RegistryHive.LocalMachine, subKey.Length == 0 ? root : root + "\\" + subKey);
                var value = _registry!.GetValue(key, valueName)?.Value?.Trim();
                if (!string.Equals(value, bad, StringComparison.Ordinal))
                {
                    continue;
                }

                findings.Add(new ConfigFinding(ConfigArea.DefenderPolicy, AuditFinding.Create(
                    "CFG-DEFENDER-POLICY", isPolicy ? Severity.High : Severity.Medium,
                    isPolicy ? "Политика отключает встроенную защиту" : "Настройка ослабляет встроенную защиту",
                    $"{key}\\{valueName} = {value}: {meaning}."
                        + (isPolicy ? " Политику ставит администратор или вредонос; Защитник её не может переопределить." : string.Empty),
                    Evidence.Of("key", key.ToString()), Evidence.Of("value", valueName), Evidence.Of("data", value))));
            }
        }

        // Защита от подделки: 5 — включена, 4 — выключена (меняется только через Безопасность Windows).
        var tamper = _registry!.GetValue(new RegistryKeyPath(RegistryHive.LocalMachine, DefenderRoot + @"\Features"), "TamperProtection")?.Value?.Trim();
        if (tamper is "4" or "0")
        {
            findings.Add(new ConfigFinding(ConfigArea.DefenderPolicy, AuditFinding.Create(
                "CFG-DEFENDER-POLICY", Severity.Medium, "Защита от подделки выключена",
                "TamperProtection выключена: вредонос может менять настройки и исключения Защитника.",
                Evidence.Of("key", DefenderRoot + @"\Features"), Evidence.Of("value", "TamperProtection"), Evidence.Of("data", tamper))));
        }
    }

    // ---- Правила брандмауэра под системными именами ----------------------------

    /// <summary>Имена групп правил Windows (англ. и рус. локализации), которые подделывают вредоносы.</summary>
    private static readonly string[] SystemRuleNames =
    [
        "Network Discovery", "Core Networking", "File and Printer Sharing", "Remote Desktop", "Windows Defender",
        "Windows Firewall", "Windows Management Instrumentation", "Remote Assistance", "mDNS", "Delivery Optimization",
        "Cast to Device", "Wi-Fi Direct", "Connected Devices Platform", "Windows Remote Management", "Microsoft",
        "Windows", "DHCP", "DNS", "Router Solicitation", "SSDP", "UPnP", "LLMNR", "Teredo", "IPHTTPS",
        "Обнаружение сети", "Основы сетей", "Общий доступ к файлам и принтерам", "Удаленный рабочий стол", "Удалённый рабочий стол",
        "Брандмауэр Защитника Windows", "Удаленный помощник",
    ];

    /// <summary>
    /// Разрешающее правило с именем системного правила Windows («Network Discovery (SSDP-Out)», «Core Networking – Router
    /// Solicitation»), но программой вне <c>%SystemRoot%</c> и Program Files либо без подписи. Настоящие системные правила
    /// хранят имя ссылкой на ресурс (<c>@FirewallAPI.dll,-28502</c>) и указывают на svchost/System.
    /// </summary>
    private ConfigFinding? CheckMasquerade(FirewallRule rule)
    {
        var name = rule.DisplayName ?? rule.Name;
        if (name.StartsWith('@') || !LooksLikeSystemRuleName(name) || string.IsNullOrWhiteSpace(rule.AppPath)
            || string.Equals(rule.AppPath, "System", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string app;
        try
        {
            app = Environment.ExpandEnvironmentVariables(rule.AppPath);
        }
        catch (ArgumentException)
        {
            app = rule.AppPath;
        }

        var normalized = PathClassifier.Normalize(app);
        var inSystemLocation = normalized.Contains(@"\windows\", StringComparison.Ordinal) && normalized.IndexOf(@"\windows\", StringComparison.Ordinal) <= 3
            || normalized.Contains("%systemroot%", StringComparison.Ordinal)
            || PathClassifier.IsInTrustedDirectory(app, _options.TrustedBinaryDirectories)
            || normalized.Contains(@"\program files", StringComparison.Ordinal);

        FileScanResult? scan = null;
        if (_analyzer is not null && File.Exists(app))
        {
            try
            {
                scan = _analyzer.Analyze(app);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                scan = null;
            }
        }

        var signature = scan?.Signature;
        var unsigned = signature is { Status: not SignatureStatus.Unsupported and not SignatureStatus.Valid };
        if (inSystemLocation && !unsigned)
        {
            return null;
        }

        if (_options.IsUserAllowed?.Invoke(app) == true || TrustedPublishers.IsTrusted(signature))
        {
            return null;
        }

        var userWritable = PathClassifier.IsUserWritableLocation(app);
        var family = ThreatFamilyCatalog.MatchPath(app);
        var severity = family is not null || userWritable || unsigned ? Severity.High : Severity.Medium;
        var direction = rule.IsInbound ? "входящий" : "исходящий";
        return new ConfigFinding(ConfigArea.FirewallRule, AuditFinding.Create(
            "CFG-FW-MASQUERADE", severity,
            "Правило брандмауэра под системным именем ведёт на постороннюю программу",
            $"Правило '{name}' выглядит как системное правило Windows, но разрешает {direction} трафик"
                + (rule.AllProfiles ? " во всех профилях" : string.Empty)
                + $" для '{rule.AppPath}'"
                + (inSystemLocation ? " без действительной подписи." : " вне %SystemRoot% и Program Files.")
                + (family is null ? string.Empty : $" Программа лежит в каталоге семейства «{family.Family.Name}»."),
            Evidence.Of("rule", name),
            Evidence.Of("ruleId", rule.Name),
            Evidence.Of("app", rule.AppPath),
            Evidence.Of("dir", rule.Direction),
            Evidence.Of("profiles", rule.AllProfiles ? "все" : string.Join(",", rule.Profiles)),
            Evidence.Of("signature", signature?.Status.ToString())));
    }

    private static bool LooksLikeSystemRuleName(string name)
    {
        if (DeceptiveNameAnalyzer.Analyze(name) is not null)
        {
            return true;
        }

        foreach (var system in SystemRuleNames)
        {
            if (name.StartsWith(system, StringComparison.OrdinalIgnoreCase)
                && (name.Length == system.Length || !char.IsLetterOrDigit(name[system.Length])))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// <c>null</c> — правило не выводится (подпись доверенного издателя, список разрешённого, файла нет).
    /// Неподписанная пользовательская программа — <c>Info</c>; Medium/High — из Temp/Public или при высоком балле угрозы.
    /// </summary>
    private (Severity? Severity, string Note) ClassifyFirewallApp(string appPath)
    {
        string full;
        try
        {
            full = Environment.ExpandEnvironmentVariables(appPath);
        }
        catch (ArgumentException)
        {
            full = appPath;
        }

        if (_options.IsUserAllowed?.Invoke(full) == true)
        {
            return (null, string.Empty);
        }

        FileScanResult? scan = null;
        if (_analyzer is not null && File.Exists(full))
        {
            try
            {
                scan = _analyzer.Analyze(full);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                scan = null;
            }

            if (scan is not null && (scan.Verdict == Verdict.Trusted || TrustedPublishers.IsTrusted(scan.Signature)))
            {
                return (null, string.Empty);
            }
        }

        var inTempOrPublic = PathClassifier.IsTempOrPublic(full);
        var score = scan?.Score?.Value ?? 0;
        if (score >= 45 || scan?.Verdict is Verdict.Malicious or Verdict.Suspicious)
        {
            return (Severity.High, $"Файл подозрителен (балл угрозы {score}/100).");
        }

        if (inTempOrPublic)
        {
            return (_options.FirewallInboundTempSeverity, "Программа запускается из временного или общедоступного каталога.");
        }

        return (Severity.Info, "Неподписанная пользовательская программа — только запись в журнал.");
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
        // Дедупликация по отпечатку: один сертификат может присутствовать и в LocalMachine, и в CurrentUser.
        var unique = _certificates!.GetRootCertificates()
            .GroupBy(c => c.Thumbprint, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToArray();
        var recentBorder = _options.Now.AddDays(-_options.RecentCertificateDays);
        var standardExpired = new List<CertificateInfo>();
        var standardWeak = new List<CertificateInfo>();

        foreach (var cert in unique)
        {
            // Штатный корень: входит в программу доверенных корней Microsoft (AuthRoot) либо это исторический корень Microsoft.
            var standard = cert.IsStandard || cert.IsKnownMicrosoftRoot;
            var recent = cert.NotBefore >= recentBorder;

            if (cert.IsExpired(_options.Now))
            {
                if (standard || !recent)
                {
                    // Просроченные корни 1997–2024 остаются в системе ради совместимости старых подписей — это не угроза.
                    standardExpired.Add(cert);
                }
                else
                {
                    findings.Add(Cert("CFG-CERT-EXPIRED", Severity.Medium,
                        "Просроченный недавно установленный корневой сертификат",
                        $"В доверенном хранилище остаётся просроченный нестандартный корень (до {cert.NotAfter:yyyy-MM-dd}): {cert.Subject}.", cert));
                }
            }

            if (!cert.SelfSigned)
            {
                var vendor = TrustedPublishers.IsTrusted(cert.Subject);
                findings.Add(Cert("CFG-CERT-NONROOT", vendor || standard ? Severity.Info : Severity.Medium,
                    "Несамоподписанный сертификат в хранилище корней",
                    $"Сертификат в хранилище доверенных корней не является самоподписанным (издатель: {cert.Issuer}) — нетипично для корневого CA.", cert));
            }
            else if (!cert.HasOrganization && !standard)
            {
                // Самоподписанный корень без организации вне списка Microsoft: признак прокси перехвата (MITM), особенно если он свежий.
                findings.Add(Cert("CFG-CERT-NOORG", recent ? Severity.Medium : Severity.Low,
                    "Подозрительный корневой сертификат без организации",
                    $"Самоподписанный корень '{cert.Subject}' не содержит поля организации (O=) и не входит в список доверенных корней Microsoft — характерно для сертификатов перехвата (MITM).", cert));
            }

            if (cert.IsWeakRsa(_options.MinRsaKeyBits))
            {
                if (standard || !recent)
                {
                    standardWeak.Add(cert);
                }
                else
                {
                    findings.Add(Cert("CFG-CERT-WEAKKEY", Severity.Medium,
                        "Слабый ключ недавно установленного корневого сертификата",
                        $"Корневой сертификат '{cert.Subject}' использует RSA-ключ длиной {cert.KeyBits} бит (< {_options.MinRsaKeyBits}).", cert));
                }
            }
        }

        AddAggregate(findings, "CFG-CERT-EXPIRED", "Просроченные штатные корневые сертификаты",
            "оставлены Microsoft для совместимости старых подписей", standardExpired);
        AddAggregate(findings, "CFG-CERT-WEAKKEY", "Устаревшие штатные корневые сертификаты с коротким ключом",
            "оставлены Microsoft для совместимости старых подписей", standardWeak);
    }

    /// <summary>Штатные устаревшие корни не плодят сотни карточек: одна сводная запись уровня Info с примерами в доказательствах.</summary>
    private static void AddAggregate(List<ConfigFinding> findings, string id, string title, string reason, List<CertificateInfo> certs)
    {
        if (certs.Count == 0)
        {
            return;
        }

        var evidence = new List<Evidence> { Evidence.Of("count", certs.Count) };
        evidence.AddRange(certs.Take(5).Select((c, i) => Evidence.Of($"example{i + 1}", $"{c.Subject} [{c.Thumbprint}]")));
        findings.Add(new ConfigFinding(ConfigArea.RootCertificate, AuditFinding.Create(id, Severity.Info, title,
            $"{certs.Count} сертификатов в хранилищах доверенных корней ({reason}). Это не угроза и ничем не заменяется автоматически.",
            [.. evidence])));
    }

    private static ConfigFinding Cert(string id, Severity severity, string title, string description, CertificateInfo cert) =>
        new(ConfigArea.RootCertificate, AuditFinding.Create(id, severity, title, description,
            Evidence.Of("subject", cert.Subject),
            Evidence.Of("issuer", cert.Issuer),
            Evidence.Of("thumbprint", cert.Thumbprint),
            Evidence.Of("key", $"{cert.KeyAlgorithm} {cert.KeyBits}")));
}
