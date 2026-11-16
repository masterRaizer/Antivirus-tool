using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;
using Sentinel.Core.Trust;
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
        if (_registry is not null || _defender is not null)
        {
            AuditStepGuard.Run("Исключения Defender", () => AuditDefenderExclusions(findings, exclusions), skipped);
        }

        if (_registry is not null)
        {
            AuditStepGuard.Run("Правила брандмауэра", () => AuditFirewall(findings), skipped);
            AuditStepGuard.Run("Системный прокси", () => AuditProxy(findings), skipped);
        }

        if (_certificates is not null)
        {
            AuditStepGuard.Run("Корневые сертификаты", () => AuditRootCertificates(findings), skipped);
        }

        return new ConfigAuditReport(findings) { DefenderExclusions = exclusions, Skipped = skipped };
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

    private void AuditFirewall(List<ConfigFinding> findings)
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
