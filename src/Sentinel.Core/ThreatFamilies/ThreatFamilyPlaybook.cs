using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Remediation;

namespace Sentinel.Core.ThreatFamilies;

/// <summary>Шаг плейбука (порядок важен: загрузчик останавливается до майнера, закрепление снимается до карантина).</summary>
public enum PlaybookStepKind
{
    Evidence = 1,
    StopProcess = 2,
    RemovePersistence = 3,
    RestoreProtection = 4,
    QuarantineFiles = 5,
    BlockIoc = 6,
    Verify = 7,
}

/// <summary>Запланированное действие: что будет сделано и с чем.</summary>
public sealed record PlaybookStep(PlaybookStepKind Kind, string Target, string Description);

/// <summary>Состояние системы для проверки после чистки и после перезагрузки. Отсутствующий источник — проверка пропускается.</summary>
public sealed record FamilyVerificationProbe
{
    public Func<string, bool> FileExists { get; init; } = File.Exists;
    public Func<IReadOnlyList<ProcessSnapshot>>? Processes { get; init; }
    public Func<IReadOnlyList<NetworkConnection>>? Connections { get; init; }
    public Func<IReadOnlyList<DefenderExclusion>>? Exclusions { get; init; }

    /// <summary>Повторный аудит закрепления (Run, задачи, службы, WMI) — ищет оставшийся механизм перезапуска.</summary>
    public Func<PersistenceAuditReport>? Persistence { get; init; }
}

public sealed record ThreatFamilyPlaybookOptions
{
    /// <summary>Только аудит: снимок улик и план, никаких изменений.</summary>
    public bool AuditOnly { get; init; } = true;

    /// <summary>Пользователь подтвердил нейтрализацию в UI или CLI. Без подтверждения ничего не удаляется.</summary>
    public bool Confirmed { get; init; }

    /// <summary>Блокировать IOC (исходящие к IP семейства, записи hosts) — отдельное подтверждение.</summary>
    public bool BlockIoc { get; init; }

    public string HostsPath { get; init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System) is { Length: > 0 } sys ? sys : @"C:\Windows\System32", "drivers", "etc", "hosts");

    /// <summary>Каталог данных Sentinel: снимки улик (<c>Evidence\</c>) и отметка перепроверки после перезагрузки.</summary>
    public required string DataDirectory { get; init; }

    /// <summary>Пауза перед проверкой (30–60 с): загрузчик или задача успевают пересоздать файл, если механизм остался.</summary>
    public TimeSpan VerifyDelay { get; init; } = TimeSpan.FromSeconds(45);

    public Func<TimeSpan, CancellationToken, Task> Delay { get; init; } = (d, ct) => Task.Delay(d, ct);

    public TimeProvider Time { get; init; } = TimeProvider.System;
}

/// <summary>Итог проверки после чистки.</summary>
public sealed record FamilyVerification(bool Clean, IReadOnlyList<string> Problems, IReadOnlyList<string> Checked);

/// <summary>Итог плейбука.</summary>
public sealed record PlaybookResult
{
    public required IReadOnlyList<FamilyDetection> Detections { get; init; }
    public required IReadOnlyList<PlaybookStep> Plan { get; init; }
    public IReadOnlyList<RemediationAction> Actions { get; init; } = [];
    public IReadOnlyList<QuarantineResult> Quarantined { get; init; } = [];
    public FamilyVerification? Verification { get; init; }
    public string? EvidenceJsonPath { get; init; }
    public string? EvidenceHtmlPath { get; init; }
    public bool Executed { get; init; }
    public bool RebootRecommended { get; init; }
    public required string UserMessage { get; init; }
}

/// <summary>
/// Плейбук нейтрализации семейств CAAService/techias и похожих. Работает через существующие <see cref="RemediationEngine"/>
/// (манифест отката, <c>CriticalProcessGuard</c>, самозащита) и <see cref="QuarantineManager"/> (шифрованный контейнер, SHA-256
/// в манифесте). Порядок: 1 снимок улик → 2 остановка процессов, загрузчик первым → 3 закрепление → 4 исключения Защитника и
/// поддельные правила брандмауэра → 5 карантин файлов и удаление пустой папки → 6 блокировка IOC (по отдельному согласию) →
/// 7 проверка через 30–60 с → 8 перепроверка после перезагрузки → 9 сообщение пользователю. Без подтверждения и в режиме
/// «только аудит» выполняется только шаг 1 и строится план.
/// </summary>
public sealed class ThreatFamilyPlaybook
{
    public const string RecheckMarkerFileName = "family-recheck.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly RemediationEngine? _engine;
    private readonly QuarantineManager? _quarantine;
    private readonly ThreatFamilyPlaybookOptions _options;
    private readonly FamilyVerificationProbe _probe;

    public ThreatFamilyPlaybook(RemediationEngine? engine, QuarantineManager? quarantine, ThreatFamilyPlaybookOptions options, FamilyVerificationProbe? probe = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _engine = engine;
        _quarantine = quarantine;
        _options = options;
        _probe = probe ?? new FamilyVerificationProbe();
    }

    // ---- План --------------------------------------------------------------------

    /// <summary>Упорядоченный план для находок высокой серьёзности (средние только показываются).</summary>
    public IReadOnlyList<PlaybookStep> Plan(IReadOnlyList<FamilyDetection> detections)
    {
        ArgumentNullException.ThrowIfNull(detections);
        var actionable = detections.Where(d => d.Actionable).ToList();
        var steps = new List<PlaybookStep> { new(PlaybookStepKind.Evidence, _options.DataDirectory, "Снимок улик: пути, хеши, подписи, командные строки, дерево процессов, XML задач, правила, исключения") };
        if (actionable.Count == 0)
        {
            return steps;
        }

        foreach (var p in actionable.SelectMany(d => d.Artifacts.Processes).DistinctBy(p => p.Process.Pid))
        {
            steps.Add(new(PlaybookStepKind.StopProcess, $"PID {p.Process.Pid} {p.Process.Name}",
                p.Role == FamilyProcessRole.Loader ? "Остановить загрузчик (родителя) — первым" : "Остановить нагрузку (майнер)"));
        }

        foreach (var e in Persistence(actionable))
        {
            steps.Add(new(PlaybookStepKind.RemovePersistence, $"{e.Location} → {e.Name}",
                e.Kind == PersistenceKind.ScheduledTask ? "Удалить задачу (XML сохраняется в манифест отката)" : "Удалить автозапуск (значение сохраняется в манифест отката)"));
        }

        foreach (var x in actionable.SelectMany(d => d.Artifacts.Exclusions).DistinctBy(x => (x.Kind, x.Value.ToLowerInvariant())))
        {
            steps.Add(new(PlaybookStepKind.RestoreProtection, x.ToString(), "Удалить исключение Защитника (сохраняется для отката)"));
        }

        foreach (var r in actionable.SelectMany(d => d.Artifacts.FirewallRules).DistinctBy(r => r.Name))
        {
            steps.Add(new(PlaybookStepKind.RestoreProtection, $"«{r.DisplayName ?? r.Name}» → {r.AppPath}", "Удалить поддельное правило брандмауэра (строка правила сохраняется)"));
        }

        foreach (var folder in actionable.SelectMany(d => d.Artifacts.Folders).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            steps.Add(new(PlaybookStepKind.QuarantineFiles, folder, "Все файлы каталога — в карантин (шифрованный контейнер, SHA-256 в манифесте), затем удалить пустой каталог"));
        }

        foreach (var file in LooseFiles(actionable))
        {
            steps.Add(new(PlaybookStepKind.QuarantineFiles, file, "Файл — в карантин"));
        }

        if (_options.BlockIoc)
        {
            var ips = actionable.SelectMany(d => d.Artifacts.IpAddresses).Distinct().ToArray();
            var domains = actionable.SelectMany(d => d.Artifacts.Domains).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (ips.Length > 0)
            {
                steps.Add(new(PlaybookStepKind.BlockIoc, string.Join(", ", ips), "Правило брандмауэра: запретить исходящие соединения"));
            }

            if (domains.Length > 0)
            {
                steps.Add(new(PlaybookStepKind.BlockIoc, string.Join(", ", domains), $"Записи 0.0.0.0 в {_options.HostsPath}"));
            }
        }

        steps.Add(new(PlaybookStepKind.Verify, $"через {_options.VerifyDelay.TotalSeconds:F0} с",
            "Проверить: файлы не пересозданы, процессов и соединений нет, исключения не вернулись; иначе — повторный поиск закрепления"));
        return steps;
    }

    // ---- Выполнение --------------------------------------------------------------

    public async Task<PlaybookResult> ExecuteAsync(IReadOnlyList<FamilyDetection> detections, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(detections);
        var plan = Plan(detections);
        var (jsonPath, htmlPath) = await WriteEvidenceAsync(detections, plan, cancellationToken).ConfigureAwait(false);
        var actionable = detections.Where(d => d.Actionable).ToList();
        var execute = !_options.AuditOnly && _options.Confirmed && actionable.Count > 0;
        if (!execute)
        {
            return new PlaybookResult
            {
                Detections = detections,
                Plan = plan,
                EvidenceJsonPath = jsonPath,
                EvidenceHtmlPath = htmlPath,
                UserMessage = BuildUserMessage(detections, [], [], null, executed: false, jsonPath),
            };
        }

        if (_engine is null || _quarantine is null)
        {
            throw new InvalidOperationException("Для нейтрализации нужны движок ремедиации и карантин.");
        }

        var actions = new List<RemediationAction>();
        var reason = "Плейбук семейства: " + string.Join("; ", actionable.Select(d => d.Verdict).Distinct());

        // 2. Процессы: загрузчики (родители) первыми — иначе загрузчик пересоздаст и перезапустит майнер.
        foreach (var p in actionable.SelectMany(d => d.Artifacts.Processes).DistinctBy(p => p.Process.Pid))
        {
            actions.Add(_engine.TerminateProcessTree(p.Process.Pid, userConfirmed: true).ToAction() with
            {
                Target = $"PID {p.Process.Pid} {p.Process.Name} ({(p.Role == FamilyProcessRole.Loader ? "загрузчик" : "нагрузка")})",
            });
        }

        // 3. Закрепление. Настоящие задачи Office не трогаются никогда.
        var persistence = Persistence(actionable).ToList();
        foreach (var office in persistence.Where(IsGenuineOfficeTask))
        {
            actions.Add(new RemediationAction(RemediationActionKind.RollbackPersistence, $"{office.Location} → {office.Name}",
                RemediationStatus.Blocked, "Настоящая задача Office (подписанный Microsoft исполняемый файл) — не изменяется."));
        }

        actions.AddRange(_engine.RollbackPersistence(persistence.Where(e => !IsGenuineOfficeTask(e))));

        // 4. Защита: исключения Защитника и поддельные правила брандмауэра.
        actions.AddRange(_engine.RemoveDefenderExclusions(
            actionable.SelectMany(d => d.Artifacts.Exclusions).DistinctBy(x => (x.Kind, x.Value.ToLowerInvariant())), reason));
        foreach (var rule in actionable.SelectMany(d => d.Artifacts.FirewallRules).DistinctBy(r => r.Name))
        {
            actions.Add(_engine.RemoveFirewallRule(rule, reason));
        }

        // 5. Карантин: все файлы каталогов семейства (без перехода по junction/symlink), затем пустой каталог.
        var quarantined = new List<QuarantineResult>();
        var folders = actionable.SelectMany(d => d.Artifacts.Folders).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var file in folders.SelectMany(EnumerateFolderFiles).Concat(LooseFiles(actionable)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var result = await _quarantine.QuarantineAsync(file, reason, dryRun: false, cancellationToken).ConfigureAwait(false);
            quarantined.Add(result);
            actions.Add(new RemediationAction(RemediationActionKind.QuarantineFile, file,
                result.Status switch
                {
                    QuarantineStatus.Quarantined => RemediationStatus.Done,
                    QuarantineStatus.NotFound => RemediationStatus.Skipped,
                    QuarantineStatus.BlockedByWhitelist => RemediationStatus.Blocked,
                    _ => RemediationStatus.Failed,
                }, result.Message) { RollbackId = result.Record?.Id });
        }

        foreach (var folder in folders)
        {
            actions.Add(_engine.RemoveEmptyDirectory(folder, reason));
        }

        // 6. Блокировка IOC — только по отдельному согласию.
        if (_options.BlockIoc)
        {
            var ips = actionable.SelectMany(d => d.Artifacts.IpAddresses).Distinct().ToArray();
            if (ips.Length > 0)
            {
                actions.Add(_engine.BlockRemoteAddresses("Sentinel IOC Block (" + string.Join(", ", actionable.Select(d => d.Family?.Id ?? "family").Distinct()) + ")", ips, reason));
            }

            var domains = actionable.SelectMany(d => d.Artifacts.Domains).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (domains.Length > 0)
            {
                actions.Add(_engine.BlockDomainsInHosts(_options.HostsPath, domains, reason));
            }
        }

        // 7. Проверка через 30–60 с; 8. отметка для перепроверки после перезагрузки.
        await _options.Delay(_options.VerifyDelay, cancellationToken).ConfigureAwait(false);
        var verification = Verify(actionable);
        WriteRecheckMarker(actionable);

        return new PlaybookResult
        {
            Detections = detections,
            Plan = plan,
            Actions = actions,
            Quarantined = quarantined,
            Verification = verification,
            EvidenceJsonPath = jsonPath,
            EvidenceHtmlPath = htmlPath,
            Executed = true,
            RebootRecommended = true,
            UserMessage = BuildUserMessage(detections, actions, quarantined, verification, executed: true, jsonPath),
        };
    }

    // ---- Проверка ----------------------------------------------------------------

    /// <summary>Файлы не пересозданы, процессов из каталогов нет, соединений с IOC нет, исключения не вернулись, закрепления нет.</summary>
    public FamilyVerification Verify(IReadOnlyList<FamilyDetection> detections) => VerifyCore(
        detections.SelectMany(d => d.Artifacts.Folders).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        detections.SelectMany(d => d.Artifacts.Files).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        detections.SelectMany(d => d.Artifacts.IpAddresses).Distinct().ToList(),
        detections.SelectMany(d => d.Artifacts.Exclusions).ToList(),
        detections.SelectMany(d => d.Artifacts.Persistence).Select(p => p.Location + "|" + p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase));

    private FamilyVerification VerifyCore(IReadOnlyList<string> folders, IReadOnlyList<string> files, IReadOnlyList<string> ips,
        IReadOnlyList<DefenderExclusion> removedExclusions, HashSet<string> removedPersistence)
    {
        var problems = new List<string>();
        var checks = new List<string>();

        checks.Add("файлы и каталоги семейства");
        foreach (var file in files.Where(_probe.FileExists))
        {
            problems.Add($"Файл снова существует: {file} — остался механизм, который его пересоздаёт.");
        }

        foreach (var folder in folders.Where(Directory.Exists))
        {
            var present = EnumerateFolderFiles(folder).Take(5).ToList();
            if (present.Count > 0)
            {
                problems.Add($"В каталоге {folder} снова появились файлы: {string.Join(", ", present.Select(Path.GetFileName))}.");
            }
        }

        if (_probe.Processes is { } processes)
        {
            checks.Add("процессы");
            foreach (var p in processes().Where(p => p.ExecutablePath is { } path
                && (folders.Any(f => InFolder(path, f)) || files.Contains(path, StringComparer.OrdinalIgnoreCase))))
            {
                problems.Add($"Процесс снова запущен: PID {p.Pid} {p.Name} ({p.ExecutablePath}).");
            }
        }

        if (_probe.Connections is { } connections && ips.Count > 0)
        {
            checks.Add("соединения с узлами семейства");
            foreach (var c in connections().Where(c => ips.Contains(ThreatFamilyCatalog.NormalizeIp(c.RemoteAddress))))
            {
                problems.Add($"Есть соединение с {c.RemoteAddress}:{c.RemotePort} (PID {c.Pid}).");
            }
        }

        if (_probe.Exclusions is { } exclusions)
        {
            checks.Add("исключения Защитника");
            var current = exclusions();
            foreach (var removed in removedExclusions)
            {
                if (current.Any(x => x.Kind == removed.Kind && string.Equals(x.ExpandedValue.TrimEnd('\\'), removed.ExpandedValue.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)))
                {
                    problems.Add($"Исключение вернулось: {removed} — его снова добавляет оставшийся компонент.");
                }
            }

            foreach (var x in current.Where(x => x.Kind == DefenderExclusionKind.Path && folders.Any(f => InFolder(x.ExpandedValue.TrimEnd('\\') + "\\x", f))))
            {
                problems.Add($"Новое исключение на каталог семейства: {x}.");
            }
        }

        if (_probe.Persistence is { } rescan)
        {
            checks.Add("закрепление (Run, задачи, службы, WMI)");
            foreach (var e in rescan().Entries.Where(e => e.HasFindings))
            {
                var returned = removedPersistence.Contains(e.Location + "|" + e.Name);
                var intoFolder = folders.Any(f => InFolder(e.ResolvedTarget, f)) || folders.Any(f => e.Command?.Contains(f, StringComparison.OrdinalIgnoreCase) == true);
                var downloader = e.Findings.Any(f => f.Id is "PERS-TASK-DOWNLOAD-EXEC" or "PERS-RUN-DOWNLOAD-EXEC" or "PERS-WMI-CONSUMER" or "PERS-WMI-SCRIPT" or "PERS-FAMILY-IOC");
                if (returned || intoFolder || downloader)
                {
                    problems.Add($"Осталось/вернулось закрепление: [{e.Kind}] {e.Location} → {e.Name} ({string.Join(", ", e.Findings.Select(f => f.Id).Distinct())})"
                        + " — вероятно, это другой механизм перезапуска (Powedon-подобная задача, WMI-подписка).");
                }
            }
        }

        return new FamilyVerification(problems.Count == 0, problems, checks);
    }

    // ---- Перепроверка после перезагрузки --------------------------------------------

    private sealed record RecheckMarker(DateTime CreatedUtc, List<string> Folders, List<string> Files, List<string> IpAddresses, List<DefenderExclusion> Exclusions, List<string> Persistence);

    private void WriteRecheckMarker(IReadOnlyList<FamilyDetection> detections)
    {
        var marker = new RecheckMarker(
            _options.Time.GetUtcNow().UtcDateTime,
            detections.SelectMany(d => d.Artifacts.Folders).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            detections.SelectMany(d => d.Artifacts.Files).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            detections.SelectMany(d => d.Artifacts.IpAddresses).Distinct().ToList(),
            detections.SelectMany(d => d.Artifacts.Exclusions).ToList(),
            detections.SelectMany(d => d.Artifacts.Persistence).Select(p => p.Location + "|" + p.Name).ToList());
        Directory.CreateDirectory(_options.DataDirectory);
        File.WriteAllText(Path.Combine(_options.DataDirectory, RecheckMarkerFileName), JsonSerializer.Serialize(marker, Json));
    }

    /// <summary>Есть ли отложенная перепроверка (после чистки рекомендована перезагрузка).</summary>
    public static bool HasPendingRecheck(string dataDirectory) => File.Exists(Path.Combine(dataDirectory, RecheckMarkerFileName));

    /// <summary>
    /// Перепроверка после перезагрузки (вызывается службой при старте): те же проверки, что и через 45 с. Отметка удаляется,
    /// если всё чисто; при проблемах остаётся, и проверка повторится при следующем запуске.
    /// </summary>
    public FamilyVerification? RunPendingRecheck()
    {
        var path = Path.Combine(_options.DataDirectory, RecheckMarkerFileName);
        if (!File.Exists(path))
        {
            return null;
        }

        RecheckMarker? marker;
        try
        {
            marker = JsonSerializer.Deserialize<RecheckMarker>(File.ReadAllText(path), Json);
        }
        catch (JsonException)
        {
            File.Delete(path);
            return null;
        }

        if (marker is null)
        {
            return null;
        }

        var result = VerifyCore(marker.Folders, marker.Files, marker.IpAddresses, marker.Exclusions, marker.Persistence.ToHashSet(StringComparer.OrdinalIgnoreCase));
        if (result.Clean)
        {
            File.Delete(path);
        }

        return result;
    }

    // ---- Улики ---------------------------------------------------------------------

    private async Task<(string? Json, string? Html)> WriteEvidenceAsync(IReadOnlyList<FamilyDetection> detections, IReadOnlyList<PlaybookStep> plan, CancellationToken ct)
    {
        if (detections.Count == 0)
        {
            return (null, null);
        }

        var files = new List<object>();
        foreach (var file in detections.SelectMany(d => d.Artifacts.Folders.SelectMany(EnumerateFolderFiles).Concat(d.Artifacts.Files))
            .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string? sha = null;
            long? size = null;
            if (File.Exists(file))
            {
                try
                {
                    size = new FileInfo(file).Length;
                    sha = await Hashing.FileHasher.ComputeSha256Async(file, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    sha = "недоступен: " + ex.Message;
                }
            }

            var scan = detections.SelectMany(d => d.Artifacts.Persistence).FirstOrDefault(p => string.Equals(p.ResolvedTarget, file, StringComparison.OrdinalIgnoreCase))?.FileScan;
            files.Add(new
            {
                path = file,
                size,
                sha256 = sha,
                family = ThreatFamilyCatalog.MatchHash(sha)?.Family.Id,
                signature = scan?.Signature?.Status.ToString(),
                signer = scan?.Signature?.SignerSubject,
            });
        }

        var snapshot = new
        {
            createdUtc = _options.Time.GetUtcNow().UtcDateTime,
            machine = Environment.MachineName,
            detections = detections.Select(d => new
            {
                d.Key,
                severity = d.Severity.ToString(),
                d.Verdict,
                family = d.Family?.Name,
                d.ChainConfirmed,
                d.Signals,
                processes = d.Artifacts.Processes.Select(p => new { p.Role, p.Process.Pid, p.Process.ParentPid, p.Process.Name, p.Process.ExecutablePath, p.Process.CommandLine }),
                persistence = d.Artifacts.Persistence.Select(p => new { p.Kind, p.Location, p.Name, p.Command, p.ResolvedTarget, findings = p.Findings.Select(f => f.Id) }),
                exclusions = d.Artifacts.Exclusions.Select(x => new { kind = x.Kind.ToString(), x.Value, x.SourceKey, x.FromPolicy }),
                firewall = d.Artifacts.FirewallRules.Select(r => new { r.Name, r.DisplayName, r.AppPath, r.Direction, raw = r.RawValue }),
                d.Artifacts.Domains,
                d.Artifacts.IpAddresses,
            }),
            files,
            plan,
        };

        var dir = Path.Combine(_options.DataDirectory, "Evidence");
        Directory.CreateDirectory(dir);
        var stamp = _options.Time.GetUtcNow().UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(dir, $"family-{stamp}.json");
        var json = JsonSerializer.Serialize(snapshot, Json);
        await File.WriteAllTextAsync(jsonPath, json, ct).ConfigureAwait(false);

        var html = new StringBuilder();
        html.Append("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><title>Sentinel — улики семейства</title>")
            .Append("<style>body{font-family:Segoe UI,sans-serif;background:#111;color:#eee;margin:24px}h2{color:#ff8a65}pre{background:#1d1d1d;padding:12px;white-space:pre-wrap;word-break:break-all}</style></head><body>")
            .Append("<h1>Снимок улик: семейство майнеров/загрузчиков</h1>");
        foreach (var d in detections)
        {
            html.Append("<h2>").Append(WebUtility.HtmlEncode($"[{d.Severity}] {d.Verdict}")).Append("</h2><ul>");
            foreach (var s in d.Signals)
            {
                html.Append("<li>").Append(WebUtility.HtmlEncode(s)).Append("</li>");
            }

            html.Append("</ul>");
        }

        html.Append("<h2>Полные данные (JSON)</h2><pre>").Append(WebUtility.HtmlEncode(json)).Append("</pre></body></html>");
        var htmlPath = Path.ChangeExtension(jsonPath, ".html");
        await File.WriteAllTextAsync(htmlPath, html.ToString(), ct).ConfigureAwait(false);
        return (jsonPath, htmlPath);
    }

    // ---- Сообщение пользователю ------------------------------------------------------

    internal static string BuildUserMessage(IReadOnlyList<FamilyDetection> detections, IReadOnlyList<RemediationAction> actions,
        IReadOnlyList<QuarantineResult> quarantined, FamilyVerification? verification, bool executed, string? evidencePath)
    {
        var sb = new StringBuilder();
        if (detections.Count == 0)
        {
            return "Признаков семейств CAAService/techias и похожих загрузчиков не найдено.";
        }

        sb.AppendLine("Что найдено:");
        foreach (var d in detections)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"  • [{SeverityRu(d.Severity)}] {d.Verdict}");
            foreach (var s in d.Signals)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"      – {s}");
            }
        }

        if (evidencePath is not null)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"Снимок улик (JSON и HTML): {evidencePath}");
        }

        if (!executed)
        {
            sb.AppendLine();
            sb.AppendLine(detections.Any(d => d.Actionable)
                ? "Ничего не изменено (режим «только аудит» или нет подтверждения). Для чистки подтвердите действие: sentinel family-clean --confirm."
                : "Признаки средней серьёзности: автоматическая чистка не предлагается, проверьте их вручную.");
        }
        else
        {
            sb.AppendLine();
            sb.AppendLine("Что сделано:");
            foreach (var a in actions)
            {
                var rollback = a.RollbackId is null ? string.Empty : $" [откат: {a.RollbackId[..Math.Min(8, a.RollbackId.Length)]}]";
                sb.AppendLine(CultureInfo.InvariantCulture, $"  • {StatusRu(a.Status)}: {a.Target} — {a.Message}{rollback}");
            }

            var inQuarantine = quarantined.Where(q => q.Status == QuarantineStatus.Quarantined).ToList();
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"В карантине файлов: {inQuarantine.Count} (каталог %ProgramData%\\Sentinel\\Quarantine, содержимое зашифровано, SHA-256 в манифесте).");
            sb.AppendLine("Как откатить: sentinel rollback list → sentinel rollback undo <id> (задачи, Run, исключения, правила);");
            sb.AppendLine("             sentinel quarantine list → sentinel quarantine restore <id> (файлы).");
            if (verification is not null)
            {
                sb.AppendLine();
                if (verification.Clean)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"Проверка через 30–60 с: чисто ({string.Join(", ", verification.Checked)}).");
                }
                else
                {
                    sb.AppendLine("Проверка через 30–60 с: НЕ чисто — остался другой механизм перезапуска:");
                    foreach (var p in verification.Problems)
                    {
                        sb.AppendLine(CultureInfo.InvariantCulture, $"  ! {p}");
                    }

                    sb.AppendLine("  Запустите повторный аудит (sentinel family-scan) и проверьте задачи Планировщика и WMI-подписки.");
                }
            }

            sb.AppendLine("Перезагрузите компьютер: после перезагрузки служба Sentinel автоматически перепроверит систему.");
        }

        sb.AppendLine();
        sb.AppendLine("Обязательно:");
        sb.AppendLine("  • смените пароли с чистого устройства (почта, мессенджеры, игровые и банковские сервисы, пароли из браузера);");
        sb.AppendLine("  • включите двухфакторную аутентификацию везде, где она есть;");
        var hashes = detections.Select(d => d.Family).Where(f => f is not null).SelectMany(f => f!.Hashes.Keys).Distinct().ToList();
        sb.AppendLine("  • можно отправить хеши (SHA-256 из снимка улик) в лабораторию Касперского: newvirus@kaspersky.com"
            + (hashes.Count > 0 ? $" ({hashes.Count} известных хешей семейства уже в отчёте)." : "."));
        foreach (var vector in detections.Select(d => d.Family?.Vector).Where(v => v is not null).Distinct())
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"  • Источник заражения: {vector}. Активаторы и пиратские сборки — основной путь таких загрузчиков; не устанавливайте их.");
        }

        return sb.ToString().TrimEnd();
    }

    // ---- Вспомогательные ---------------------------------------------------------------

    private static IEnumerable<PersistenceEntry> Persistence(IEnumerable<FamilyDetection> detections) =>
        detections.SelectMany(d => d.Artifacts.Persistence)
            .Where(e => e.Kind != PersistenceKind.UninstallEntry)
            .DistinctBy(e => (e.Kind, e.Location.ToLowerInvariant(), e.Name.ToLowerInvariant()));

    private static IEnumerable<string> LooseFiles(IEnumerable<FamilyDetection> detections)
    {
        var list = detections.ToList();
        var folders = list.SelectMany(d => d.Artifacts.Folders).ToList();
        return list.SelectMany(d => d.Artifacts.Files)
            .Where(f => !folders.Any(folder => InFolder(f, folder)))
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Настоящая задача Office: выполняет <c>OfficeC2RClient.exe</c> или <c>OfficeTelemetryAgent*.exe</c> из Program Files с
    /// действительной подписью Microsoft (подпись берётся из анализа цели, если он выполнялся).
    /// </summary>
    internal static bool IsGenuineOfficeTask(PersistenceEntry entry)
    {
        if (entry.Kind != PersistenceKind.ScheduledTask || entry.ResolvedTarget is not { } target)
        {
            return false;
        }

        var name = Path.GetFileName(target.Replace('\\', '/'));
        var officeBinary = name.Equals("OfficeC2RClient.exe", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("OfficeTelemetryAgent", StringComparison.OrdinalIgnoreCase);
        var inProgramFiles = PathClassifier.Normalize(target).Contains(@"\program files", StringComparison.Ordinal);
        var signature = entry.FileScan?.Signature;
        return officeBinary && inProgramFiles && (signature is null || DeceptiveNameAnalyzer.IsMicrosoftSigned(signature));
    }

    private static bool InFolder(string? path, string folder)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var p = PathClassifier.Normalize(path);
        var f = PathClassifier.Normalize(folder).TrimEnd('\\');
        return p.StartsWith(f + "\\", StringComparison.Ordinal);
    }

    /// <summary>Файлы каталога рекурсивно; точки повторной обработки (junction/symlink) пропускаются.</summary>
    private static IEnumerable<string> EnumerateFolderFiles(string folder)
    {
        if (!Directory.Exists(folder))
        {
            return [];
        }

        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        try
        {
            return Directory.EnumerateFiles(folder, "*", options).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static string SeverityRu(Signatures.Severity severity) => severity switch
    {
        Signatures.Severity.Critical => "критично",
        Signatures.Severity.High => "высокая",
        Signatures.Severity.Medium => "средняя",
        _ => "низкая",
    };

    private static string StatusRu(RemediationStatus status) => status switch
    {
        RemediationStatus.Done => "выполнено",
        RemediationStatus.WouldDo => "будет выполнено",
        RemediationStatus.Skipped => "пропущено",
        RemediationStatus.Blocked => "запрещено защитой",
        _ => "ошибка",
    };
}
