using System.Globalization;
using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.ThreatFamilies;

/// <summary>Роль процесса в цепочке: загрузчик (родитель) останавливается раньше нагрузки, иначе пересоздаст её.</summary>
public enum FamilyProcessRole
{
    Loader,
    Payload,
}

public sealed record FamilyProcess(ProcessSnapshot Process, FamilyProcessRole Role);

/// <summary>Всё, что относится к одной находке семейства: улики и объекты для плейбука нейтрализации.</summary>
public sealed record FamilyArtifacts
{
    /// <summary>Каталоги семейства (<c>C:\ProgramData\CAAService</c>), файлы которых изолируются целиком.</summary>
    public IReadOnlyList<string> Folders { get; init; } = [];

    /// <summary>Отдельные файлы вне каталогов (цели автозапуска, образы процессов).</summary>
    public IReadOnlyList<string> Files { get; init; } = [];

    public IReadOnlyList<PersistenceEntry> Persistence { get; init; } = [];

    public IReadOnlyList<DefenderExclusion> Exclusions { get; init; } = [];

    public IReadOnlyList<FirewallRule> FirewallRules { get; init; } = [];

    /// <summary>Процессы в порядке остановки: загрузчики (родители) первыми.</summary>
    public IReadOnlyList<FamilyProcess> Processes { get; init; } = [];

    public IReadOnlyList<string> Domains { get; init; } = [];

    public IReadOnlyList<string> IpAddresses { get; init; } = [];
}

/// <summary>Итог корреляции: вердикт, серьёзность, обоснование и артефакты.</summary>
public sealed record FamilyDetection
{
    /// <summary>Ключ находки: каталог семейства или путь задачи.</summary>
    public required string Key { get; init; }

    public required Severity Severity { get; init; }

    public required string Verdict { get; init; }

    /// <summary>Известное семейство из каталога или <c>null</c> — «похожее» по поведению.</summary>
    public ThreatFamily? Family { get; init; }

    /// <summary>Сработала связка (файл + Run + исключение Защитника в пределах окна времени).</summary>
    public bool ChainConfirmed { get; init; }

    public IReadOnlyList<string> Signals { get; init; } = [];

    public required FamilyArtifacts Artifacts { get; init; }

    /// <summary>Нейтрализация предлагается только для High/Critical; Medium — повод проверить вручную.</summary>
    public bool Actionable => Severity >= Severity.High;

    public AuditFinding ToFinding() => AuditFinding.Create(
        ChainConfirmed || Family is not null ? "FAM-CHAIN" : "FAM-SIGNAL", Severity, Verdict,
        string.Join("; ", Signals),
        [
            Evidence.Of("key", Key),
            Evidence.Of("family", Family?.Id),
            Evidence.Of("folders", string.Join(" | ", Artifacts.Folders)),
            Evidence.Of("persistence", string.Join(" | ", Artifacts.Persistence.Select(p => $"{p.Location} → {p.Name}"))),
            Evidence.Of("exclusions", string.Join(" | ", Artifacts.Exclusions.Select(e => e.ToString()))),
            Evidence.Of("firewall", string.Join(" | ", Artifacts.FirewallRules.Select(r => r.DisplayName ?? r.Name))),
            Evidence.Of("processes", string.Join(" | ", Artifacts.Processes.Select(p => $"{p.Role}:{p.Process.Pid}:{p.Process.Name}"))),
        ]);
}

/// <summary>Входные данные корреляции — отчёты аудиторов и время событий.</summary>
public sealed record FamilyCorrelationInput
{
    public PersistenceAuditReport? Persistence { get; init; }
    public ConfigAuditReport? Config { get; init; }
    public ProcessAuditReport? Processes { get; init; }

    /// <summary>События 5007 (добавление исключений) из журнала Защитника.</summary>
    public IReadOnlyList<DefenderExclusionChange> DefenderEvents { get; init; } = [];

    /// <summary>Время создания файла (UTC).</summary>
    public Func<string, DateTime?> FileCreationTimeUtc { get; init; } = _ => null;

    /// <summary>Окно «нескольких минут» для связки файл + Run + исключение.</summary>
    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(10);
}

/// <summary>
/// Корреляция находок аудиторов в вердикт «Майнер/загрузчик (семейство CAAService/techias-подобное)». Отдельные признаки
/// (неподписанный exe в ProgramData, Run, исключение Защитника, правило брандмауэра-маскировка) дают среднюю серьёзность;
/// связка «новый неподписанный exe в ProgramData + Run + исключение Защитника на эту папку» в пределах окна времени (время
/// создания файла, изменения ключа Run и события 5007) — высокую; совпадение с IOC известного семейства — критическую.
/// </summary>
public static class ThreatFamilyCorrelator
{
    public const string ChainVerdict = "Майнер/загрузчик (семейство CAAService/techias-подобное)";

    /// <summary>Каталоги ProgramData легитимных поставщиков и самого Sentinel: связка в них не строится.</summary>
    private static readonly HashSet<string> TrustedProgramDataFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "package cache", "sentinel", "windows", "packages", "usoshared", "usoprivate", "ssh", "softwaredistribution",
        "intel", "nvidia", "nvidia corporation", "amd", "apple", "google", "mozilla", "adobe", "oracle", "chocolatey", "regid.1991-06.com.microsoft",
    };

    private static readonly HashSet<string> AutostartIds = new(StringComparer.Ordinal)
    {
        "PERS-RUN-USERWRITABLE-UNSIGNED", "PERS-FILE-UNSIGNED", "PERS-FAMILY-IOC", "PERS-DECEPTIVE-NAME", "PERS-FAKE-MICROSOFT",
    };

    public static IReadOnlyList<FamilyDetection> Correlate(FamilyCorrelationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var persistence = input.Persistence?.Entries ?? [];
        var exclusions = input.Config?.DefenderExclusions ?? [];
        var firewall = input.Config?.MasqueradingFirewallRules ?? [];
        var processes = input.Processes?.Entries ?? [];

        var detections = new List<FamilyDetection>();
        foreach (var folder in CandidateFolders(persistence, processes, firewall, exclusions))
        {
            if (CorrelateFolder(folder, input, persistence, exclusions, firewall, processes) is { } detection)
            {
                detections.Add(detection);
            }
        }

        detections.AddRange(CorrelateTasks(persistence, exclusions, detections));
        return detections.OrderByDescending(d => d.Severity).ThenBy(d => d.Key, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    // ---- Каталоги ProgramData ---------------------------------------------------

    private static IEnumerable<string> CandidateFolders(IReadOnlyList<PersistenceEntry> persistence, IReadOnlyList<ProcessAuditEntry> processes,
        IReadOnlyList<FirewallRule> firewall, IReadOnlyList<DefenderExclusion> exclusions)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in persistence.Where(e => e.HasFindings))
        {
            Add(roots, e.ResolvedTarget);
        }

        foreach (var p in processes.Where(p => p.HasFindings))
        {
            Add(roots, p.Process.ExecutablePath);
        }

        foreach (var r in firewall)
        {
            Add(roots, r.AppPath);
        }

        foreach (var x in exclusions.Where(x => x.Kind == DefenderExclusionKind.Path))
        {
            Add(roots, x.ExpandedValue.TrimEnd('\\') + "\\x");
        }

        return roots.Order(StringComparer.OrdinalIgnoreCase);
    }

    private static void Add(HashSet<string> roots, string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || ProcessAuditor.ProgramDataRoot(path) is not { } root)
        {
            return;
        }

        var folder = root[(root.LastIndexOf('\\') + 1)..];
        if (!TrustedProgramDataFolders.Contains(folder) && !folder.StartsWith("regid.", StringComparison.OrdinalIgnoreCase))
        {
            roots.Add(root);
        }
    }

    private static bool InFolder(string? path, string root) =>
        path is not null && ProcessAuditor.ProgramDataRoot(path) is { } r
        && string.Equals(PathClassifier.Normalize(r), PathClassifier.Normalize(root), StringComparison.Ordinal);

    private static FamilyDetection? CorrelateFolder(string root, FamilyCorrelationInput input, IReadOnlyList<PersistenceEntry> persistence,
        IReadOnlyList<DefenderExclusion> exclusions, IReadOnlyList<FirewallRule> firewall, IReadOnlyList<ProcessAuditEntry> processes)
    {
        var signals = new List<string>();
        var autostart = persistence.Where(e => InFolder(e.ResolvedTarget, root) && e.HasFindings).ToList();
        var runEntries = autostart.Where(e => e.Kind is PersistenceKind.RegistryRun or PersistenceKind.RegistryRunOnce).ToList();
        var unsignedTarget = autostart.FirstOrDefault(e => e.Findings.Any(f => AutostartIds.Contains(f.Id)));
        var folderExclusions = exclusions.Where(x => CoversFolder(x, root)).ToList();
        var folderRules = firewall.Where(r => InFolder(r.AppPath, root)).ToList();
        var folderProcesses = processes.Where(p => InFolder(p.Process.ExecutablePath, root)).ToList();

        var family = autostart.SelectMany(e => e.Findings).Concat(folderProcesses.SelectMany(p => p.Findings))
            .Select(f => f.Evidence.FirstOrDefault(ev => ev.Key == "family")?.Value)
            .Where(v => v is not null and not "<null>")
            .Select(v => ThreatFamilyCatalog.All.FirstOrDefault(f => f.Id == v))
            .FirstOrDefault(f => f is not null)
            ?? ThreatFamilyCatalog.MatchPath(root + "\\x")?.Family;
        var hashHit = autostart.Any(e => e.Findings.Any(f => f.Id.StartsWith("PERS-FILE-SNT-FAM-", StringComparison.Ordinal)))
            || folderProcesses.Any(p => p.Findings.Any(f => f.Id is "PROC-FAMILY-IOC" || f.Id.StartsWith("PROC-FILE-SNT-FAM-", StringComparison.Ordinal)));

        if (unsignedTarget is not null)
        {
            signals.Add($"неподписанный исполняемый файл в {root}, на который ссылается автозапуск ({unsignedTarget.ResolvedTarget})");
        }

        if (runEntries.Count > 0)
        {
            signals.Add("Run-значение: " + string.Join(", ", runEntries.Select(e => $"«{e.Name}»")));
        }

        if (folderExclusions.Count > 0)
        {
            signals.Add("исключение Защитника на папку: " + string.Join(", ", folderExclusions.Select(x => x.Value)));
        }

        if (folderRules.Count > 0)
        {
            signals.Add("правило брандмауэра под системным именем: " + string.Join(", ", folderRules.Select(r => $"«{r.DisplayName ?? r.Name}»")));
        }

        var flaggedProcesses = folderProcesses.Where(p => p.HasFindings).ToList();
        if (flaggedProcesses.Count > 0)
        {
            signals.Add("подозрительные процессы: " + string.Join(", ", flaggedProcesses.SelectMany(p => p.Findings.Select(f => f.Id)).Distinct()));
        }

        if (hashHit)
        {
            signals.Add("совпадение SHA-256 с IOC семейства");
        }

        if (signals.Count == 0)
        {
            return null;
        }

        // Связка: файл + Run + исключение. Время: создание файла, изменение ключа Run, событие 5007 для этой папки.
        var chain = unsignedTarget is not null && runEntries.Count > 0 && folderExclusions.Count > 0;
        if (chain)
        {
            var times = new List<(string What, DateTime Time)>();
            if (unsignedTarget!.ResolvedTarget is { } target && input.FileCreationTimeUtc(target) is { } created)
            {
                times.Add(("создан файл", created));
            }

            foreach (var run in runEntries.Where(r => r.TimestampUtc is not null))
            {
                times.Add(("изменён ключ Run", run.TimestampUtc!.Value));
            }

            foreach (var ev in input.DefenderEvents.Where(e => e.Added && e.Kind == DefenderExclusionKind.Path && CoversFolder(new DefenderExclusion(e.Kind, e.Value, "5007"), root)))
            {
                times.Add(("событие 5007 (исключение добавлено)", ev.TimeUtc));
            }

            if (times.Count >= 2)
            {
                var span = times.Max(t => t.Time) - times.Min(t => t.Time);
                var stamps = string.Join(", ", times.OrderBy(t => t.Time).Select(t => $"{t.What} {t.Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} UTC"));
                if (span <= input.Window)
                {
                    signals.Add($"связка во времени подтверждена: {stamps}");
                }
                else
                {
                    chain = false;
                    signals.Add($"элементы связки разнесены во времени ({span.TotalMinutes:F0} мин > {input.Window.TotalMinutes:F0} мин): {stamps}");
                }
            }
            else
            {
                signals.Add("время создания элементов связки неизвестно — связка засчитана по составу");
            }
        }

        var severity = hashHit || (family is not null && (chain || unsignedTarget is not null)) ? Severity.Critical
            : chain ? Severity.High
            : Severity.Medium;
        var verdict = family is not null && severity >= Severity.High
            ? $"{ChainVerdict}: {family.Name}"
            : severity >= Severity.High ? ChainVerdict : $"Отдельные признаки загрузчика в {root} — нужна проверка";

        return new FamilyDetection
        {
            Key = root,
            Severity = severity,
            Verdict = verdict,
            Family = family,
            ChainConfirmed = chain,
            Signals = signals,
            Artifacts = new FamilyArtifacts
            {
                Folders = [root],
                Files = autostart.Select(e => e.ResolvedTarget).Concat(folderProcesses.Select(p => p.Process.ExecutablePath))
                    .Where(p => p is not null).Select(p => p!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Persistence = autostart,
                Exclusions = folderExclusions,
                FirewallRules = folderRules,
                Processes = OrderProcesses(folderProcesses.Select(p => p.Process).ToList()),
                Domains = family?.Domains ?? [],
                IpAddresses = family?.IpAddresses ?? [],
            },
        };
    }

    /// <summary>Исключение-путь покрывает каталог семейства (сам каталог, файл в нём или шаблон).</summary>
    private static bool CoversFolder(DefenderExclusion exclusion, string root)
    {
        if (exclusion.Kind != DefenderExclusionKind.Path)
        {
            return false;
        }

        var value = PathClassifier.Normalize(exclusion.ExpandedValue).TrimEnd('\\');
        var folder = PathClassifier.Normalize(root);
        return string.Equals(value, folder, StringComparison.Ordinal)
            || value.StartsWith(folder + "\\", StringComparison.Ordinal)
            || exclusion.CoversFile(root + "\\x.exe");
    }

    /// <summary>Родители раньше потомков: загрузчик не успеет пересоздать и перезапустить майнер.</summary>
    internal static IReadOnlyList<FamilyProcess> OrderProcesses(IReadOnlyList<ProcessSnapshot> processes)
    {
        var pids = processes.Select(p => p.Pid).ToHashSet();
        var parentPids = processes.Where(p => pids.Contains(p.ParentPid) && p.ParentPid != p.Pid).Select(p => p.ParentPid).ToHashSet();
        var ordered = new List<FamilyProcess>();
        var visited = new HashSet<int>();

        void Visit(ProcessSnapshot p)
        {
            if (!visited.Add(p.Pid))
            {
                return;
            }

            if (pids.Contains(p.ParentPid) && p.ParentPid != p.Pid)
            {
                Visit(processes.First(x => x.Pid == p.ParentPid));
            }

            ordered.Add(new FamilyProcess(p, parentPids.Contains(p.Pid) ? FamilyProcessRole.Loader : FamilyProcessRole.Payload));
        }

        foreach (var p in processes.OrderBy(p => p.StartTimeUtc ?? DateTime.MaxValue).ThenBy(p => p.Pid))
        {
            Visit(p);
        }

        return ordered;
    }

    // ---- Задачи «скачать и выполнить» (techias) ---------------------------------

    private static IEnumerable<FamilyDetection> CorrelateTasks(IReadOnlyList<PersistenceEntry> persistence, IReadOnlyList<DefenderExclusion> exclusions,
        IReadOnlyList<FamilyDetection> folderDetections)
    {
        var interpreterExclusions = exclusions
            .Where(x => x.Kind == DefenderExclusionKind.Process && InterpreterHeuristics.IsInterpreter(Path.GetFileName(x.ExpandedValue.Replace('\\', '/'))))
            .ToList();
        foreach (var task in persistence.Where(e => e.Kind == PersistenceKind.ScheduledTask))
        {
            var download = task.Findings.FirstOrDefault(f => f.Id == "PERS-TASK-DOWNLOAD-EXEC");
            var familyFinding = task.Findings.FirstOrDefault(f => f.Id == "PERS-FAMILY-IOC");
            if (download is null && familyFinding is null)
            {
                continue;
            }

            var familyId = (download ?? familyFinding)!.Evidence.FirstOrDefault(e => e.Key == "family")?.Value;
            var family = ThreatFamilyCatalog.All.FirstOrDefault(f => f.Id == familyId);
            var signals = new List<string> { (download ?? familyFinding)!.Description };
            if (interpreterExclusions.Count > 0)
            {
                signals.Add("исключение Защитника для интерпретатора: " + string.Join(", ", interpreterExclusions.Select(x => x.Value)));
            }

            var severity = family is not null ? Severity.Critical
                : download is not null && (download.Severity >= Severity.High || interpreterExclusions.Count > 0) ? Severity.High
                : Severity.Medium;
            var urls = download?.Evidence.FirstOrDefault(e => e.Key == "urls")?.Value ?? string.Empty;
            var domains = urls.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(u => Uri.TryCreate(u, UriKind.Absolute, out var uri) ? uri.Host : null)
                .Where(h => !string.IsNullOrEmpty(h)).Select(h => h!)
                .Concat(family?.Domains ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

            // Каталог, который задача создала (WinAIHService), если он найден отдельной связкой того же семейства.
            var related = folderDetections.Where(d => family is not null && d.Family == family).ToList();
            yield return new FamilyDetection
            {
                Key = task.Location,
                Severity = severity,
                Verdict = severity >= Severity.High
                    ? (family is null ? "Загрузчик через задачу-маскировку (techias-подобный)" : $"{ChainVerdict}: {family.Name}")
                    : "Задача скачивает и выполняет код — нужна проверка",
                Family = family,
                ChainConfirmed = severity >= Severity.High,
                Signals = signals,
                Artifacts = new FamilyArtifacts
                {
                    Persistence = [task],
                    Exclusions = severity >= Severity.High ? interpreterExclusions : [],
                    Folders = related.SelectMany(d => d.Artifacts.Folders).ToArray(),
                    Domains = domains,
                    IpAddresses = family?.IpAddresses ?? [],
                },
            };
        }
    }
}
