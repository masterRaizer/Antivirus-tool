using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Remediation;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Reporting;

/// <summary>Итоговый статус действия над находкой.</summary>
public enum FindingActionStatus
{
    /// <summary>Только обнаружено, действий не предпринималось.</summary>
    Detected,

    /// <summary>Предпросмотр (dry-run): действие запланировано, изменений нет.</summary>
    Planned,

    /// <summary>Файл изолирован в карантин.</summary>
    Quarantined,

    /// <summary>Дерево процессов завершено.</summary>
    Terminated,

    /// <summary>Параметр конфигурации/автозагрузки возвращён к эталону.</summary>
    Cleaned,

    /// <summary>Действие запрещено белым списком или защитой системных процессов.</summary>
    Blocked,

    /// <summary>Автоматическое действие не применимо.</summary>
    Skipped,
    Failed,
}

/// <summary>Строка таблицы проверенных областей.</summary>
public sealed record ReportArea(string Name, int Checked, int Found, string? Note = null);

/// <summary>Одна находка отчёта — файл, процесс, точка автозапуска или параметр конфигурации.</summary>
public sealed record ReportFinding
{
    /// <summary>Устойчивый ключ для привязки результата действия (<c>file:…</c>, <c>proc:…</c> и т.п.).</summary>
    public required string Key { get; init; }

    public required string Area { get; init; }
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? Sha256 { get; init; }
    public double? Entropy { get; init; }

    /// <summary>Статус цифровой подписи (например, <c>Valid: CN=…</c>, <c>NotSigned</c>, «не проверялась»).</summary>
    public string SignatureStatus { get; init; } = "не проверялась";

    /// <summary>Сработавшее правило или эвристика.</summary>
    public required string Rule { get; init; }

    public Severity Severity { get; init; }
    public string Description { get; init; } = string.Empty;
    public IReadOnlyList<Evidence> Evidence { get; init; } = [];
    public FindingActionStatus ActionStatus { get; init; } = FindingActionStatus.Detected;
    public string? ActionMessage { get; init; }
}

/// <summary>Полный отчёт: сводка, проверенные области, находки и журнал действий.</summary>
public sealed record SentinelReport
{
    public string Title { get; init; } = "Sentinel — отчёт аудита";
    public string Product { get; init; } = "Sentinel";
    public required string Command { get; init; }
    public string Host { get; init; } = Environment.MachineName;
    public DateTime StartedAtUtc { get; init; }
    public TimeSpan Duration { get; init; }

    /// <summary>Режим: только аудит, предпросмотр нейтрализации или нейтрализация.</summary>
    public string Mode { get; init; } = "audit";

    public IReadOnlyList<ReportArea> Areas { get; init; } = [];
    public IReadOnlyList<ReportFinding> Findings { get; init; } = [];
    public IReadOnlyList<RemediationAction> Actions { get; init; } = [];

    public int TotalChecked => Areas.Sum(a => a.Checked);
    public int Found => Findings.Count;
    public int Quarantined => Findings.Count(f => f.ActionStatus == FindingActionStatus.Quarantined);
    public int ConfigCleaned => Findings.Count(f => f.ActionStatus == FindingActionStatus.Cleaned);
    public int ProcessesTerminated => Findings.Count(f => f.ActionStatus == FindingActionStatus.Terminated);
}

/// <summary>
/// Сборщик отчёта: принимает результаты сканирования и аудиторов, приводит их к единому виду
/// и позволяет отметить итог действия над каждой находкой.
/// </summary>
public sealed class ReportBuilder
{
    private readonly List<ReportArea> _areas = [];
    private readonly List<ReportFinding> _findings = [];
    private readonly List<RemediationAction> _actions = [];
    private readonly string _command;
    private readonly DateTime _startedAtUtc;

    public ReportBuilder(string command, DateTime? startedAtUtc = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(command);
        _command = command;
        _startedAtUtc = startedAtUtc ?? DateTime.UtcNow;
    }

    public IReadOnlyList<ReportFinding> Findings => _findings;

    public static string FileKey(string path) => "file:" + path;

    public static string ProcessKey(int pid) => "proc:" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public static string PersistenceKey(PersistenceEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return $"pers:{entry.Kind}|{entry.Location}|{entry.Name}";
    }

    public static string ExclusionKey(DefenderExclusion exclusion)
    {
        ArgumentNullException.ThrowIfNull(exclusion);
        return $"excl:{exclusion.SourceKey}|{exclusion.Value}";
    }

    public ReportBuilder AddArea(string name, int checkedCount, int found, string? note = null)
    {
        _areas.Add(new ReportArea(name, checkedCount, found, note));
        return this;
    }

    /// <summary>Результаты файлового сканирования: в находки попадают только угрозы и подозрения.</summary>
    public ReportBuilder AddFileScan(string areaName, IReadOnlyCollection<FileScanResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        var added = 0;
        foreach (var r in results.Where(r => r.Verdict is Verdict.Malicious or Verdict.Suspicious))
        {
            if (AddFileFinding(areaName, r))
            {
                added++;
            }
        }

        var errors = results.Count(r => r.Verdict == Verdict.Error);
        return AddArea(areaName, results.Count, added, errors > 0 ? $"ошибок чтения: {errors}" : null);
    }

    /// <summary>
    /// Гарантирует, что файл представлен отдельной находкой (например, образ завершённого процесса),
    /// чтобы итог его изоляции попал в отчёт. Чистые файлы не добавляются.
    /// </summary>
    public bool EnsureFileFinding(string areaName, FileScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.Detections.Count > 0 && AddFileFinding(areaName, result);
    }

    private bool AddFileFinding(string areaName, FileScanResult r)
    {
        var key = FileKey(r.Path);
        if (_findings.Any(f => f.Key == key))
        {
            return false; // файл уже учтён (например, найден и сканированием, и через исключение)
        }

        var top = r.Detections.OrderByDescending(d => d.Severity).First();
        _findings.Add(new ReportFinding
        {
            Key = key,
            Area = areaName,
            Name = FileNameOf(r.Path),
            Path = r.Path,
            Sha256 = r.Sha256,
            Entropy = r.Entropy,
            SignatureStatus = DescribeSignature(r),
            Rule = string.Join("; ", r.Detections.Select(d => d.RuleId is null ? d.Name : $"{d.Name} [{d.RuleId}]")),
            Severity = top.Severity,
            Description = string.Join(" ", r.Detections.Select(d => d.Description))
                + (r.PriorityReason is null ? string.Empty : $" Приоритетная глубокая проверка: {r.PriorityReason}."),
            Evidence =
            [
                Audit.Evidence.Of("verdict", r.Verdict.ToString()),
                Audit.Evidence.Of("size", r.Size.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ],
        });
        return true;
    }

    public ReportBuilder AddProcessAudit(ProcessAuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        foreach (var e in report.Flagged)
        {
            AddProcessFinding(e, "Процессы");
        }

        return AddArea("Процессы", report.ProcessCount, report.FlaggedCount);
    }

    /// <summary>Добавляет находку по одному процессу (если у него есть находки и он ещё не учтён).</summary>
    public bool AddProcessFinding(ProcessAuditEntry entry, string areaName)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var key = ProcessKey(entry.Process.Pid);
        if (!entry.HasFindings || _findings.Any(f => f.Key == key))
        {
            return false;
        }

        _findings.Add(new ReportFinding
        {
            Key = key,
            Area = areaName,
            Name = $"{entry.Process.Name} (PID {entry.Process.Pid})",
            Path = entry.Process.ExecutablePath,
            Sha256 = entry.FileScan?.Sha256,
            Entropy = entry.FileScan?.Entropy,
            SignatureStatus = entry.FileScan is null ? "не проверялась" : DescribeSignature(entry.FileScan),
            Rule = string.Join("; ", entry.Findings.Select(f => f.Id).Distinct()),
            Severity = entry.Findings.Max(f => f.Severity),
            Description = string.Join(" ", entry.Findings.Select(f => f.Description)),
            Evidence = entry.Findings.SelectMany(f => f.Evidence).Distinct().ToArray(),
        });
        return true;
    }

    public ReportBuilder AddPersistenceAudit(PersistenceAuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        foreach (var e in report.Flagged)
        {
            _findings.Add(new ReportFinding
            {
                Key = PersistenceKey(e),
                Area = "Автозагрузка",
                Name = $"{e.Name} [{e.Kind}]",
                Path = e.ResolvedTarget ?? e.Location,
                Sha256 = e.FileScan?.Sha256,
                Entropy = e.FileScan?.Entropy,
                SignatureStatus = e.FileScan is null ? "не проверялась" : DescribeSignature(e.FileScan),
                Rule = string.Join("; ", e.Findings.Select(f => f.Id).Distinct()),
                Severity = e.MaxSeverity,
                Description = string.Join(" ", e.Findings.Select(f => f.Description)),
                Evidence =
                [
                    Audit.Evidence.Of("location", e.Location),
                    Audit.Evidence.Of("command", e.Command),
                    .. e.Findings.SelectMany(f => f.Evidence).Distinct(),
                ],
            });
        }

        return AddArea("Автозагрузка", report.Count, report.FlaggedCount);
    }

    public ReportBuilder AddConfigAudit(ConfigAuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var exclusionIndex = 0;
        foreach (var f in report.Findings)
        {
            string key;
            string name;
            if (f.Area == ConfigArea.DefenderExclusion && exclusionIndex < report.DefenderExclusions.Count)
            {
                // Находки об исключениях создаются в том же порядке, что и сами исключения.
                var exclusion = report.DefenderExclusions[exclusionIndex++];
                key = ExclusionKey(exclusion);
                name = exclusion.ToString();
            }
            else
            {
                key = $"cfg:{f.Area}|{_findings.Count}";
                name = f.Finding.Title;
            }

            _findings.Add(new ReportFinding
            {
                Key = key,
                Area = "Конфигурация",
                Name = name,
                Path = f.Finding.Evidence.FirstOrDefault(e => e.Key is "key" or "app")?.Value,
                Rule = f.Finding.Id,
                Severity = f.Severity,
                Description = f.Finding.Description,
                Evidence = f.Finding.Evidence,
            });
        }

        return AddArea("Конфигурация безопасности", report.Count, report.Count,
            report.DefenderExclusions.Count > 0 ? $"исключений Defender: {report.DefenderExclusions.Count}" : null);
    }

    /// <summary>Файлы, найденные приоритетной проверкой исключений Defender.</summary>
    public ReportBuilder AddExclusionScan(ExclusionScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        const string Area = "Файлы под исключениями Defender";
        var added = 0;
        foreach (var file in report.FlaggedFiles.DistinctBy(f => f.Path))
        {
            if (AddFileFinding(Area, file))
            {
                added++;
            }
        }

        var truncated = report.Entries.Count(e => e.Truncated);
        return AddArea(Area, report.FilesScanned, added, truncated > 0 ? $"исключений с усечённым обходом: {truncated}" : null);
    }

    /// <summary>Отмечает итог действия над находкой. Возвращает <c>false</c>, если находки с таким ключом нет.</summary>
    public bool SetAction(string key, FindingActionStatus status, string? message)
    {
        var index = _findings.FindIndex(f => f.Key == key);
        if (index < 0)
        {
            return false;
        }

        _findings[index] = _findings[index] with { ActionStatus = status, ActionMessage = message };
        return true;
    }

    public bool SetAction(string key, RemediationAction action, FindingActionStatus doneStatus)
    {
        ArgumentNullException.ThrowIfNull(action);
        _actions.Add(action);
        return SetAction(key, Map(action.Status, doneStatus), action.Message);
    }

    public bool SetAction(string key, QuarantineResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var status = result.Status switch
        {
            QuarantineStatus.Quarantined => FindingActionStatus.Quarantined,
            QuarantineStatus.WouldQuarantine => FindingActionStatus.Planned,
            QuarantineStatus.BlockedByWhitelist => FindingActionStatus.Blocked,
            QuarantineStatus.NotFound => FindingActionStatus.Skipped,
            _ => FindingActionStatus.Failed,
        };
        var message = result.Record is null ? result.Message : $"{result.Message} (запись карантина {result.Record.Id})";
        return SetAction(key, status, message);
    }

    public static FindingActionStatus Map(RemediationStatus status, FindingActionStatus doneStatus) => status switch
    {
        RemediationStatus.Done => doneStatus,
        RemediationStatus.WouldDo => FindingActionStatus.Planned,
        RemediationStatus.Blocked => FindingActionStatus.Blocked,
        RemediationStatus.Skipped => FindingActionStatus.Skipped,
        _ => FindingActionStatus.Failed,
    };

    public SentinelReport Build(TimeSpan duration, string mode = "audit") => new()
    {
        Command = _command,
        StartedAtUtc = _startedAtUtc,
        Duration = duration,
        Mode = mode,
        Areas = _areas.ToArray(),
        Findings = _findings.OrderByDescending(f => f.Severity).ToArray(),
        Actions = _actions.ToArray(),
    };

    /// <summary>Имя файла из пути с любыми разделителями (отчёт может строиться не на той ОС, где шёл аудит).</summary>
    private static string FileNameOf(string path)
    {
        var idx = path.LastIndexOfAny(['\\', '/']);
        return idx < 0 || idx == path.Length - 1 ? path : path[(idx + 1)..];
    }

    public static string DescribeSignature(FileScanResult r)
    {
        if (r.Signature is null)
        {
            return "не проверялась (не PE)";
        }

        var s = r.Signature;
        return s.IsValid
            ? $"Valid ({s.Source}): {s.SignerSubject}"
            : $"{s.Status}{(string.IsNullOrEmpty(s.Message) ? string.Empty : " — " + s.Message)}";
    }
}
