using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit.Process;

public sealed class ProcessAuditorOptions
{
    /// <summary>Политика штатного расположения системных процессов.</summary>
    public SystemProcessPolicy SystemPolicy { get; init; } = SystemProcessPolicy.CreateDefault();

    /// <summary>Порог «аномально высокой» загрузки CPU в процентах.</summary>
    public double HighCpuPercent { get; init; } = 90.0;

    /// <summary>Порог «аномально высокой» загрузки GPU в процентах.</summary>
    public double HighGpuPercent { get; init; } = 90.0;

    /// <summary>Анализировать исполняемый файл процесса через <see cref="FileAnalyzer"/>, если он задан.</summary>
    public bool AnalyzeExecutable { get; init; } = true;

    /// <summary>
    /// Потоковый аудит памяти процесса (RWX-регионы, PE-образы без файла, сигнатуры в памяти); <c>null</c> — память не читается.
    /// Защищённые процессы сканер отсекает сам через <c>CriticalProcessGuard</c> до открытия дескриптора.
    /// </summary>
    public Auditors.Memory.MemoryIntegrityScanner? MemoryScanner { get; init; }
}

/// <summary>
/// Аудитор активных процессов. Сам по себе платформонезависим: принимает снимки процессов
/// (<see cref="ProcessSnapshot"/>) от любого поставщика и применяет к ним эвристики и
/// (опционально) анализ исполняемого файла. Благодаря этому тестируется в Linux на моках.
/// </summary>
public sealed class ProcessAuditor
{
    private readonly ProcessAuditorOptions _options;
    private readonly FileAnalyzer? _fileAnalyzer;

    public ProcessAuditor(ProcessAuditorOptions? options = null, FileAnalyzer? fileAnalyzer = null)
    {
        _options = options ?? new ProcessAuditorOptions();
        _fileAnalyzer = fileAnalyzer;
    }

    public ProcessAuditReport Audit(IEnumerable<ProcessSnapshot> processes) => Audit(processes, []);

    /// <summary>
    /// Аудит с учётом исключений встроенной защиты Windows. Процессы, попавшие под
    /// <c>ExclusionProcess</c> или запущенные из <c>ExclusionPath</c>, проверяются первыми,
    /// получают находку <c>PROC-DEFENDER-EXCLUDED</c>, а их образ — глубокую проверку файла.
    /// </summary>
    public ProcessAuditReport Audit(IEnumerable<ProcessSnapshot> processes, IReadOnlyList<DefenderExclusion> exclusions)
    {
        ArgumentNullException.ThrowIfNull(processes);
        ArgumentNullException.ThrowIfNull(exclusions);

        var prioritized = new List<ProcessAuditEntry>();
        var regular = new List<ProcessSnapshot>();
        foreach (var p in processes)
        {
            var matched = MatchExclusions(p, exclusions);
            if (matched.Count > 0)
            {
                prioritized.Add(AuditOne(p, matched));
            }
            else
            {
                regular.Add(p);
            }
        }

        var entries = new List<ProcessAuditEntry>(prioritized);
        foreach (var p in regular)
        {
            entries.Add(AuditOne(p, []));
        }

        return new ProcessAuditReport(entries);
    }

    /// <summary>Исключения, под которые попадает процесс (по образу или по каталогу запуска).</summary>
    public static IReadOnlyList<DefenderExclusion> MatchExclusions(ProcessSnapshot process, IReadOnlyList<DefenderExclusion> exclusions)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(exclusions);
        var matched = new List<DefenderExclusion>();
        foreach (var e in exclusions)
        {
            var hit = e.Kind switch
            {
                DefenderExclusionKind.Process => e.CoversProcess(process.Name, process.ExecutablePath),
                DefenderExclusionKind.Path => e.CoversFile(process.ExecutablePath),
                _ => false,
            };
            if (hit)
            {
                matched.Add(e);
            }
        }

        return matched;
    }

    private ProcessAuditEntry AuditOne(ProcessSnapshot p, IReadOnlyList<DefenderExclusion> matched)
    {
        var findings = new List<AuditFinding>();
        var priority = matched.Count > 0
            ? new PriorityScanContext(string.Join("; ", matched.Select(m => m.ToString())))
            : null;

        if (priority is not null)
        {
            var interpreter = InterpreterHeuristics.IsInterpreter(p.Name);
            var userWritable = p.ExecutablePath is not null && PathClassifier.IsUserWritableLocation(p.ExecutablePath);
            findings.Add(AuditFinding.Create("PROC-DEFENDER-EXCLUDED",
                interpreter || userWritable ? Severity.High : Severity.Medium,
                "Процесс скрыт от встроенной защиты исключением",
                $"Процесс '{p.Name}' подпадает под исключение встроенной защиты Windows ({priority.Reason})"
                    + (interpreter ? " и является интерпретатором — его действия и открываемые файлы не проверяются." : ".")
                    + " Образ процесса проверен в приоритетном глубоком режиме.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", p.Name),
                Evidence.Of("path", p.ExecutablePath),
                Evidence.Of("exclusions", priority.Reason)));
        }

        CheckSystemImpersonation(p, findings);
        CheckHomoglyphs(p, findings);

        if (InterpreterHeuristics.IsInterpreter(p.Name))
        {
            findings.AddRange(InterpreterHeuristics.Analyze(p.Name, p.CommandLine));
        }

        CheckResourceUsage(p, findings);

        FileScanResult? scan = null;
        if (_options.AnalyzeExecutable && _fileAnalyzer is not null && !string.IsNullOrWhiteSpace(p.ExecutablePath))
        {
            scan = AnalyzeFileSafely(p.ExecutablePath, priority);
            if (scan is not null)
            {
                AppendFileFindings(p, scan, findings);
            }
        }

        Auditors.Memory.MemoryScanResult? memory = null;
        if (_options.MemoryScanner is { } memoryScanner && p.Pid > 0)
        {
            memory = memoryScanner.Scan(p.Pid, p.Name, p.ExecutablePath);
            findings.AddRange(memory.ToFindings(p.Name, p.ExecutablePath));
        }

        return new ProcessAuditEntry(p, findings, scan) { MatchedExclusions = matched, MemoryScan = memory };
    }

    private void CheckSystemImpersonation(ProcessSnapshot p, List<AuditFinding> findings)
    {
        var inAllowed = _options.SystemPolicy.IsInAllowedLocation(p.Name, p.ExecutablePath);
        if (inAllowed == false)
        {
            var allowed = string.Join(", ", _options.SystemPolicy.AllowedDirectories(p.Name));
            findings.Add(AuditFinding.Create("PROC-IMPERSONATION", Severity.High,
                "Системное имя вне штатного каталога",
                $"Процесс с именем системного компонента '{p.Name}' запущен вне допустимых каталогов — признак маскировки.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("path", p.ExecutablePath),
                Evidence.Of("allowed", allowed)));
        }
    }

    private static void CheckHomoglyphs(ProcessSnapshot p, List<AuditFinding> findings)
    {
        var name = p.Name;
        if (string.IsNullOrEmpty(name))
        {
            return;
        }

        var fold = ConfusableFolder.Fold(name);

        // Скелет совпал с известным системным именем, но само имя отличается — явная подмена символов.
        if (fold.Changed && KnownSkeletons.Contains(fold.Skeleton) && !KnownSkeletons.Contains(fold.Lowered))
        {
            findings.Add(AuditFinding.Create("PROC-HOMOGLYPH", Severity.Critical,
                "Подмена символов в имени процесса",
                $"Имя процесса '{name}' визуально имитирует системный процесс '{fold.Skeleton}' за счёт обманчивых символов.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", name),
                Evidence.Of("skeleton", fold.Skeleton),
                Evidence.Of("path", p.ExecutablePath)));
            return;
        }

        if (ConfusableFolder.ContainsNonLatinLetters(name))
        {
            findings.Add(AuditFinding.Create("PROC-NONLATIN", Severity.Medium,
                "Не-латинские символы в имени процесса",
                $"Имя процесса '{name}' содержит не-латинские буквы — нетипично для исполняемых файлов Windows.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", name),
                Evidence.Of("path", p.ExecutablePath)));
        }
    }

    private void CheckResourceUsage(ProcessSnapshot p, List<AuditFinding> findings)
    {
        if (p.CpuKnown && p.CpuPercent >= _options.HighCpuPercent)
        {
            findings.Add(AuditFinding.Create("PROC-HIGH-CPU", Severity.Low,
                "Аномально высокая загрузка CPU",
                $"Процесс потребляет {p.CpuPercent:F1}% CPU (порог {_options.HighCpuPercent:F0}%) — возможен майнер или зависший цикл.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", p.Name),
                Evidence.Of("cpu", $"{p.CpuPercent:F1}%")));
        }

        if (p.GpuKnown && p.GpuPercent >= _options.HighGpuPercent)
        {
            findings.Add(AuditFinding.Create("PROC-HIGH-GPU", Severity.Low,
                "Аномально высокая загрузка GPU",
                $"Процесс потребляет {p.GpuPercent:F1}% GPU (порог {_options.HighGpuPercent:F0}%) — характерно для GPU-майнеров.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", p.Name),
                Evidence.Of("gpu", $"{p.GpuPercent:F1}%")));
        }
    }

    private static void AppendFileFindings(ProcessSnapshot p, FileScanResult scan, List<AuditFinding> findings)
    {
        if (scan.Verdict is Verdict.Trusted or Verdict.Clean)
        {
            return;
        }

        foreach (var d in scan.Detections)
        {
            findings.Add(AuditFinding.Create("PROC-FILE-" + (d.RuleId ?? d.Source.ToString().ToUpperInvariant()),
                d.Severity,
                $"Детект в исполняемом файле процесса: {d.Name}",
                d.Description,
                Evidence.Of("pid", p.Pid),
                Evidence.Of("path", scan.Path),
                Evidence.Of("source", d.Source.ToString()),
                Evidence.Of("verdict", scan.Verdict.ToString())));
        }
    }

    /// <summary>
    /// Один и тот же образ (svchost.exe ×80, chrome.exe ×30) за прогон анализируется один раз: без этого проверка процессов
    /// перечитывала и хешировала одни и те же файлы сотни раз. Приоритетная (под исключением Defender) проверка не кэшируется.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Lazy<FileScanResult?>> _scanMemo = new(StringComparer.OrdinalIgnoreCase);

    private FileScanResult? AnalyzeFileSafely(string path, PriorityScanContext? priority)
    {
        if (priority is null)
        {
            return _scanMemo.GetOrAdd(path, p => new Lazy<FileScanResult?>(() => AnalyzeFileCore(p, null))).Value;
        }

        return AnalyzeFileCore(path, priority);
    }

    private FileScanResult? AnalyzeFileCore(string path, PriorityScanContext? priority)
    {
        try
        {
            return _fileAnalyzer!.Analyze(path, priority);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Скелеты известных системных имён для сопоставления при подмене символов.</summary>
    private static readonly HashSet<string> KnownSkeletons = BuildKnownSkeletons();

    private static HashSet<string> BuildKnownSkeletons()
    {
        string[] names =
        [
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
            "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "taskhostw.exe",
            "spoolsv.exe", "conhost.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
            "runtimebroker.exe", "searchindexer.exe", "dllhost.exe", "explorer.exe",
        ];
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var n in names)
        {
            set.Add(ConfusableFolder.Fold(n).Skeleton);
        }

        return set;
    }
}
