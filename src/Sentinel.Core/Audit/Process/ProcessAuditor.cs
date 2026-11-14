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

    public ProcessAuditReport Audit(IEnumerable<ProcessSnapshot> processes)
    {
        ArgumentNullException.ThrowIfNull(processes);
        var entries = new List<ProcessAuditEntry>();
        foreach (var p in processes)
        {
            entries.Add(AuditOne(p));
        }

        return new ProcessAuditReport(entries);
    }

    private ProcessAuditEntry AuditOne(ProcessSnapshot p)
    {
        var findings = new List<AuditFinding>();

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
            scan = AnalyzeFileSafely(p.ExecutablePath);
            if (scan is not null)
            {
                AppendFileFindings(p, scan, findings);
            }
        }

        return new ProcessAuditEntry(p, findings, scan);
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

    private FileScanResult? AnalyzeFileSafely(string path)
    {
        try
        {
            return _fileAnalyzer!.Analyze(path);
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
