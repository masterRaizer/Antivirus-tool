using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;

namespace Sentinel.Core.Audit.Config;

public sealed class ExclusionScanOptions
{
    /// <summary>Максимум файлов, проверяемых внутри одного исключённого каталога.</summary>
    public int MaxFilesPerExclusion { get; init; } = 10_000;

    /// <summary>Обходить вложенные каталоги исключённого пути.</summary>
    public bool Recurse { get; init; } = true;
}

/// <summary>Результат приоритетной проверки одного исключения.</summary>
public sealed record ExclusionScanEntry(
    DefenderExclusion Exclusion,
    IReadOnlyList<FileScanResult> Files,
    IReadOnlyList<ProcessAuditEntry> Processes)
{
    /// <summary>Достигнут лимит <see cref="ExclusionScanOptions.MaxFilesPerExclusion"/> — проверены не все файлы.</summary>
    public bool Truncated { get; init; }

    /// <summary>Пояснение, если исключение нельзя сопоставить с файлами (шаблон, отсутствующий путь и т.п.).</summary>
    public string? Note { get; init; }

    public IEnumerable<FileScanResult> FlaggedFiles =>
        Files.Where(f => f.Verdict is Verdict.Malicious or Verdict.Suspicious);
}

/// <summary>Итог связной проверки исключений: что именно скрыто от встроенной защиты и что там найдено.</summary>
public sealed record ExclusionScanReport(IReadOnlyList<ExclusionScanEntry> Entries, ProcessAuditReport Processes)
{
    public int FilesScanned => Entries.Sum(e => e.Files.Count);

    public IEnumerable<FileScanResult> FlaggedFiles => Entries.SelectMany(e => e.FlaggedFiles);

    /// <summary>Процессы, попавшие под исключения (все они получают как минимум PROC-DEFENDER-EXCLUDED).</summary>
    public IEnumerable<ProcessAuditEntry> ExcludedProcesses => Processes.Entries.Where(e => e.MatchedExclusions.Count > 0);
}

/// <summary>
/// Связная проверка исключений конфигурации: всё, что исключено из встроенной защиты Windows
/// (<c>ExclusionPath</c>, <c>ExclusionProcess</c>), автоматически передаётся в
/// <see cref="FileAnalyzer"/> и <see cref="ProcessAuditor"/> для приоритетной глубокой проверки.
/// Исключения никогда не трактуются как признак доверия — наоборот, это первые кандидаты на проверку.
/// Сканер только читает файлы.
/// </summary>
public sealed class ExclusionPriorityScanner
{
    private readonly FileAnalyzer _analyzer;
    private readonly ProcessAuditor _processAuditor;
    private readonly ExclusionScanOptions _options;

    public ExclusionPriorityScanner(FileAnalyzer analyzer, ProcessAuditor processAuditor, ExclusionScanOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(analyzer);
        ArgumentNullException.ThrowIfNull(processAuditor);
        _analyzer = analyzer;
        _processAuditor = processAuditor;
        _options = options ?? new ExclusionScanOptions();
    }

    /// <param name="exclusions">Исключения из <see cref="ConfigAuditReport.DefenderExclusions"/>.</param>
    /// <param name="processes">Снимок активных процессов (пустой список — проверяются только файлы).</param>
    public ExclusionScanReport Scan(IReadOnlyList<DefenderExclusion> exclusions, IReadOnlyList<ProcessSnapshot> processes)
    {
        ArgumentNullException.ThrowIfNull(exclusions);
        ArgumentNullException.ThrowIfNull(processes);

        var processReport = _processAuditor.Audit(processes, exclusions);
        var scanned = new Dictionary<string, FileScanResult>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<ExclusionScanEntry>();

        foreach (var exclusion in exclusions)
        {
            var matchedProcesses = processReport.Entries.Where(e => e.MatchedExclusions.Contains(exclusion)).ToArray();
            var context = new PriorityScanContext(exclusion.ToString());
            var files = new List<FileScanResult>();
            var truncated = false;
            string? note = null;

            switch (exclusion.Kind)
            {
                case DefenderExclusionKind.Path:
                    (truncated, note) = ScanPath(exclusion, context, scanned, files);
                    break;

                case DefenderExclusionKind.Process:
                    note = ScanProcessImage(exclusion, context, scanned, files);
                    break;

                default:
                    note = "Исключение не указывает на конкретные файлы; подлежит удалению как нештатное.";
                    break;
            }

            // Образы работающих процессов, подпавших под исключение, тоже относятся к его области.
            foreach (var p in matchedProcesses)
            {
                if (p.FileScan is { } scan && files.All(f => !string.Equals(f.Path, scan.Path, StringComparison.OrdinalIgnoreCase)))
                {
                    files.Add(scan);
                }
            }

            entries.Add(new ExclusionScanEntry(exclusion, files, matchedProcesses) { Truncated = truncated, Note = note });
        }

        return new ExclusionScanReport(entries, processReport);
    }

    private (bool Truncated, string? Note) ScanPath(
        DefenderExclusion exclusion, PriorityScanContext context, Dictionary<string, FileScanResult> scanned, List<FileScanResult> files)
    {
        var target = exclusion.ExpandedValue;
        if (exclusion.HasWildcard)
        {
            // Шаблон раскрывается от ближайшего каталога без подстановочных знаков.
            var root = WildcardFreeRoot(target);
            if (root is null || !Directory.Exists(root))
            {
                return (false, "Шаблон исключения не удалось сопоставить с существующим каталогом.");
            }

            return (EnumerateInto(root, exclusion, context, scanned, files, filter: true), null);
        }

        if (File.Exists(target))
        {
            files.Add(AnalyzeOnce(target, context, scanned));
            return (false, null);
        }

        if (Directory.Exists(target))
        {
            return (EnumerateInto(target, exclusion, context, scanned, files, filter: false), null);
        }

        return (false, "Исключённый путь не существует — «спящее» исключение, подготовленное для будущего файла.");
    }

    private string? ScanProcessImage(
        DefenderExclusion exclusion, PriorityScanContext context, Dictionary<string, FileScanResult> scanned, List<FileScanResult> files)
    {
        if (exclusion.IsBareProcessName)
        {
            return "Исключение задано только именем образа: под него попадает любой файл с таким именем; проверены работающие процессы.";
        }

        if (exclusion.HasWildcard)
        {
            return "Исключение процесса задано шаблоном; проверены работающие процессы, подпадающие под него.";
        }

        var target = exclusion.ExpandedValue;
        if (!File.Exists(target))
        {
            return "Образ исключённого процесса отсутствует на диске.";
        }

        files.Add(AnalyzeOnce(target, context, scanned));
        return null;
    }

    private bool EnumerateInto(
        string root, DefenderExclusion exclusion, PriorityScanContext context,
        Dictionary<string, FileScanResult> scanned, List<FileScanResult> files, bool filter)
    {
        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = _options.Recurse,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint, // не следуем по junction/symlink — защита от циклов
            ReturnSpecialDirectories = false,
        };

        foreach (var file in Directory.EnumerateFiles(root, "*", enumeration))
        {
            if (filter && !exclusion.CoversFile(file))
            {
                continue;
            }

            if (files.Count >= _options.MaxFilesPerExclusion)
            {
                return true;
            }

            files.Add(AnalyzeOnce(file, context, scanned));
        }

        return false;
    }

    private FileScanResult AnalyzeOnce(string path, PriorityScanContext context, Dictionary<string, FileScanResult> scanned)
    {
        var full = Path.GetFullPath(path);
        if (!scanned.TryGetValue(full, out var result))
        {
            result = _analyzer.Analyze(full, context);
            scanned[full] = result;
        }

        return result;
    }

    private static string? WildcardFreeRoot(string pattern)
    {
        var idx = pattern.IndexOfAny(['*', '?']);
        var sep = pattern.LastIndexOfAny(['\\', '/'], idx);
        return sep <= 0 ? null : pattern[..sep];
    }
}
