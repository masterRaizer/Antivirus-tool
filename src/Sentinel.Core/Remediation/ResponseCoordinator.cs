using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Remediation;

public sealed class ResponsePolicy
{
    /// <summary>Файл изолируется, если его вердикт — угроза/подозрение и есть детект не ниже этого уровня.</summary>
    public Severity QuarantineThreshold { get; init; } = Severity.Medium;

    /// <summary>Дерево процесса завершается при находке не ниже этого уровня.</summary>
    public Severity TerminateThreshold { get; init; } = Severity.High;

    /// <summary>Точка автозапуска откатывается при находке не ниже этого уровня.</summary>
    public Severity RollbackThreshold { get; init; } = Severity.Medium;

    /// <summary>Предпросмотр: действия только планируются.</summary>
    public bool DryRun { get; init; }
}

/// <summary>
/// Связывает результаты обнаружения с действиями и отчётом: «процесс → файл → конфигурация».
/// Порядок важен: сначала останавливаются процессы (иначе их образы заблокированы и могут
/// восстановить автозапуск), затем файлы уходят в карантин, затем откатываются параметры.
/// Каждый итог фиксируется в <see cref="ReportBuilder"/>.
/// </summary>
public sealed class ResponseCoordinator
{
    private readonly QuarantineManager _quarantine;
    private readonly RemediationEngine? _engine;
    private readonly ReportBuilder _report;
    private readonly ResponsePolicy _policy;
    private readonly HashSet<string> _handledFiles = new(StringComparer.OrdinalIgnoreCase);

    public ResponseCoordinator(QuarantineManager quarantine, RemediationEngine? engine, ReportBuilder report, ResponsePolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(quarantine);
        ArgumentNullException.ThrowIfNull(report);
        _quarantine = quarantine;
        _engine = engine;
        _report = report;
        _policy = policy ?? new ResponsePolicy { DryRun = engine?.DryRun ?? false };
        if (engine is not null && engine.DryRun != _policy.DryRun)
        {
            throw new ArgumentException("Режим dry-run политики и движка нейтрализации должен совпадать.", nameof(policy));
        }
    }

    /// <summary>Изолирует файлы с вердиктом «угроза»/«подозрение» (с учётом порога критичности).</summary>
    public async Task<IReadOnlyList<QuarantineResult>> HandleFilesAsync(
        IEnumerable<FileScanResult> results, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(results);
        var outcomes = new List<QuarantineResult>();
        foreach (var r in results)
        {
            if (!ShouldQuarantine(r) || !_handledFiles.Add(r.Path))
            {
                continue;
            }

            var reason = string.Join("; ", r.Detections.Select(d => d.RuleId is null ? d.Name : $"{d.Name} [{d.RuleId}]"));
            var outcome = await _quarantine.QuarantineAsync(r.Path, reason, _policy.DryRun, cancellationToken).ConfigureAwait(false);
            outcomes.Add(outcome);
            _report.SetAction(ReportBuilder.FileKey(r.Path), outcome);
        }

        return outcomes;
    }

    /// <summary>Завершает деревья опасных процессов и изолирует их образы.</summary>
    public Task HandleProcessesAsync(ProcessAuditReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        return HandleProcessesAsync(report.Flagged, cancellationToken);
    }

    private async Task HandleProcessesAsync(IEnumerable<ProcessAuditEntry> entries, CancellationToken cancellationToken)
    {
        foreach (var entry in entries.Where(e => e.HasFindings))
        {
            if (entry.Findings.Max(f => f.Severity) < _policy.TerminateThreshold)
            {
                continue;
            }

            var key = ReportBuilder.ProcessKey(entry.Process.Pid);
            if (_engine is null)
            {
                _report.SetAction(key, FindingActionStatus.Skipped, "Завершение процессов недоступно на этой платформе.");
                continue;
            }

            var tree = _engine.TerminateProcessTree(entry.Process.Pid);
            _report.SetAction(key, tree.ToAction(), FindingActionStatus.Terminated);

            // Образ изолируется только когда процесс действительно остановлен (или в предпросмотре).
            if (tree.Status is RemediationStatus.Done or RemediationStatus.WouldDo && entry.FileScan is { } scan && ShouldQuarantine(scan)
                && _handledFiles.Add(scan.Path))
            {
                var reason = string.Join("; ", entry.Findings.Select(f => f.Id).Distinct());
                var outcome = await _quarantine.QuarantineAsync(scan.Path, reason, _policy.DryRun, cancellationToken).ConfigureAwait(false);
                _report.EnsureFileFinding("Образы процессов", scan);
                _report.SetAction(ReportBuilder.FileKey(scan.Path), outcome);
            }
        }
    }

    /// <summary>Откатывает нештатные точки автозапуска и изолирует их вредоносные цели.</summary>
    public async Task HandlePersistenceAsync(PersistenceAuditReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        var targets = report.Flagged.Where(e => e.MaxSeverity >= _policy.RollbackThreshold).ToArray();

        // Сначала параметры (чтобы запись не запустила файл повторно), затем сами файлы.
        if (_engine is not null)
        {
            var hosts = targets.Where(t => t.Kind == PersistenceKind.HostsFile).ToArray();
            foreach (var entry in targets.Where(t => t.Kind != PersistenceKind.HostsFile))
            {
                _report.SetAction(ReportBuilder.PersistenceKey(entry), _engine.RollbackPersistence(entry), FindingActionStatus.Cleaned);
            }

            foreach (var group in hosts.GroupBy(h => h.Location, StringComparer.OrdinalIgnoreCase))
            {
                var action = _engine.RollbackPersistence(group)[0];
                var first = true;
                foreach (var entry in group)
                {
                    // Одно изменение файла hosts закрывает все его находки; в журнал действие попадает один раз.
                    if (first)
                    {
                        _report.SetAction(ReportBuilder.PersistenceKey(entry), action, FindingActionStatus.Cleaned);
                        first = false;
                    }
                    else
                    {
                        _report.SetAction(ReportBuilder.PersistenceKey(entry), ReportBuilder.Map(action.Status, FindingActionStatus.Cleaned), action.Message);
                    }
                }
            }
        }

        foreach (var entry in targets)
        {
            if (entry.FileScan is { } scan && ShouldQuarantine(scan) && _handledFiles.Add(scan.Path))
            {
                var outcome = await _quarantine.QuarantineAsync(scan.Path, string.Join("; ", entry.Findings.Select(f => f.Id).Distinct()),
                    _policy.DryRun, cancellationToken).ConfigureAwait(false);
                _report.EnsureFileFinding("Цели автозапуска", scan);
                _report.SetAction(ReportBuilder.FileKey(scan.Path), outcome);
            }
        }
    }

    /// <summary>
    /// Обработка конфигурации: процессы и файлы, скрытые исключениями Defender, нейтрализуются,
    /// после чего сами исключения удаляются.
    /// </summary>
    public async Task HandleConfigAsync(ConfigAuditReport config, ExclusionScanReport? exclusionScan, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (exclusionScan is not null)
        {
            // Только процессы, скрытые исключениями: остальные — предмет отдельного аудита процессов.
            await HandleProcessesAsync(exclusionScan.ExcludedProcesses, cancellationToken).ConfigureAwait(false);
            await HandleFilesAsync(exclusionScan.FlaggedFiles, cancellationToken).ConfigureAwait(false);
        }

        if (_engine is null)
        {
            return;
        }

        foreach (var exclusion in config.DefenderExclusions)
        {
            var action = _engine.RemoveDefenderExclusion(exclusion, "CFG-DEFENDER-EXCL");
            _report.SetAction(ReportBuilder.ExclusionKey(exclusion), action, FindingActionStatus.Cleaned);
        }
    }

    private bool ShouldQuarantine(FileScanResult r) =>
        r.Verdict is Verdict.Malicious or Verdict.Suspicious
        && r.Detections.Count > 0
        && r.Detections.Max(d => d.Severity) >= _policy.QuarantineThreshold;
}
