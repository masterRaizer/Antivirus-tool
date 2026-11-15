using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Remediation;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Realtime;

/// <summary>
/// Диспетчер событий реального времени с политикой «Опасное сразу, спорное спросить»:
/// находки High/Critical нейтрализуются немедленно (процесс → файл → параметр), находки Medium
/// попадают в очередь ожидания решения пользователя, находки ниже — только в журнал.
/// Объекты из <c>allowed_exclusions.json</c> событий не порождают.
/// </summary>
public sealed class RealtimeEventDispatcher
{
    private readonly QuarantineManager _quarantine;
    private readonly RemediationEngine? _engine;
    private readonly AllowedExclusionStore _allowed;
    private readonly DispatcherOptions _options;
    private readonly TimeProvider _time;
    private readonly object _sync = new();
    private readonly List<Entry> _entries = [];

    public RealtimeEventDispatcher(
        QuarantineManager quarantine,
        RemediationEngine? engine,
        AllowedExclusionStore allowed,
        DispatcherOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(quarantine);
        ArgumentNullException.ThrowIfNull(allowed);
        if (engine is { DryRun: true })
        {
            throw new ArgumentException("Диспетчер реального времени не работает с движком в режиме dry-run.", nameof(engine));
        }

        _quarantine = quarantine;
        _engine = engine;
        _allowed = allowed;
        _options = options ?? new DispatcherOptions();
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Новая находка (в любом статусе).</summary>
    public event Action<ThreatEvent>? ThreatRaised;

    /// <summary>Статус находки изменился (решение пользователя).</summary>
    public event Action<ThreatEvent>? ThreatUpdated;

    public AllowedExclusionStore AllowedStore => _allowed;

    /// <summary>Журнал событий, новые — первыми.</summary>
    public IReadOnlyList<ThreatEvent> Snapshot()
    {
        lock (_sync)
        {
            return _entries.Select(e => e.Event).Reverse().ToArray();
        }
    }

    /// <summary>Очередь спорных находок, ожидающих решения.</summary>
    public IReadOnlyList<ThreatEvent> Pending()
    {
        lock (_sync)
        {
            return _entries.Where(e => e.Event.Status == ThreatStatus.PendingDecision).Select(e => e.Event).ToArray();
        }
    }

    public Task<ThreatEvent?> DispatchFileAsync(FileScanResult result, string source = "realtime", CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (!IsFlagged(result) || _allowed.Load().IsPathAllowed(result.Path))
        {
            return Task.FromResult<ThreatEvent?>(null);
        }

        var reason = DescribeDetections(result);
        var threat = new ThreatEvent
        {
            Id = NewId(),
            Kind = ThreatKind.File,
            Name = FileNameOf(result.Path),
            Path = result.Path,
            Sha256 = result.Sha256,
            Entropy = result.Entropy,
            SignatureStatus = ReportBuilder.DescribeSignature(result),
            Reason = reason,
            Description = string.Join(" ", result.Detections.Select(d => d.Description)),
            Severity = result.Detections.Max(d => d.Severity),
            Source = source,
        };
        return RouteAsync(
            $"file:{result.Path}|{result.Sha256}",
            threat,
            ct => QuarantineFileAsync(result.Path, reason, ct),
            () => AllowPath(result.Path),
            cancellationToken);
    }

    public Task<ThreatEvent?> DispatchProcessAsync(ProcessAuditEntry entry, string source = "realtime", CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var process = entry.Process;
        if (!entry.HasFindings || _allowed.Load().IsProcessAllowed(process.Name, process.ExecutablePath))
        {
            return Task.FromResult<ThreatEvent?>(null);
        }

        var reason = DescribeFindings(entry.Findings);
        var threat = new ThreatEvent
        {
            Id = NewId(),
            Kind = ThreatKind.Process,
            Name = $"{process.Name} (PID {process.Pid})",
            Path = process.ExecutablePath,
            Sha256 = entry.FileScan?.Sha256,
            Entropy = entry.FileScan?.Entropy,
            SignatureStatus = entry.FileScan is null ? "не проверялась" : ReportBuilder.DescribeSignature(entry.FileScan),
            Reason = reason,
            Description = string.Join(" ", entry.Findings.Select(f => f.Description)),
            Severity = entry.Findings.Max(f => f.Severity),
            Source = source,
            ProcessId = process.Pid,
        };
        return RouteAsync(
            $"proc:{process.Pid}|{process.StartTimeUtc?.Ticks}|{process.ExecutablePath}",
            threat,
            async ct =>
            {
                if (_engine is null)
                {
                    return new Outcome(ThreatStatus.Skipped, "Завершение процессов недоступно на этой платформе.");
                }

                var tree = _engine.TerminateProcessTree(process.Pid);
                var outcome = new Outcome(Map(tree.Status, ThreatStatus.Terminated), tree.Message);
                if (tree.Status == RemediationStatus.Done && entry.FileScan is { } scan && IsFlagged(scan))
                {
                    // Образ изолируется только после фактической остановки процесса — иначе файл заблокирован.
                    var file = await QuarantineFileAsync(scan.Path, reason, ct).ConfigureAwait(false);
                    outcome = outcome with { Message = $"{tree.Message} Образ: {file.Message}", QuarantineId = file.QuarantineId };
                }

                return outcome;
            },
            () => process.ExecutablePath is { Length: > 0 } path ? AllowPath(path) : AllowProcess(process.Name),
            cancellationToken);
    }

    public Task<ThreatEvent?> DispatchPersistenceAsync(PersistenceEntry entry, string source = "realtime", CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (!entry.HasFindings || _allowed.Load().IsPathAllowed(entry.ResolvedTarget))
        {
            return Task.FromResult<ThreatEvent?>(null);
        }

        var reason = DescribeFindings(entry.Findings);
        var threat = new ThreatEvent
        {
            Id = NewId(),
            Kind = ThreatKind.Persistence,
            Name = $"{entry.Name} [{entry.Kind}]",
            Path = entry.ResolvedTarget ?? entry.Location,
            Sha256 = entry.FileScan?.Sha256,
            Entropy = entry.FileScan?.Entropy,
            SignatureStatus = entry.FileScan is null ? "не проверялась" : ReportBuilder.DescribeSignature(entry.FileScan),
            Reason = reason,
            Description = string.Join(" ", entry.Findings.Select(f => f.Description))
                + (string.IsNullOrEmpty(entry.Command) ? string.Empty : $" Команда: {entry.Command}"),
            Severity = entry.MaxSeverity,
            Source = source,
        };
        return RouteAsync(
            ReportBuilder.PersistenceKey(entry) + "|" + entry.Command,
            threat,
            async ct =>
            {
                if (_engine is null)
                {
                    return new Outcome(ThreatStatus.Skipped, "Откат автозагрузки недоступен на этой платформе.");
                }

                // Сначала параметр (чтобы запись не запустила файл повторно), затем сам файл.
                var action = _engine.RollbackPersistence(entry);
                var outcome = new Outcome(Map(action.Status, ThreatStatus.Cleaned), action.Message);
                if (action.Status == RemediationStatus.Done && entry.FileScan is { } scan && IsFlagged(scan))
                {
                    var file = await QuarantineFileAsync(scan.Path, reason, ct).ConfigureAwait(false);
                    outcome = outcome with { Message = $"{action.Message} Цель: {file.Message}", QuarantineId = file.QuarantineId };
                }

                return outcome;
            },
            () => entry.ResolvedTarget is { Length: > 0 } target
                ? AllowPath(target)
                : (false, "Цель автозапуска не определена — добавить её в исключения нельзя."),
            cancellationToken);
    }

    public Task<ThreatEvent?> DispatchExclusionAsync(
        DefenderExclusion exclusion, AuditFinding finding, string source = "realtime", CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(exclusion);
        ArgumentNullException.ThrowIfNull(finding);
        if (_allowed.Load().IsAllowed(exclusion))
        {
            return Task.FromResult<ThreatEvent?>(null);
        }

        var threat = new ThreatEvent
        {
            Id = NewId(),
            Kind = ThreatKind.DefenderExclusion,
            Name = exclusion.ToString(),
            Path = exclusion.Kind is DefenderExclusionKind.Path or DefenderExclusionKind.Process ? exclusion.ExpandedValue : exclusion.SourceKey,
            Reason = finding.Id,
            Description = finding.Description,
            Severity = finding.Severity,
            Source = source,
        };
        return RouteAsync(
            ReportBuilder.ExclusionKey(exclusion),
            threat,
            _ =>
            {
                if (_engine is null)
                {
                    return Task.FromResult(new Outcome(ThreatStatus.Skipped, "Изменение настроек Defender недоступно на этой платформе."));
                }

                var action = _engine.RemoveDefenderExclusion(exclusion, finding.Id);
                return Task.FromResult(new Outcome(Map(action.Status, ThreatStatus.Cleaned), action.Message));
            },
            () => exclusion switch
            {
                { HasWildcard: true } => (false, "Исключение с шаблоном слишком широкое — разрешить его нельзя."),
                { Kind: DefenderExclusionKind.Path } => AllowPath(exclusion.ExpandedValue),
                { Kind: DefenderExclusionKind.Process } => AllowProcess(exclusion.ExpandedValue),
                _ => (false, "Исключения по расширению и IP-адресу слишком широкие — разрешить их нельзя."),
            },
            cancellationToken);
    }

    /// <summary>Применяет решение пользователя к находке из очереди (или к любой ещё не закрытой находке).</summary>
    public async Task<ThreatEvent> ResolveAsync(string id, ThreatDecision decision, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        Entry entry;
        lock (_sync)
        {
            entry = _entries.Find(e => e.Event.Id == id)
                ?? throw new KeyNotFoundException($"Находка '{id}' отсутствует в журнале.");
            if (!entry.Event.IsActionable || entry.Busy)
            {
                return entry.Event; // решение уже принято (например, из другого окна) — повтор безвреден
            }

            entry.Busy = true;
        }

        ThreatEvent updated;
        try
        {
            if (decision == ThreatDecision.Ignore)
            {
                updated = entry.Event with { Status = ThreatStatus.Skipped, ActionMessage = "Пользователь решил игнорировать: изменений не вносилось." };
            }
            else if (decision == ThreatDecision.Allow)
            {
                var (ok, message) = entry.Allow();
                updated = entry.Event with { Status = ok ? ThreatStatus.Allowed : entry.Event.Status, ActionMessage = message };
            }
            else
            {
                updated = Apply(entry.Event, await NeutralizeSafeAsync(entry, cancellationToken).ConfigureAwait(false));
            }
        }
        finally
        {
            lock (_sync)
            {
                entry.Busy = false;
            }
        }

        lock (_sync)
        {
            entry.Event = updated;
        }

        ThreatUpdated?.Invoke(updated);
        return updated;
    }

    // ---- Маршрутизация ---------------------------------------------------------

    private async Task<ThreatEvent?> RouteAsync(
        string key,
        ThreatEvent threat,
        Func<CancellationToken, Task<Outcome>> neutralize,
        Func<(bool Ok, string Message)> allow,
        CancellationToken cancellationToken)
    {
        Entry entry;
        lock (_sync)
        {
            // Повторное срабатывание по тому же объекту, пока по нему не принято решение, не дублируется.
            var existing = _entries.FindLast(e => e.Key == key);
            // То же — если действие запрещено или неприменимо: повтор ничего не изменит, а журнал засорит.
            if (existing is not null && (existing.Busy || existing.Event.IsActionable
                || existing.Event.Status is ThreatStatus.Blocked or ThreatStatus.Skipped))
            {
                return existing.Event;
            }

            entry = new Entry(key, threat with { DetectedAtUtc = _time.GetUtcNow().UtcDateTime }, neutralize, allow) { Busy = true };
            _entries.Add(entry);
            Trim();
        }

        ThreatEvent result;
        try
        {
            if (threat.Severity >= _options.AutoThreshold)
            {
                result = Apply(entry.Event, await NeutralizeSafeAsync(entry, cancellationToken).ConfigureAwait(false));
            }
            else if (threat.Severity >= _options.AskThreshold)
            {
                result = entry.Event with { Status = ThreatStatus.PendingDecision, ActionMessage = "Ожидает решения пользователя." };
            }
            else
            {
                result = entry.Event with { Status = ThreatStatus.Detected, ActionMessage = "Низкая критичность — только зафиксировано." };
            }
        }
        finally
        {
            lock (_sync)
            {
                entry.Busy = false;
            }
        }

        lock (_sync)
        {
            entry.Event = result;
        }

        ThreatRaised?.Invoke(result);
        return result;
    }

    private static async Task<Outcome> NeutralizeSafeAsync(Entry entry, CancellationToken cancellationToken)
    {
        try
        {
            return await entry.Neutralize(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new Outcome(ThreatStatus.Failed, ex.Message);
        }
    }

    private async Task<Outcome> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken)
    {
        var result = await _quarantine.QuarantineAsync(path, reason, false, cancellationToken).ConfigureAwait(false);
        var status = result.Status switch
        {
            QuarantineStatus.Quarantined => ThreatStatus.Quarantined,
            QuarantineStatus.BlockedByWhitelist => ThreatStatus.Blocked,
            QuarantineStatus.NotFound => ThreatStatus.Skipped,
            _ => ThreatStatus.Failed,
        };
        return new Outcome(status, result.Message, result.Record?.Id);
    }

    private (bool Ok, string Message) AllowPath(string path)
    {
        _allowed.AddPath(path);
        return (true, $"Добавлено в разрешённые исключения: {path}");
    }

    private (bool Ok, string Message) AllowProcess(string process)
    {
        _allowed.AddProcess(process);
        return (true, $"Процесс добавлен в разрешённые исключения: {process}");
    }

    private static ThreatEvent Apply(ThreatEvent threat, Outcome outcome) =>
        threat with { Status = outcome.Status, ActionMessage = outcome.Message, QuarantineId = outcome.QuarantineId ?? threat.QuarantineId };

    private static ThreatStatus Map(RemediationStatus status, ThreatStatus done) => status switch
    {
        RemediationStatus.Done => done,
        RemediationStatus.Blocked => ThreatStatus.Blocked,
        RemediationStatus.Skipped => ThreatStatus.Skipped,
        _ => ThreatStatus.Failed,
    };

    private void Trim()
    {
        while (_entries.Count > _options.MaxHistory)
        {
            var index = _entries.FindIndex(e => !e.Busy && e.Event.Status != ThreatStatus.PendingDecision);
            if (index < 0)
            {
                return; // очередь решений не вытесняется никогда
            }

            _entries.RemoveAt(index);
        }
    }

    private static bool IsFlagged(FileScanResult r) =>
        r.Verdict is Verdict.Malicious or Verdict.Suspicious && r.Detections.Count > 0;

    private static string DescribeDetections(FileScanResult r) =>
        string.Join("; ", r.Detections.Select(d => d.RuleId is null ? d.Name : $"{d.Name} [{d.RuleId}]"));

    private static string DescribeFindings(IEnumerable<AuditFinding> findings) =>
        string.Join("; ", findings.Select(f => $"{f.Id}: {f.Title}").Distinct());

    private static string FileNameOf(string path)
    {
        var idx = path.LastIndexOfAny(['\\', '/']);
        return idx < 0 || idx == path.Length - 1 ? path : path[(idx + 1)..];
    }

    private static string NewId() => Guid.NewGuid().ToString("N")[..12];

    private sealed record Outcome(ThreatStatus Status, string Message, string? QuarantineId = null);

    private sealed class Entry(
        string key, ThreatEvent threat, Func<CancellationToken, Task<Outcome>> neutralize, Func<(bool Ok, string Message)> allow)
    {
        public string Key { get; } = key;

        public ThreatEvent Event { get; set; } = threat;

        public bool Busy { get; set; }

        public Func<CancellationToken, Task<Outcome>> Neutralize { get; } = neutralize;

        public Func<(bool Ok, string Message)> Allow { get; } = allow;
    }
}
