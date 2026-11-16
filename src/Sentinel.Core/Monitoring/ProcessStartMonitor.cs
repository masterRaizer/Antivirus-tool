using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Behavioral;
using Sentinel.Core.Protection;
using Sentinel.Core.Realtime;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Monitoring;

/// <summary>Итог обработки события старта процесса.</summary>
public enum ProcessStartDecision
{
    /// <summary>Защищённый процесс (ядро ОС в системном каталоге, сам Sentinel) — пропущен без анализа.</summary>
    Protected,

    /// <summary>Пользовательский список разрешённого или самозащита <see cref="FalsePositiveGuard"/>.</summary>
    Allowed,

    /// <summary>Замечаний нет.</summary>
    Clean,

    /// <summary>Риск ниже порога — только журнал, без реакции.</summary>
    LogOnly,

    /// <summary>Спорно — находка ждёт решения пользователя.</summary>
    AskUser,

    /// <summary>Опасно — передано на нейтрализацию (завершение дерева процессов и карантин образа).</summary>
    Act,
}

/// <summary>Результат проверки одного стартовавшего процесса.</summary>
public sealed record ProcessStartOutcome(
    ProcessCreationEvent Event,
    ProcessStartDecision Decision,
    int Score,
    string Reason,
    IReadOnlyList<AuditFinding> Findings,
    CorrelationFinding? Correlation,
    ThreatEvent? Threat);

public sealed class ProcessStartMonitorOptions
{
    /// <summary>Надбавка к баллу за маскировку под системный процесс вне системного каталога.</summary>
    public int MasqueradeBonus { get; init; } = 25;

    /// <summary>Порог автоматической нейтрализации для <see cref="FalsePositiveGuard"/>.</summary>
    public int ActThreshold { get; init; } = 80;

    /// <summary>Порог запроса решения пользователя для <see cref="FalsePositiveGuard"/>.</summary>
    public int AskThreshold { get; init; } = 50;

    /// <summary>Пороги критичности диспетчера (должны совпадать с <see cref="RealtimeEventDispatcher"/>).</summary>
    public DispatcherOptions Dispatcher { get; init; } = new();

    /// <summary>Проверка подписи для <see cref="CriticalProcessGuard"/>; <c>null</c> — подпись учитывается по итогам анализа файла.</summary>
    public ISignatureVerifier? Verifier { get; init; }

    /// <summary>Дополнительные каталоги Sentinel (например, каталог данных рантайма).</summary>
    public IReadOnlyList<string> ExtraOwnDirectories { get; init; } = [];

    /// <summary>Аудитор процессов (политика системных каталогов, пороги).</summary>
    public ProcessAuditorOptions Auditor { get; init; } = new();
}

/// <summary>
/// Координатор реакции на старт процесса. Порядок для каждого события:
/// (1) <see cref="CriticalProcessGuard"/> — системный процесс в системном каталоге и сам Sentinel пропускаются мгновенно,
/// а системное имя вне системного каталога (маскировка) получает надбавку к риску;
/// (2) <c>allowed_exclusions.json</c>; (3) аудит процесса (<see cref="ProcessAuditor"/>: маскировка, интерпретаторы,
/// потоковый <see cref="FileAnalyzer"/> образа и <see cref="Scoring.ThreatScoringEngine"/>); (4) командная строка —
/// в <see cref="BehavioralCorrelationEngine"/>; (5) <see cref="FalsePositiveGuard"/> по итоговому баллу;
/// (6) вердикт «Act» — диспетчеру, который завершает дерево процессов через <see cref="Remediation.RemediationEngine"/>
/// и изолирует образ в карантин, «AskUser» — в очередь решений.
/// </summary>
public sealed class ProcessStartMonitor
{
    public const string Source = "process-start";

    private readonly IProcessCreationEventSource _source;
    private readonly RealtimeEventDispatcher _dispatcher;
    private readonly BehavioralCorrelationEngine _correlation;
    private readonly FileAnalyzer? _analyzer;
    private readonly Func<AllowedExclusions> _allowed;
    private readonly Func<bool> _shadowMode;
    private readonly ProcessStartMonitorOptions _options;
    private long _processed;
    private long _skipped;

    public ProcessStartMonitor(
        IProcessCreationEventSource source,
        RealtimeEventDispatcher dispatcher,
        BehavioralCorrelationEngine correlation,
        FileAnalyzer? analyzer,
        Func<AllowedExclusions>? allowed = null,
        Func<bool>? shadowMode = null,
        ProcessStartMonitorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(correlation);
        _source = source;
        _dispatcher = dispatcher;
        _correlation = correlation;
        _analyzer = analyzer;
        _allowed = allowed ?? (() => dispatcher.AllowedStore.Load());
        _shadowMode = shadowMode ?? (() => false);
        _options = options ?? new ProcessStartMonitorOptions();
    }

    /// <summary>Каждое обработанное событие (для журнала, статистики и тестов).</summary>
    public event Action<ProcessStartOutcome>? Inspected;

    /// <summary>Диагностика (сбой анализа одного события не останавливает монитор).</summary>
    public event Action<string>? Log;

    public string SourceMode => _source.Mode;

    public long Processed => Interlocked.Read(ref _processed);

    /// <summary>Пропущено предохранителями без анализа (защищённые и разрешённые процессы).</summary>
    public long Skipped => Interlocked.Read(ref _skipped);

    /// <summary>Читает источник до отмены. <paramref name="isEnabled"/> = false — события пропускаются (защита приостановлена).</summary>
    public async Task RunAsync(Func<bool>? isEnabled = null, CancellationToken cancellationToken = default)
    {
        try
        {
            await foreach (var created in _source.ReadEventsAsync(cancellationToken).ConfigureAwait(false))
            {
                if (isEnabled?.Invoke() == false)
                {
                    continue;
                }

                try
                {
                    await InspectAsync(created, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                    or ArgumentException or System.Text.Json.JsonException)
                {
                    Log?.Invoke($"Старт процесса {created.ProcessName} (PID {created.ProcessId}) не проверен: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Проверяет одно событие старта процесса и при необходимости передаёт находку диспетчеру.</summary>
    public async Task<ProcessStartOutcome> InspectAsync(ProcessCreationEvent created, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(created);
        Interlocked.Increment(ref _processed);
        var path = string.IsNullOrWhiteSpace(created.ExecutablePath) ? null : created.ExecutablePath;
        var name = string.IsNullOrWhiteSpace(created.ProcessName) ? Path.GetFileName(path ?? string.Empty) : created.ProcessName;

        // (1) Жёсткий предохранитель: ядро ОС в системном каталоге и сам Sentinel не анализируются и не трогаются.
        if (created.ProcessId == Environment.ProcessId
            || CriticalProcessGuard.IsProtectedProcess(created.ProcessId, name, path, _options.Verifier))
        {
            return Skip(created, ProcessStartDecision.Protected, "CriticalProcessGuard: защищённый системный процесс или процесс Sentinel.");
        }

        // (2) Пользовательский список разрешённого.
        var allowed = _allowed();
        if (allowed.IsProcessAllowed(name, path) || (path is not null && allowed.IsPathAllowed(path)))
        {
            return Skip(created, ProcessStartDecision.Allowed, "Процесс в списке разрешённого (allowed_exclusions.json).");
        }

        // (3) Аудит процесса и потоковый анализ образа.
        var snapshot = new ProcessSnapshot
        {
            Pid = created.ProcessId,
            ParentPid = created.ParentProcessId,
            Name = name,
            ExecutablePath = path,
            CommandLine = string.IsNullOrEmpty(created.CommandLine) ? null : created.CommandLine,
            StartTimeUtc = created.TimestampUtc.UtcDateTime,
        };
        var audited = new ProcessAuditor(_options.Auditor, _analyzer).Audit([snapshot]).Entries[0];
        var findings = audited.Findings.ToList();
        var scan = audited.FileScan;

        var score = Math.Max(scan?.Score?.Value ?? 0, findings.Count == 0 ? 0 : findings.Max(f => ScoreOf(f.Severity)));
        if (scan is { Verdict: Verdict.Malicious })
        {
            score = 100;
        }

        // Маскировка: системное имя, но не в системном каталоге (CriticalProcessGuard иммунитета не дал).
        var masquerade = CriticalProcessGuard.IsCriticalImageName(name);
        if (masquerade)
        {
            score += _options.MasqueradeBonus;
            if (!findings.Exists(f => f.Id == "PROC-IMPERSONATION"))
            {
                findings.Add(AuditFinding.Create("PROC-START-MASQUERADE", Severity.High,
                    "Запуск под именем системного процесса вне системного каталога",
                    $"Стартовал процесс '{name}' с именем критического компонента Windows из '{path ?? "неизвестного пути"}' — признак маскировки.",
                    Evidence.Of("pid", created.ProcessId),
                    Evidence.Of("path", path)));
            }
        }

        // (4) Поведенческая корреляция по командной строке.
        var signed = scan?.Signature is { Status: SignatureStatus.Valid } signature && TrustedPublishers.IsTrusted(signature.SignerSubject);
        var correlation = _correlation.ReportProcessStart(path ?? name, created.CommandLine, signed);
        if (correlation is not null)
        {
            // Статический и поведенческий сигналы вместе весомее каждого по отдельности.
            score = Math.Max(score, correlation.Score) + (score > 0 ? 10 : 0);
            findings.Add(AuditFinding.Create($"PROC-{ChainCode(correlation.Chain)}",
                correlation.Score >= 65 ? Severity.High : Severity.Medium,
                "Поведенческая цепочка при старте процесса",
                correlation.Summary,
                Evidence.Of("pid", created.ProcessId),
                Evidence.Of("commandLine", created.CommandLine)));
        }

        score = Math.Clamp(score, 0, 100);
        if (findings.Count == 0)
        {
            return Finish(created, ProcessStartDecision.Clean, score, "Замечаний нет.", findings, correlation, null);
        }

        // (5) Фильтр ложных срабатываний: самозащита, белый список (пути/хеши), доверенная подпись, теневой режим.
        var guard = new FalsePositiveGuard(allowed, null, _options.ExtraOwnDirectories, _options.ActThreshold, _options.AskThreshold)
            .Evaluate(new GuardContext
            {
                Path = path,
                Sha256 = scan?.Sha256,
                Score = score,
                HasValidTrustedSignature = signed,
                ShadowMode = _shadowMode(),
            });

        var decision = guard.Decision switch
        {
            GuardDecision.Protected => ProcessStartDecision.Allowed,
            GuardDecision.LogOnly => ProcessStartDecision.LogOnly,
            GuardDecision.AskUser => ProcessStartDecision.AskUser,
            _ => ProcessStartDecision.Act,
        };
        if (decision is ProcessStartDecision.Allowed)
        {
            Interlocked.Increment(ref _skipped);
            return Finish(created, decision, 0, guard.Reason, findings, correlation, null);
        }

        if (decision is ProcessStartDecision.LogOnly)
        {
            Log?.Invoke($"Старт процесса {name} (PID {created.ProcessId}): балл {guard.EffectiveScore}, только журнал — "
                + string.Join("; ", findings.Select(f => f.Id)));
            return Finish(created, decision, guard.EffectiveScore, guard.Reason, findings, correlation, null);
        }

        // (6) Критичность находок приводится к решению предохранителя: диспетчер реагирует по критичности.
        var routed = AlignSeverity(findings, decision, guard);
        var entry = new ProcessAuditEntry(snapshot, routed, scan);
        var threat = await _dispatcher.DispatchProcessAsync(entry, Source, cancellationToken).ConfigureAwait(false);
        return Finish(created, decision, guard.EffectiveScore, guard.Reason, routed, correlation, threat);
    }

    private List<AuditFinding> AlignSeverity(List<AuditFinding> findings, ProcessStartDecision decision, GuardVerdict guard)
    {
        var auto = _options.Dispatcher.AutoThreshold;
        var ask = _options.Dispatcher.AskThreshold;
        if (decision == ProcessStartDecision.AskUser)
        {
            // Спорное не нейтрализуется автоматически, даже если отдельное правило критично (например, подписанный файл).
            var capped = findings.Select(f => f.Severity >= auto ? f with { Severity = ask } : f).ToList();
            if (capped.Max(f => f.Severity) < ask)
            {
                capped.Add(Summary(ask, guard));
            }

            return capped;
        }

        var result = findings.ToList();
        if (result.Max(f => f.Severity) < auto)
        {
            result.Add(Summary(auto, guard));
        }

        return result;
    }

    private static AuditFinding Summary(Severity severity, GuardVerdict guard) =>
        AuditFinding.Create("PROC-START-RISK", severity, "Совокупный риск при старте процесса",
            $"Итоговый балл {guard.EffectiveScore}/100: {guard.Reason}", Evidence.Of("score", guard.EffectiveScore));

    private ProcessStartOutcome Skip(ProcessCreationEvent created, ProcessStartDecision decision, string reason)
    {
        Interlocked.Increment(ref _skipped);
        return Finish(created, decision, 0, reason, [], null, null);
    }

    private ProcessStartOutcome Finish(
        ProcessCreationEvent created, ProcessStartDecision decision, int score, string reason,
        IReadOnlyList<AuditFinding> findings, CorrelationFinding? correlation, ThreatEvent? threat)
    {
        var outcome = new ProcessStartOutcome(created, decision, score, reason, findings, correlation, threat);
        Inspected?.Invoke(outcome);
        return outcome;
    }

    private static int ScoreOf(Severity severity) => severity switch
    {
        Severity.Critical => 100,
        Severity.High => 80,
        Severity.Medium => 55,
        Severity.Low => 25,
        _ => 0,
    };

    private static string ChainCode(CorrelationChain chain) => chain switch
    {
        CorrelationChain.DropperStaging => "BH-01",
        CorrelationChain.WeaponizedArtifact => "BH-02",
        CorrelationChain.PersistenceUnsignedProfile => "BH-03",
        _ => "BH-04",
    };
}
