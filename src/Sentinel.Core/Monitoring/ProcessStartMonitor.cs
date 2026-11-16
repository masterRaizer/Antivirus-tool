using System.Collections.Concurrent;
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

    /// <summary>Аудитор процессов (политика системных каталогов, пороги, сканер памяти).</summary>
    public ProcessAuditorOptions Auditor { get; init; } = new();

    /// <summary>
    /// Задержка отложенной повторной проверки памяти интерпретаторов и неподписанных процессов: полезная нагрузка часто
    /// распаковывается в RWX-память через 1–2 с после старта. <see cref="TimeSpan.Zero"/> — повторная проверка выключена.
    /// </summary>
    public TimeSpan MemoryRescanDelay { get; init; } = TimeSpan.FromSeconds(1.75);

    /// <summary>Сколько повторных проверок памяти выполняется одновременно.</summary>
    public int MaxConcurrentMemoryRescans { get; init; } = 2;

    /// <summary>Предел очереди повторных проверок: при всплеске запусков лишние не ставятся (периодический аудит их догонит).</summary>
    public int MaxPendingMemoryRescans { get; init; } = 32;
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
    private long _rescansScheduled;
    private long _rescansDropped;
    private int _pendingRescans;
    private SemaphoreSlim? _rescanGate;
    private readonly ConcurrentDictionary<Task, byte> _rescans = new();

    /// <summary>Интерпретаторы и хосты сценариев: им всегда назначается отложенная повторная проверка памяти.</summary>
    private static readonly HashSet<string> RescanHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe",
    };

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

    public long MemoryRescansScheduled => Interlocked.Read(ref _rescansScheduled);

    public long MemoryRescansDropped => Interlocked.Read(ref _rescansDropped);

    /// <summary>Итог отложенной повторной проверки памяти, нашедшей угрозу.</summary>
    public event Action<ProcessStartOutcome>? MemoryRescanned;

    /// <summary>Дожидается завершения запланированных повторных проверок памяти (остановка службы, тесты).</summary>
    public Task DrainMemoryRescansAsync() => Task.WhenAll(_rescans.Keys);

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
        // Пути из ядра (\SystemRoot\System32\conhost.exe, \??\C:\…) приводятся к Win32 до сравнения со штатными каталогами.
        var path = string.IsNullOrWhiteSpace(created.ExecutablePath) ? null : Kernel.NtPath.ToWin32(created.ExecutablePath);
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
        score = Math.Max(score, audited.MemoryScan?.Score.Value ?? 0);
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

        // Аномалия памяти (PE/сигнатура) у того же образа может замкнуть BH-05 — она сильнее цепочки старта.
        if (audited.MemoryScan is { HasAnomalies: true } memory
            && memory.Anomalies.Any(a => a.Kind != Auditors.Memory.MemoryAnomalyKind.ImagePatch)
            && _correlation.ReportMemoryAnomaly(path ?? name, string.Join(", ", memory.Anomalies.Select(a => a.Id).Distinct())) is { } payload)
        {
            correlation = payload;
        }
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
        var outcome = findings.Count == 0
            ? Finish(created, ProcessStartDecision.Clean, score, "Замечаний нет.", findings, correlation, null)
            : await DecideAsync(created, snapshot, findings, score, scan, signed, allowed, correlation, cancellationToken).ConfigureAwait(false);

        if (ShouldRescanMemory(outcome.Decision, name, path, scan, signed))
        {
            ScheduleMemoryRescan(created, snapshot, signed, cancellationToken);
        }

        return outcome;
    }

    /// <summary>(5) FalsePositiveGuard → (6) выравнивание критичности → диспетчер. Общий для первичной и повторной проверки.</summary>
    private async Task<ProcessStartOutcome> DecideAsync(
        ProcessCreationEvent created, ProcessSnapshot snapshot, List<AuditFinding> findings, int score, FileScanResult? scan,
        bool signed, AllowedExclusions allowed, CorrelationFinding? correlation, CancellationToken cancellationToken)
    {
        // (5) Фильтр ложных срабатываний: самозащита, белый список (пути/хеши), доверенная подпись, теневой режим.
        var guard = new FalsePositiveGuard(allowed, null, _options.ExtraOwnDirectories, _options.ActThreshold, _options.AskThreshold)
            .Evaluate(new GuardContext
            {
                Path = snapshot.ExecutablePath,
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
            Log?.Invoke($"Старт процесса {snapshot.Name} (PID {created.ProcessId}): балл {guard.EffectiveScore}, только журнал — "
                + string.Join("; ", findings.Select(f => f.Id)));
            return Finish(created, decision, guard.EffectiveScore, guard.Reason, findings, correlation, null);
        }

        // (6) Критичность находок приводится к решению предохранителя: диспетчер реагирует по критичности.
        var routed = AlignSeverity(findings, decision, guard);
        var entry = new ProcessAuditEntry(snapshot, routed, scan);
        var threat = decision == ProcessStartDecision.AskUser
            ? await _dispatcher.DispatchProcessForDecisionAsync(entry, guard.Reason, Source, cancellationToken).ConfigureAwait(false)
            : await _dispatcher.DispatchProcessAsync(entry, Source, cancellationToken).ConfigureAwait(false);
        return Finish(created, decision, guard.EffectiveScore, guard.Reason, routed, correlation, threat);
    }

    private bool ShouldRescanMemory(ProcessStartDecision decision, string name, string? path, FileScanResult? scan, bool signed) =>
        _options.Auditor.MemoryScanner is not null
        && _options.MemoryRescanDelay > TimeSpan.Zero
        && path is not null
        && decision is ProcessStartDecision.Clean or ProcessStartDecision.LogOnly or ProcessStartDecision.AskUser
        && (RescanHosts.Contains(name)
            || (scan is not null && !signed && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)));

    private void ScheduleMemoryRescan(ProcessCreationEvent created, ProcessSnapshot snapshot, bool signed, CancellationToken cancellationToken)
    {
        if (Interlocked.Increment(ref _pendingRescans) > _options.MaxPendingMemoryRescans)
        {
            Interlocked.Decrement(ref _pendingRescans);
            Interlocked.Increment(ref _rescansDropped);
            return;
        }

        Interlocked.Increment(ref _rescansScheduled);
        var gate = LazyInitializer.EnsureInitialized(ref _rescanGate, () => new SemaphoreSlim(Math.Max(1, _options.MaxConcurrentMemoryRescans)));
        var task = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(_options.MemoryRescanDelay, cancellationToken).ConfigureAwait(false);
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    if (await RescanMemoryAsync(created, snapshot, signed, cancellationToken).ConfigureAwait(false) is { } outcome)
                    {
                        MemoryRescanned?.Invoke(outcome);
                    }
                }
                finally
                {
                    gate.Release();
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                or ArgumentException or System.ComponentModel.Win32Exception)
            {
                Log?.Invoke($"Повторная проверка памяти {snapshot.Name} (PID {created.ProcessId}) не выполнена: {ex.Message}");
            }
            finally
            {
                Interlocked.Decrement(ref _pendingRescans);
            }
        }, CancellationToken.None);
        _rescans.TryAdd(task, 0);
        _ = task.ContinueWith(t => _rescans.TryRemove(t, out _), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    /// <summary>
    /// Отложенная проверка памяти: ловит RWX-регионы с PE/сигнатурами, выделенные уже после старта. Угроза проходит тот же
    /// путь, что и первичная находка: корреляция BH-05 → FalsePositiveGuard → диспетчер. <c>null</c> — память чиста.
    /// </summary>
    private async Task<ProcessStartOutcome?> RescanMemoryAsync(
        ProcessCreationEvent created, ProcessSnapshot snapshot, bool signed, CancellationToken cancellationToken)
    {
        var memory = _options.Auditor.MemoryScanner!.Scan(snapshot.Pid, snapshot.Name, snapshot.ExecutablePath);
        if (!memory.IsThreat)
        {
            return null;
        }

        var findings = memory.ToFindings(snapshot.Name, snapshot.ExecutablePath).ToList();
        var score = memory.Score.Value;
        var correlation = _correlation.ReportMemoryAnomaly(snapshot.ExecutablePath ?? snapshot.Name,
            string.Join(", ", memory.Anomalies.Select(a => a.Id).Distinct()));
        if (correlation is not null)
        {
            score = Math.Max(score, correlation.Score) + 10;
            findings.Add(AuditFinding.Create($"PROC-{ChainCode(correlation.Chain)}", Severity.High,
                "Поведенческая цепочка после старта процесса", correlation.Summary, Evidence.Of("pid", created.ProcessId)));
        }

        return await DecideAsync(created, snapshot, findings, Math.Clamp(score, 0, 100), null, signed, _allowed(), correlation, cancellationToken)
            .ConfigureAwait(false);
    }

    private List<AuditFinding> AlignSeverity(List<AuditFinding> findings, ProcessStartDecision decision, GuardVerdict guard)
    {
        var auto = _options.Dispatcher.AutoThreshold;
        var ask = _options.Dispatcher.AskThreshold;
        if (decision == ProcessStartDecision.AskUser)
        {
            // Критичность не занижается (MEM-YARA-MATCH/MEM-REFLECTIVE-PE остаются Critical): автоматическое действие
            // запрещает не она, а явный маршрут «решение за пользователем» в диспетчере (decisionReason).
            var kept = findings.ToList();
            if (kept.Max(f => f.Severity) < ask)
            {
                kept.Add(Summary(ask, guard));
            }

            return kept;
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
        CorrelationChain.DropAndExecute => "BH-04",
        _ => "BH-05",
    };
}
