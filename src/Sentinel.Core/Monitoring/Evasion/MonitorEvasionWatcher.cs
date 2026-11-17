using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Behavioral;
using Sentinel.Core.Protection;
using Sentinel.Core.Realtime;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Monitoring.Evasion;

/// <summary>Итог обработки находки уклонения.</summary>
public enum EvasionDecision
{
    /// <summary>Процесс защищён <c>CriticalProcessGuard</c> или самозащитой — не трогается.</summary>
    Protected,

    /// <summary>Процесс или образ в списке разрешённого пользователем.</summary>
    Allowed,

    /// <summary>Риск ниже порога — только журнал.</summary>
    LogOnly,

    /// <summary>Находка ждёт решения пользователя.</summary>
    AskUser,

    /// <summary>Передано на нейтрализацию: завершение дерева процессов и карантин образа.</summary>
    Act,
}

public sealed record MonitorEvasionOutcome(
    MonitorEvasionFinding Finding,
    EvasionDecision Decision,
    int Score,
    string Reason,
    string? ExecutablePath,
    IReadOnlyList<string> Factors,
    ThreatEvent? Threat);

public sealed class MonitorEvasionWatcherOptions
{
    /// <summary>Период замера. Секунда — достаточно, чтобы поймать реакцию майнера (они проверяют процессы раз в 1–5 с).</summary>
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(1);

    public int ActThreshold { get; init; } = 80;

    public int AskThreshold { get; init; } = 50;

    public DispatcherOptions Dispatcher { get; init; } = new();

    /// <summary>Дополнительные каталоги Sentinel (каталог данных) для самозащиты.</summary>
    public IReadOnlyList<string> ExtraOwnDirectories { get; init; } = [];

    /// <summary>Потоковый аудит памяти находки (только Windows): PE без файла и сигнатуры в памяти подтверждают внедрение.</summary>
    public Auditors.Memory.MemoryIntegrityScanner? MemoryScanner { get; init; }
}

/// <summary>
/// Цикл детектора уклонения: раз в секунду замер активности всех процессов → <see cref="MonitorEvasionDetector"/>.
/// По каждой находке: (1) путь образа и <see cref="CriticalProcessGuard"/> — защищённые процессы не трогаются и о них не
/// собираются дальнейшие сведения; (2) список разрешённого; (3) потоковый анализ образа, подпись, окна процесса;
/// (4) <see cref="MonitorEvasionPolicy"/> и <see cref="FalsePositiveGuard"/>; (5) диспетчер: «Act» — завершение дерева
/// процессов и карантин образа, «AskUser» — карточка с выбором для пользователя.
/// </summary>
public sealed class MonitorEvasionWatcher
{
    public const string Source = "monitor-evasion";
    public const string FindingHide = "PROC-MONITOR-EVASION";
    public const string FindingHidden = "PROC-MONITOR-HIDDEN";
    public const string FindingExit = "PROC-MONITOR-EXIT";
    public const string BehaviorRuleId = "SNT-BEH-EVASION";

    private readonly IProcessActivitySampler _sampler;
    private readonly MonitorEvasionDetector _detector;
    private readonly IEvasionProcessInspector _inspector;
    private readonly RealtimeEventDispatcher _dispatcher;
    private readonly FileAnalyzer? _analyzer;
    private readonly Func<AllowedExclusions> _allowed;
    private readonly Func<bool> _shadowMode;
    private readonly MonitorEvasionWatcherOptions _options;
    private readonly object _sync = new();
    private readonly Queue<string> _recent = new();
    private int _sampleErrors;

    public MonitorEvasionWatcher(
        IProcessActivitySampler sampler,
        MonitorEvasionDetector detector,
        IEvasionProcessInspector inspector,
        RealtimeEventDispatcher dispatcher,
        FileAnalyzer? analyzer,
        Func<AllowedExclusions>? allowed = null,
        Func<bool>? shadowMode = null,
        MonitorEvasionWatcherOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sampler);
        ArgumentNullException.ThrowIfNull(detector);
        ArgumentNullException.ThrowIfNull(inspector);
        ArgumentNullException.ThrowIfNull(dispatcher);
        _sampler = sampler;
        _detector = detector;
        _inspector = inspector;
        _dispatcher = dispatcher;
        _analyzer = analyzer;
        _allowed = allowed ?? (() => dispatcher.AllowedStore.Load());
        _shadowMode = shadowMode ?? (() => false);
        _options = options ?? new MonitorEvasionWatcherOptions();
    }

    /// <summary>Каждая обработанная находка (журнал, статистика, тесты).</summary>
    public event Action<MonitorEvasionOutcome>? Detected;

    /// <summary>Устойчивая нагрузка, не принадлежащая ни одному видимому процессу.</summary>
    public event Action<HiddenCpuFinding>? HiddenCpuDetected;

    /// <summary>Появление и закрытие средства мониторинга (для журнала службы).</summary>
    public event Action<string>? Info;

    public event Action<string>? Log;

    public MonitorEvasionStats Stats => _detector.Stats;

    /// <summary>Последние находки (новые — в конце) для интерфейса.</summary>
    public IReadOnlyList<string> Recent
    {
        get
        {
            lock (_sync)
            {
                return _recent.ToArray();
            }
        }
    }

    /// <summary>Цикл до отмены. <paramref name="isEnabled"/> = false — замеры не снимаются (история сбросится при возобновлении).</summary>
    public async Task RunAsync(Func<bool>? isEnabled = null, CancellationToken cancellationToken = default)
    {
        using var timer = new PeriodicTimer(_options.Interval);
        string? monitor = null;
        try
        {
            do
            {
                if (isEnabled?.Invoke() == false)
                {
                    continue;
                }

                EvasionObservation observation;
                try
                {
                    observation = _detector.Observe(_sampler.Capture());
                    _sampleErrors = 0;
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or OutOfMemoryException)
                {
                    if (++_sampleErrors is 1 or 60)
                    {
                        Log?.Invoke($"Детектор уклонения: замер активности процессов не удался ({ex.Message}).");
                    }

                    continue;
                }

                if (observation.MonitorName != monitor)
                {
                    Info?.Invoke(observation.MonitorName is null
                        ? $"Детектор уклонения: {monitor} закрыт, жду возврата нагрузки у затихших процессов."
                        : $"Детектор уклонения: открыт {observation.MonitorName}, наблюдаю за процессами с устойчивой нагрузкой ({_detector.Stats.WatchedCandidates}).");
                    monitor = observation.MonitorName;
                }

                if (observation.HiddenCpu is { } hidden)
                {
                    Remember($"Скрытая нагрузка: {hidden.Describe()}");
                    Log?.Invoke($"Детектор уклонения: {hidden.Describe()}");
                    HiddenCpuDetected?.Invoke(hidden);
                }

                foreach (var finding in observation.Findings)
                {
                    try
                    {
                        await HandleAsync(finding, cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
                    {
                        Log?.Invoke($"Детектор уклонения: находка по {finding.Name} (PID {finding.Pid}) не обработана: {ex.Message}");
                    }
                }
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Оценивает находку детектора и передаёт её диспетчеру.</summary>
    public async Task<MonitorEvasionOutcome> HandleAsync(MonitorEvasionFinding finding, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(finding);

        // (1) Путь образа (только PROCESS_QUERY_LIMITED_INFORMATION) и жёсткий предохранитель до любых других обращений.
        var path = _inspector.GetImagePath(finding.Pid);
        if (finding.Pid <= 4 || finding.Pid == Environment.ProcessId
            || CriticalProcessGuard.IsProtectedProcess(finding.Pid, finding.Name, path))
        {
            return Finish(finding, EvasionDecision.Protected, 0, "CriticalProcessGuard: защищённый системный процесс или процесс Sentinel.", path, [], null);
        }

        // (2) Пользовательский список разрешённого.
        var allowed = _allowed();
        if (allowed.IsProcessAllowed(finding.Name, path) || (path is not null && allowed.IsPathAllowed(path)))
        {
            return Finish(finding, EvasionDecision.Allowed, 0, "Процесс в списке разрешённого (allowed_exclusions.json).", path, [], null);
        }

        // (3) Сведения о процессе и потоковый анализ образа.
        var details = finding.Kind == EvasionKind.ExitOnMonitor ? new EvasionProcessDetails(null, -1) : _inspector.Describe(finding.Pid);
        var imageMissing = path is not null && !File.Exists(path);
        FileScanResult? scan = null;
        if (path is not null && !imageMissing && _analyzer is not null)
        {
            try
            {
                scan = _analyzer.Analyze(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log?.Invoke($"Детектор уклонения: образ {path} не проверен: {ex.Message}");
            }
        }

        // Память проверяется только у живого процесса; сканер сам вызывает CriticalProcessGuard до открытия дескриптора.
        Auditors.Memory.MemoryScanResult? memory = null;
        if (finding.Kind != EvasionKind.ExitOnMonitor && _options.MemoryScanner is { } memoryScanner)
        {
            memory = memoryScanner.Scan(finding.Pid, finding.Name, path);
        }

        var hollowingHost = MonitorEvasionPolicy.HollowingHosts.Contains(finding.Name);
        // Подпись носителя внедрения не говорит ничего о том, что в нём исполняется.
        var trusted = TrustedPublishers.IsTrusted(scan?.Signature) && !hollowingHost;
        var flagged = scan is { Verdict: Verdict.Malicious or Verdict.Suspicious, Detections.Count: > 0 };
        var score = MonitorEvasionPolicy.Score(finding, new EvasionScoreContext
        {
            FileFlagged = flagged,
            FileScore = scan?.Score?.Value ?? 0,
            TrustedSigned = trusted,
            UserWritableLocation = MonitorEvasionPolicy.IsUserWritableLocation(path),
            SystemLocation = MonitorEvasionPolicy.IsSystemLocation(path),
            ImageMissing = imageMissing,
            UserObjects = details.UserObjects,
            HollowingHost = hollowingHost,
            MemoryAnomaly = memory?.IsThreat == true,
        });

        // (4) Фильтр ложных срабатываний: самозащита, белый список путей и хешей, доверенная подпись, теневой режим.
        var guard = new FalsePositiveGuard(allowed, null, _options.ExtraOwnDirectories, _options.ActThreshold, _options.AskThreshold)
            .Evaluate(new GuardContext
            {
                Path = path,
                Sha256 = scan?.Sha256,
                Score = score.Score,
                HasValidTrustedSignature = trusted,
                ShadowMode = _shadowMode(),
            });
        var decision = guard.Decision switch
        {
            GuardDecision.Protected => EvasionDecision.Allowed,
            GuardDecision.LogOnly => EvasionDecision.LogOnly,
            GuardDecision.AskUser => EvasionDecision.AskUser,
            GuardDecision.Act when !score.AllowAutoAction => EvasionDecision.AskUser,
            _ => EvasionDecision.Act,
        };

        var summary = $"{finding.Describe()} Балл {guard.EffectiveScore}: {string.Join("; ", score.Factors)}.";
        if (decision is EvasionDecision.Allowed or EvasionDecision.LogOnly)
        {
            Log?.Invoke($"Детектор уклонения ({(decision == EvasionDecision.Allowed ? "разрешено" : "только журнал")}): {summary}");
            return Finish(finding, decision, guard.EffectiveScore, guard.Reason, path, score.Factors, null);
        }

        // (5) Диспетчер реагирует по критичности: она приводится к решению. Поведенческий вердикт добавляется к образу как
        // обнаружение, чтобы после завершения процесса образ ушёл в карантин и не запустился снова.
        var severity = decision == EvasionDecision.Act
            ? Max(_options.Dispatcher.AutoThreshold, Severity.High)
            : Max(_options.Dispatcher.AskThreshold, guard.EffectiveScore >= 65 ? Severity.High : Severity.Medium);
        var id = finding.Kind switch
        {
            EvasionKind.HideAndResume => FindingHide,
            EvasionKind.HiddenWhileMonitorOpen => FindingHidden,
            _ => FindingExit,
        };
        var auditFinding = AuditFinding.Create(id, severity, "Прячется от Диспетчера задач (скрытый майнер)", summary,
            Evidence.Of("pid", finding.Pid),
            Evidence.Of("monitor", finding.Monitor),
            Evidence.Of("baselineCores", finding.BaselineCores.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)),
            Evidence.Of("cycles", finding.CycleCount),
            Evidence.Of("score", guard.EffectiveScore));

        var routedScan = scan is null || flagged ? scan : scan with
        {
            Verdict = Verdict.Suspicious,
            Detections = [.. scan.Detections, new Scanning.Detection("Behavior.MonitorEvasion", severity, "miner", DetectionSource.Heuristic,
                BehaviorRuleId, "Процесс прятал нагрузку на процессор от Диспетчера задач", [])],
        };
        var snapshot = new ProcessSnapshot
        {
            Pid = finding.Pid,
            ParentPid = finding.ParentPid,
            Name = finding.Name,
            ExecutablePath = path,
            CommandLine = details.CommandLine,
            StartTimeUtc = finding.CreateTimeTicks > 0 ? DateTime.FromFileTimeUtc(finding.CreateTimeTicks) : null,
        };
        var findings = new List<AuditFinding> { auditFinding };
        if (memory is { IsThreat: true })
        {
            findings.AddRange(memory.ToFindings(finding.Name, path));
        }

        var entry = new ProcessAuditEntry(snapshot, findings, routedScan) { MemoryScan = memory };
        var threat = decision == EvasionDecision.AskUser
            ? await _dispatcher.DispatchProcessForDecisionAsync(entry, guard.Decision == GuardDecision.Act ? "поведенческая находка без подтверждения: решает пользователь" : guard.Reason, Source, cancellationToken).ConfigureAwait(false)
            : await _dispatcher.DispatchProcessAsync(entry, Source, cancellationToken).ConfigureAwait(false);
        if (decision == EvasionDecision.Act && threat is { Status: ThreatStatus.PendingDecision } pending)
        {
            // По этому процессу уже висит карточка (прошлый цикл спросил пользователя): диспетчер не дублирует находку,
            // поэтому повторный подтверждённый цикл решает её сам — как если бы пользователь нажал «Нейтрализовать».
            Log?.Invoke($"Детектор уклонения: повторный цикл {finding.Name} (PID {finding.Pid}) — находка {pending.Id} решается автоматически.");
            threat = await _dispatcher.ResolveAsync(pending.Id, ThreatDecision.Quarantine, cancellationToken).ConfigureAwait(false);
        }

        Remember($"{finding.Name} (PID {finding.Pid}): {(decision == EvasionDecision.Act ? "нейтрализация" : "ждёт решения")}, балл {guard.EffectiveScore}");
        Log?.Invoke($"Детектор уклонения ({(decision == EvasionDecision.Act ? "нейтрализация" : "решение пользователя")}): {summary} Итог: {threat?.Status.ToString() ?? "-"}.");
        return Finish(finding, decision, guard.EffectiveScore, guard.Reason, path, score.Factors, threat);
    }

    private static Severity Max(Severity a, Severity b) => a >= b ? a : b;

    private void Remember(string text)
    {
        lock (_sync)
        {
            _recent.Enqueue($"{DateTime.Now:HH:mm:ss} {text}");
            while (_recent.Count > 20)
            {
                _recent.Dequeue();
            }
        }
    }

    private MonitorEvasionOutcome Finish(
        MonitorEvasionFinding finding, EvasionDecision decision, int score, string reason, string? path, IReadOnlyList<string> factors, ThreatEvent? threat)
    {
        var outcome = new MonitorEvasionOutcome(finding, decision, score, reason, path, factors, threat);
        Detected?.Invoke(outcome);
        return outcome;
    }
}
