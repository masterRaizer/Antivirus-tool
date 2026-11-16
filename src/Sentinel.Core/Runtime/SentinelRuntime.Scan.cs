using System.Diagnostics;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;

namespace Sentinel.Core.Runtime;

/// <summary>Проверка по требованию: быстрая, полная и выборочная — с паузой, остановкой и живым прогрессом.</summary>
public sealed partial class SentinelRuntime
{
    private readonly ManualResetEventSlim _pauseGate = new(initialState: true);
    private ScanProgress _scan = ScanProgress.Idle;
    private CancellationTokenSource? _scanCts;
    private Task? _scanTask;
    private long _lastPublish;
    private Scanning.Pool.IScanPool? _activePool;

    /// <summary>Текущее состояние проверки.</summary>
    public ScanProgress CurrentScan
    {
        get
        {
            lock (_sync)
            {
                return _scan;
            }
        }
    }

    /// <summary>Задача выполняющейся (или последней) проверки — чтобы дождаться её завершения.</summary>
    public Task ScanCompletion
    {
        get
        {
            lock (_sync)
            {
                return _scanTask ?? Task.CompletedTask;
            }
        }
    }

    public Task<OperationResult> StartScanAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        IReadOnlyList<ScanRoot> roots;
        switch (request.Mode)
        {
            case ScanMode.Custom:
                var customPath = NormalizeManualPath(request.Path);
                if (customPath is null || (!Directory.Exists(customPath) && !File.Exists(customPath)))
                {
                    return Task.FromResult(OperationResult.Fail("Укажите существующую папку или файл для выборочной проверки."));
                }

                roots = [new ScanRoot(Path.GetFullPath(customPath))];
                break;
            case ScanMode.Full:
                roots = _o.FullScanRoots;
                break;
            case ScanMode.Removable:
                roots = _o.RemovableRoots();
                if (roots.Count == 0)
                {
                    return Task.FromResult(OperationResult.Fail("Нет подключённых съёмных дисков."));
                }

                break;
            default:
                roots = _o.QuickScanRoots;
                break;
        }

        lock (_sync)
        {
            if (_scan.IsActive)
            {
                return Task.FromResult(OperationResult.Fail("Проверка уже выполняется."));
            }

            _scanCts?.Dispose();
            _scanCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
            _pauseGate.Set();
            _scan = new ScanProgress { State = ScanState.Counting, Mode = request.Mode, Stage = "Подготовка" };
            var token = _scanCts.Token;
            _scanTask = Task.Run(() => RunScanAsync(request, roots, token), CancellationToken.None);
        }

        ScanProgressChanged?.Invoke(CurrentScan);
        return Task.FromResult(OperationResult.Ok("Проверка запущена."));
    }

    /// <summary>
    /// Путь, введённый вручную: без кавычек и пробелов по краям; «C:» превращается в корень «C:\» (иначе Windows понимает его
    /// как текущий каталог диска). <c>null</c> — путь пуст.
    /// </summary>
    public static string? NormalizeManualPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var trimmed = path.Trim().Trim('"').Trim();
        if (trimmed.Length == 2 && char.IsAsciiLetter(trimmed[0]) && trimmed[1] == ':')
        {
            return trimmed + "\\";
        }

        return trimmed.Length == 0 ? null : trimmed;
    }

    public Task<OperationResult> PauseScanAsync(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            if (_scan.State != ScanState.Running)
            {
                return Task.FromResult(OperationResult.Fail("Нет выполняющейся проверки."));
            }

            _pauseGate.Reset();
            _scan = _scan with { State = ScanState.Paused, ItemsPerSecond = 0 };
        }

        ScanProgressChanged?.Invoke(CurrentScan);
        return Task.FromResult(OperationResult.Ok("Проверка приостановлена."));
    }

    public Task<OperationResult> ResumeScanAsync(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            if (_scan.State != ScanState.Paused)
            {
                return Task.FromResult(OperationResult.Fail("Проверка не приостановлена."));
            }

            _scan = _scan with { State = ScanState.Running };
            _pauseGate.Set();
        }

        ScanProgressChanged?.Invoke(CurrentScan);
        return Task.FromResult(OperationResult.Ok("Проверка продолжена."));
    }

    public Task<OperationResult> StopScanAsync(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            if (!_scan.IsActive || _scanCts is null)
            {
                return Task.FromResult(OperationResult.Fail("Нет выполняющейся проверки."));
            }

            _scanCts.Cancel();
            _pauseGate.Set(); // приостановленная проверка должна проснуться и увидеть отмену
        }

        return Task.FromResult(OperationResult.Ok("Проверка останавливается."));
    }

    // ---- Выполнение ------------------------------------------------------------

    private async Task RunScanAsync(ScanRequest request, IReadOnlyList<ScanRoot> roots, CancellationToken token)
    {
        var title = request.Mode switch
        {
            ScanMode.Quick => "Быстрая проверка",
            ScanMode.Full => "Полная проверка",
            ScanMode.Removable => "Проверка съёмных дисков",
            _ => $"Выборочная проверка: {request.Path}",
        };
        var run = new ScanRun(new ReportBuilder(title, _o.TimeProvider.GetUtcNow().UtcDateTime));
        var final = ScanState.Completed;
        string? message = null;
        try
        {
            // Обход каталогов идёт параллельно с проверкой: пул получает файлы сразу, без предварительного подсчёта.
            Update(run, p => p with { State = ScanState.Running }, force: true);
            run.Active.Start();

            // Процент считается по этапам: процессы, автозагрузка и конфигурация занимают первые 15 %, файлы — остальное.
            // Раньше процент брался от всех известных объектов, и после этапа процессов «204 из 204» сразу давало 95 %.
            if (request.Mode is ScanMode.Quick or ScanMode.Full)
            {
                BeginPhase(run, 0, 4);
                await ScanProcessesAsync(run, token).ConfigureAwait(false);
                BeginPhase(run, 4, 8);
                await ScanPersistenceAsync(run, token).ConfigureAwait(false);
                BeginPhase(run, 12, 3);
                await ScanConfigAsync(run, token).ConfigureAwait(false);
                BeginPhase(run, 15, 85, files: true);
            }
            else
            {
                BeginPhase(run, 0, 100, files: true);
            }

            await ScanFilesAsync(roots, request.Mode, run, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            final = ScanState.Cancelled;
            message = "Проверка остановлена пользователем.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
            or System.ComponentModel.Win32Exception or System.Text.Json.JsonException)
        {
            final = ScanState.Failed;
            message = ex.Message;
        }

        run.Active.Stop();
        string? reportId = null;
        try
        {
            reportId = _reports.Save(run.Report.Build(run.Wall.Elapsed, "remediate"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            message = $"{message} Отчёт не сохранён: {ex.Message}".Trim();
        }

        Update(run, p => p with
        {
            State = final,
            Stage = final == ScanState.Completed ? "Завершено" : p.Stage,
            CurrentItem = string.Empty,
            Percent = final == ScanState.Completed ? 100 : p.Percent,
            ReportId = reportId,
            Message = message ?? $"Проверено объектов: {run.Scanned}; находок: {run.Threats}.",
        }, force: true);
        PublishStatus();
    }

    private async Task ScanProcessesAsync(ScanRun run, CancellationToken token)
    {
        if (_o.Processes is null)
        {
            return;
        }

        Checkpoint(run, token);
        Update(run, p => p with { Stage = "Процессы", CurrentItem = "Снимок активных процессов (Toolhelp32)" }, force: true);
        var snapshot = _o.Processes.GetProcesses();
        run.Processes = snapshot;
        run.Total += snapshot.Count;
        var auditor = new ProcessAuditor(new ProcessAuditorOptions(), _o.Analyzer);
        var entries = new List<ProcessAuditEntry>(snapshot.Count);
        foreach (var process in snapshot)
        {
            Checkpoint(run, token);
            Update(run, p => p with { CurrentItem = $"PID {process.Pid}: {process.ExecutablePath ?? process.Name}" });
            var entry = auditor.Audit([process]).Entries[0];
            entries.Add(entry);
            run.Scanned++;
            if (entry.HasFindings)
            {
                run.Report.AddProcessFinding(entry, "Процессы");
                Record(run, ReportBuilder.ProcessKey(process.Pid),
                    await DispatchAuditedProcessAsync(entry, "scan", token).ConfigureAwait(false));
            }
        }

        Interlocked.Add(ref _processesChecked, snapshot.Count);
        run.Report.AddArea("Процессы", snapshot.Count, entries.Count(e => e.HasFindings));
    }

    private async Task ScanPersistenceAsync(ScanRun run, CancellationToken token)
    {
        if (_o.PersistenceAudit is null)
        {
            return;
        }

        Checkpoint(run, token);
        Update(run, p => p with
        {
            Stage = "Автозагрузка и реестр",
            CurrentItem = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, службы, планировщик задач, WMI, hosts",
        }, force: true);
        var report = await GetPersistenceReportAsync(run, token).ConfigureAwait(false);
        run.Total += report.Count;
        run.Report.AddPersistenceAudit(report);
        RecordSkipped(run, report.Skipped);
        foreach (var entry in report.Entries)
        {
            Checkpoint(run, token);
            Update(run, p => p with { CurrentItem = $@"{entry.Location}\{entry.Name}" });
            run.Scanned++;
            if (entry.HasFindings)
            {
                Record(run, ReportBuilder.PersistenceKey(entry),
                    await _dispatcher.DispatchPersistenceAsync(entry, "scan", token).ConfigureAwait(false));
            }
        }
    }

    private async Task ScanConfigAsync(ScanRun run, CancellationToken token)
    {
        if (_o.ConfigAudit is null)
        {
            return;
        }

        Checkpoint(run, token);
        Update(run, p => p with
        {
            Stage = "Конфигурация безопасности",
            CurrentItem = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions, брандмауэр, корневые сертификаты, прокси",
        }, force: true);
        var config = _o.ConfigAudit();
        lock (_sync)
        {
            _knownExclusions = config.DefenderExclusions;
        }

        run.Total += config.Count;
        run.Scanned += config.Count;
        run.Report.AddConfigAudit(config);
        RecordSkipped(run, config.Skipped);

        // Всё, что скрыто от встроенной защиты, проверяется приоритетно и глубоко — до удаления самих исключений.
        if (config.DefenderExclusions.Count > 0)
        {
            Update(run, p => p with { CurrentItem = "Файлы и процессы под исключениями Defender" }, force: true);
            var scanner = new ExclusionPriorityScanner(_o.Analyzer, new ProcessAuditor(new ProcessAuditorOptions(), _o.Analyzer));
            var scan = scanner.Scan(config.DefenderExclusions, run.Processes);
            run.Report.AddExclusionScan(scan);
            Interlocked.Add(ref _filesChecked, scan.FilesScanned);
            foreach (var file in scan.FlaggedFiles.DistinctBy(f => f.Path))
            {
                Record(run, ReportBuilder.FileKey(file.Path), await _dispatcher.DispatchFileAsync(file, "scan", token).ConfigureAwait(false));
            }
        }

        foreach (var (exclusion, finding) in PairExclusions(config))
        {
            Checkpoint(run, token);
            Record(run, ReportBuilder.ExclusionKey(exclusion),
                await _dispatcher.DispatchExclusionAsync(exclusion, finding, "scan", token).ConfigureAwait(false),
                allowedWhenNull: true);
        }

        run.Threats += config.Findings.Count(f => f.Area != ConfigArea.DefenderExclusion);
    }

    private static void BeginPhase(ScanRun run, double start, double span, bool files = false)
    {
        run.PhaseStart = start;
        run.PhaseSpan = span;
        run.PhaseBaseScanned = run.Scanned;
        run.PhaseBaseTotal = run.Total;
        run.FilesPhase = files;
    }

    /// <summary>
    /// Процент по этапам: начало этапа + его доля × выполненная часть этапа. Пока обход каталогов не закончен, файловый этап
    /// не поднимается выше 95 % своей доли (число файлов ещё растёт).
    /// </summary>
    private static double PhasePercent(ScanRun run, long total, bool enumerationDone)
    {
        var phaseTotal = Math.Max(0, total - run.PhaseBaseTotal);
        var phaseScanned = Math.Max(0, run.Scanned - run.PhaseBaseScanned);
        var fraction = phaseTotal == 0 ? 0 : Math.Min(1.0, (double)phaseScanned / phaseTotal);
        if (run.FilesPhase)
        {
            fraction = Math.Min(enumerationDone ? 0.999 : 0.95, fraction);
        }

        return Math.Round(Math.Min(99.9, run.PhaseStart + (run.PhaseSpan * fraction)), 1);
    }

    /// <summary>
    /// Отчёт аудита автозагрузки: свежий результат фонового аудита службы (не старше <see cref="SentinelRuntimeOptions.ConfigAuditInterval"/>)
    /// используется повторно; иначе аудит выполняется в фоне, а интерфейс раз в секунду видит, сколько он уже идёт
    /// (полный обход служб, задач и WMI с проверкой подписей занимает 1–3 минуты).
    /// </summary>
    private async Task<Audit.Persistence.PersistenceAuditReport> GetPersistenceReportAsync(ScanRun run, CancellationToken token)
    {
        const string surface = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, службы, планировщик задач, WMI, hosts";
        if (TryGetFreshPersistence(out var cached, out var age))
        {
            Update(run, p => p with { CurrentItem = $"{surface} — результат фонового аудита службы ({age.TotalSeconds:0} с назад)" }, force: true);
            return cached;
        }

        var audit = Task.Run(() => _o.PersistenceAudit!(), token);
        var started = _o.TimeProvider.GetTimestamp();
        while (!audit.IsCompleted)
        {
            try
            {
                await Task.WhenAny(audit, Task.Delay(TimeSpan.FromSeconds(1), _o.TimeProvider, token)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            Checkpoint(run, token);
            var elapsed = _o.TimeProvider.GetElapsedTime(started);
            Update(run, p => p with { CurrentItem = $"{surface} — идёт аудит, {elapsed.TotalSeconds:0} с (обычно 1–3 мин)" }, force: true);
        }

        var report = await audit.ConfigureAwait(false);
        StorePersistence(report);
        return report;
    }

    private async Task ScanFilesAsync(IReadOnlyList<ScanRoot> roots, ScanMode mode, ScanRun run, CancellationToken token)
    {
        var enumeration = mode switch
        {
            ScanMode.Quick => EnumerationMode.Quick,
            ScanMode.Full => EnumerationMode.Full,
            _ => EnumerationMode.Custom,
        };

        // Кэш чистых файлов — для быстрой и полной проверки; выборочная и USB-проверка всегда глубокие.
        var cache = _o.UseVerdictCache && mode is ScanMode.Quick or ScanMode.Full ? OpenVerdictCache() : null;
        await using var pool = _o.ScanPoolFactory?.Invoke(cache) ?? Scanning.Pool.ScanPoolFactory.Create(path => _o.Analyzer.Analyze(path),
            _o.RulesDirectory ?? SentinelRuntimeOptions.DefaultRulesDirectory(), _o.DataDirectory, cache);
        lock (_sync)
        {
            _activePool = pool;
        }

        long files = 0;
        var found = 0;
        var first = true;
        var excluded = SelfProtection.OwnDirectories(_o.DataDirectory, _o.Quarantine.QuarantineDirectory).ToArray();
        try
        {
            await pool.RunAsync(Discover(ScanFileEnumerator.Enumerate(roots, enumeration, excluded, token), run), async r =>
            {
                // Пауза замораживает и выдачу уже готовых результатов: счётчики не растут, пока проверка приостановлена.
                Checkpoint(run, token);
                files++;
                run.Scanned++;
                Interlocked.Increment(ref _filesChecked);
                Update(run, p => p with { Stage = "Файлы", CurrentItem = r.Path }, force: first);
                first = false;
                if (r.FromCache)
                {
                    run.CachedSkipped++;
                    return;
                }

                if (r.Result is null)
                {
                    run.Errors++;
                    Log?.Invoke($"{r.Error}: {r.Path}");
                    return;
                }

                if (r.Result.Verdict == Verdict.Error)
                {
                    run.Errors++;
                }
                else if (r.Result.Verdict is Verdict.Malicious or Verdict.Suspicious && run.Report.EnsureFileFinding("Файлы", r.Result))
                {
                    found++;
                    Record(run, ReportBuilder.FileKey(r.Path),
                        await _dispatcher.DispatchFileAsync(r.Result, "scan", token).ConfigureAwait(false), allowedWhenNull: true);
                }
            }, _pauseGate, token).ConfigureAwait(false);
        }
        finally
        {
            lock (_sync)
            {
                _activePool = null;
            }
        }

        var note = new List<string>();
        if (run.Errors > 0)
        {
            note.Add($"не удалось проверить: {run.Errors}");
        }

        if (run.CachedSkipped > 0)
        {
            note.Add($"пропущено по кэшу: {run.CachedSkipped}");
        }

        note.Add($"пул: {(pool.Mode == Scanning.Pool.ScanPoolMode.MultiProcess ? "процессы" : "потоки")} × {pool.WorkerCount}");
        run.Report.AddArea("Файлы", (int)Math.Min(files, int.MaxValue), found, string.Join("; ", note));
    }

    /// <summary>Считает найденные файлы для оценки прогресса, пока обход ещё идёт.</summary>
    private static IEnumerable<string> Discover(IEnumerable<string> files, ScanRun run)
    {
        foreach (var file in files)
        {
            Interlocked.Increment(ref run.DiscoveredCounter);
            yield return file;
        }

        Volatile.Write(ref run.EnumerationDoneFlag, 1);
    }

    private ScanVerdictCache? OpenVerdictCache()
    {
        try
        {
            var fingerprint = ScanVerdictCache.ComputeFingerprint(
                _o.RulesDirectory ?? SentinelRuntimeOptions.DefaultRulesDirectory(),
                _o.Services?.ThreatIntel.ActivePath,
                Path.Combine(_o.DataDirectory, AllowedExclusionStore.DefaultFileName));
            return new ScanVerdictCache(Path.Combine(_o.DataDirectory, "scan_cache.bin"), fingerprint);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Шаги аудита, пропущенные из-за остановленной службы (WMI, брандмауэр, планировщик), — в журнал и в отчёт.</summary>
    private void RecordSkipped(ScanRun run, IReadOnlyList<Audit.SkippedAuditStep> skipped)
    {
        foreach (var step in skipped)
        {
            Log?.Invoke($"Шаг «{step.Step}» пропущен: {step.Reason}");
            run.Report.AddArea(step.Step, 0, 0, $"пропущено: служба или источник недоступны ({step.Reason})");
        }
    }

    /// <summary>Точка паузы и отмены между объектами.</summary>
    private void Checkpoint(ScanRun run, CancellationToken token)
    {
        if (!_pauseGate.IsSet)
        {
            run.Active.Stop();
            _pauseGate.Wait(token);
            run.Active.Start();
        }

        token.ThrowIfCancellationRequested();
    }

    /// <summary>Переносит итог реакции диспетчера в отчёт и счётчик находок.</summary>
    private static void Record(ScanRun run, string reportKey, ThreatEvent? threat, bool allowedWhenNull = false)
    {
        if (threat is null)
        {
            if (allowedWhenNull)
            {
                run.Report.SetAction(reportKey, FindingActionStatus.Skipped, Remediation.ResponseCoordinator.AllowedByUserMessage);
            }

            return;
        }

        run.Threats++;
        var status = threat.Status switch
        {
            ThreatStatus.Quarantined => FindingActionStatus.Quarantined,
            ThreatStatus.Terminated => FindingActionStatus.Terminated,
            ThreatStatus.Cleaned => FindingActionStatus.Cleaned,
            ThreatStatus.Blocked => FindingActionStatus.Blocked,
            ThreatStatus.Skipped or ThreatStatus.Allowed => FindingActionStatus.Skipped,
            ThreatStatus.Failed => FindingActionStatus.Failed,
            _ => FindingActionStatus.Detected,
        };
        run.Report.SetAction(reportKey, status, threat.ActionMessage);
    }

    private void Update(ScanRun run, Func<ScanProgress, ScanProgress> change, bool force = false)
    {
        ScanProgress snapshot;
        lock (_sync)
        {
            var active = run.Active.Elapsed.TotalSeconds;
            var next = change(_scan);
            var enumerationDone = Volatile.Read(ref run.EnumerationDoneFlag) == 1;
            var total = Math.Max(run.Total + Interlocked.Read(ref run.DiscoveredCounter), run.Scanned);
            var pool = _activePool;
            _scan = next with
            {
                // Пауза выставляется из другого потока — рабочий поток не должен её затирать.
                State = _scan.State == ScanState.Paused && next.State == ScanState.Running ? ScanState.Paused : next.State,
                Scanned = run.Scanned,
                Total = next.State == ScanState.Counting ? next.Total : total,
                Threats = run.Threats,
                ElapsedSeconds = run.Wall.Elapsed.TotalSeconds,
                ItemsPerSecond = active > 0.2 ? run.Scanned / active : 0,
                Percent = next.State == ScanState.Completed ? 100 : PhasePercent(run, total, enumerationDone),
                Workers = pool?.WorkerCount ?? 0,
                ActiveWorkers = pool?.ActiveWorkers ?? 0,
                PoolMode = pool is null ? next.PoolMode : pool.Mode == Scanning.Pool.ScanPoolMode.MultiProcess ? "процессы" : "потоки",
                CachedSkipped = run.CachedSkipped,
                Errors = run.Errors,
                EnumerationComplete = enumerationDone,
            };
            snapshot = _scan;
            if (!force && _o.TimeProvider.GetElapsedTime(_lastPublish) < TimeSpan.FromMilliseconds(100))
            {
                return;
            }

            _lastPublish = _o.TimeProvider.GetTimestamp();
        }

        ScanProgressChanged?.Invoke(snapshot);
    }

    /// <summary>Состояние одного прогона (изменяется только рабочим потоком проверки).</summary>
    private sealed class ScanRun(ReportBuilder report)
    {
        public ReportBuilder Report { get; } = report;

        public Stopwatch Wall { get; } = Stopwatch.StartNew();

        /// <summary>Время активной работы — без пауз, для честной скорости.</summary>
        public Stopwatch Active { get; } = new();

        public long Scanned { get; set; }

        public long Total { get; set; }

        public int Threats { get; set; }

        public long CachedSkipped { get; set; }

        public long Errors { get; set; }

        /// <summary>Найдено файлов при обходе (пишется потоком обхода).</summary>
        public long DiscoveredCounter;

        /// <summary>1 — обход каталогов завершён.</summary>
        public int EnumerationDoneFlag;

        public IReadOnlyList<ProcessSnapshot> Processes { get; set; } = [];

        /// <summary>Начало и доля текущего этапа в общей шкале процентов.</summary>
        public double PhaseStart { get; set; }

        public double PhaseSpan { get; set; } = 100;

        public long PhaseBaseScanned { get; set; }

        public long PhaseBaseTotal { get; set; }

        /// <summary>Текущий этап — файлы (обход каталогов идёт параллельно с проверкой).</summary>
        public bool FilesPhase { get; set; }
    }
}
