using System.Diagnostics;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;

namespace Sentinel.Core.Runtime;

/// <summary>Проверка по требованию: быстрая, полная и выборочная — с паузой, остановкой и живым прогрессом.</summary>
public sealed partial class SentinelRuntime
{
    private readonly ManualResetEventSlim _pauseGate = new(initialState: true);
    private ScanProgress _scan = ScanProgress.Idle;
    private CancellationTokenSource? _scanCts;
    private Task? _scanTask;
    private long _lastPublish;

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
                if (string.IsNullOrWhiteSpace(request.Path) || (!Directory.Exists(request.Path) && !File.Exists(request.Path)))
                {
                    return Task.FromResult(OperationResult.Fail("Укажите существующую папку или файл для выборочной проверки."));
                }

                roots = [new ScanRoot(Path.GetFullPath(request.Path))];
                break;
            case ScanMode.Full:
                roots = _o.FullScanRoots;
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
            _ => $"Выборочная проверка: {request.Path}",
        };
        var run = new ScanRun(new ReportBuilder(title, _o.TimeProvider.GetUtcNow().UtcDateTime));
        var final = ScanState.Completed;
        string? message = null;
        try
        {
            run.Total = CountFiles(roots, run, token);
            Update(run, p => p with { State = ScanState.Running }, force: true);
            run.Active.Start();

            if (request.Mode != ScanMode.Custom)
            {
                await ScanProcessesAsync(run, token).ConfigureAwait(false);
                await ScanPersistenceAsync(run, token).ConfigureAwait(false);
                await ScanConfigAsync(run, token).ConfigureAwait(false);
            }

            await ScanFilesAsync(roots, run, token).ConfigureAwait(false);
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

    private long CountFiles(IReadOnlyList<ScanRoot> roots, ScanRun run, CancellationToken token)
    {
        long count = 0;
        foreach (var file in EnumerateFiles(roots))
        {
            if (++count % 500 == 0)
            {
                token.ThrowIfCancellationRequested();
                var current = count;
                Update(run, p => p with { Stage = "Подсчёт объектов", CurrentItem = file, Total = current });
            }
        }

        token.ThrowIfCancellationRequested();
        return count;
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
                    await _dispatcher.DispatchProcessAsync(entry, "scan", token).ConfigureAwait(false));
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
        var report = _o.PersistenceAudit();
        run.Total += report.Count;
        run.Report.AddPersistenceAudit(report);
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

    private async Task ScanFilesAsync(IReadOnlyList<ScanRoot> roots, ScanRun run, CancellationToken token)
    {
        long files = 0;
        var found = 0;
        var errors = 0;
        foreach (var file in EnumerateFiles(roots))
        {
            Checkpoint(run, token);

            // Первый файл этапа публикуется всегда, остальные — не чаще десяти раз в секунду.
            Update(run, p => p with { Stage = "Файлы", CurrentItem = file }, force: files == 0);
            var result = _o.Analyzer.Analyze(file);
            files++;
            run.Scanned++;
            Interlocked.Increment(ref _filesChecked);
            if (result.Verdict == Verdict.Error)
            {
                errors++;
            }
            else if (result.Verdict is Verdict.Malicious or Verdict.Suspicious && run.Report.EnsureFileFinding("Файлы", result))
            {
                found++;
                Record(run, ReportBuilder.FileKey(file),
                    await _dispatcher.DispatchFileAsync(result, "scan", token).ConfigureAwait(false), allowedWhenNull: true);
            }
        }

        run.Report.AddArea("Файлы", (int)Math.Min(files, int.MaxValue), found, errors > 0 ? $"ошибок чтения: {errors}" : null);
    }

    /// <summary>Файлы всех корней. Точки повторного разбора не обходятся (защита от циклов), данные Sentinel пропускаются.</summary>
    private IEnumerable<string> EnumerateFiles(IReadOnlyList<ScanRoot> roots)
    {
        var own = _o.DataDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        foreach (var root in roots)
        {
            if (File.Exists(root.Path))
            {
                yield return root.Path;
                continue;
            }

            if (!Directory.Exists(root.Path))
            {
                continue;
            }

            var options = new EnumerationOptions
            {
                RecurseSubdirectories = root.MaxDepth > 0,
                MaxRecursionDepth = Math.Max(0, root.MaxDepth),
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
                ReturnSpecialDirectories = false,
            };
            foreach (var file in Directory.EnumerateFiles(root.Path, "*", options))
            {
                if (!file.StartsWith(own, StringComparison.OrdinalIgnoreCase))
                {
                    yield return file;
                }
            }
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
            var total = Math.Max(run.Total, run.Scanned);
            _scan = next with
            {
                // Пауза выставляется из другого потока — рабочий поток не должен её затирать.
                State = _scan.State == ScanState.Paused && next.State == ScanState.Running ? ScanState.Paused : next.State,
                Scanned = run.Scanned,
                Total = next.State == ScanState.Counting ? next.Total : total,
                Threats = run.Threats,
                ElapsedSeconds = run.Wall.Elapsed.TotalSeconds,
                ItemsPerSecond = active > 0.2 ? run.Scanned / active : 0,
                Percent = next.State == ScanState.Completed ? 100 : total == 0 ? 0 : Math.Min(99.9, 100.0 * run.Scanned / total),
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

        public IReadOnlyList<ProcessSnapshot> Processes { get; set; } = [];
    }
}
