using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using Sentinel.Core.Monitoring.Evasion;
using Sentinel.Core.Protection;
using Sentinel.Core.Scanning;
using Sentinel.Core.Trust;

namespace Sentinel.Cli;

internal static partial class Program
{
    /// <summary>
    /// <c>evasion-watch [секунды]</c> — живой прогон детектора скрытых майнеров в консоли: раз в секунду замер нагрузки
    /// всех процессов; когда открывают Диспетчер задач и закрывают его, печатаются процессы, которые спрятали нагрузку,
    /// с баллом и факторами. Только наблюдение: процессы не завершаются, файлы не трогаются. Код 1 — есть находка с баллом
    /// от 50. Ctrl+C — досрочный выход.
    /// </summary>
    private static int EvasionWatch(CliOptions opts)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Детектор скрытых майнеров доступен только в Windows (NtQuerySystemInformation).");
            return ExitError;
        }

        var seconds = 180;
        if (opts.Target is not null && (!int.TryParse(opts.Target, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) || seconds is < 15 or > 86_400))
        {
            Console.Error.WriteLine("Ошибка: длительность — число секунд от 15 до 86400.");
            return ExitError;
        }

        return RunEvasionWatch(opts, seconds);
    }

    [SupportedOSPlatform("windows")]
    private static int RunEvasionWatch(CliOptions opts, int seconds)
    {
        var (_, analyzer) = CreateAnalyzer(opts, printRuleErrors: !opts.Json);
        var inspector = new WindowsEvasionProcessInspector();
        var detector = new MonitorEvasionDetector();
        using var sampler = new WindowsProcessActivitySampler();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        ConsoleCancelEventHandler onCancel = (_, e) =>
        {
            e.Cancel = true;
            stop.Cancel();
        };
        Console.CancelKeyPress += onCancel;

        var results = new List<object>();
        var worst = 0;
        string? monitor = null;
        if (!opts.Json)
        {
            Console.WriteLine($"Детектор скрытых майнеров: наблюдение {seconds} с (Ctrl+C — выход). Только чтение — процессы не трогаются.");
            Console.WriteLine("Дайте процессам поработать 30 с, затем откройте Диспетчер задач на 15–30 с и закройте его.");
            sampler.Capture(); // первый замер запускает счётчики видеокарты
            Console.WriteLine(sampler.GpuUnavailable is { } gpuOff
                ? $"Нагрузка видеокарты недоступна ({gpuOff}) — наблюдение только за процессором."
                : "Наблюдаются процессор и видеокарта.");
        }

        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            do
            {
                var observation = detector.Observe(sampler.Capture());
                if (observation.MonitorName != monitor && !opts.Json)
                {
                    Console.WriteLine(observation.MonitorName is null
                        ? $"{DateTime.Now:HH:mm:ss}  {monitor} закрыт — жду, вернётся ли нагрузка (до 90 с)."
                        : $"{DateTime.Now:HH:mm:ss}  Открыт {observation.MonitorName}: под наблюдением процессов с устойчивой нагрузкой — {detector.Stats.WatchedCandidates}.");
                }

                monitor = observation.MonitorName;
                if (observation.HiddenCpu is { } hidden)
                {
                    results.Add(new { kind = "HiddenCpu", hidden.HiddenCores, hidden.ProcessorCount, seconds = hidden.Duration.TotalSeconds });
                    if (!opts.Json)
                    {
                        Console.WriteLine($"{DateTime.Now:HH:mm:ss}  [!] {hidden.Describe()}");
                    }
                }

                foreach (var finding in observation.Findings)
                {
                    var path = inspector.GetImagePath(finding.Pid);
                    if (CriticalProcessGuard.IsProtectedProcess(finding.Pid, finding.Name, path))
                    {
                        if (!opts.Json)
                        {
                            Console.WriteLine($"{DateTime.Now:HH:mm:ss}  {finding.Name} (PID {finding.Pid}) — защищённый системный процесс, пропущен.");
                        }

                        continue;
                    }

                    var details = finding.Kind == EvasionKind.ExitOnMonitor ? new EvasionProcessDetails(null, -1) : inspector.Describe(finding.Pid);
                    FileScanResult? scan = null;
                    try
                    {
                        scan = path is not null && File.Exists(path) ? analyzer.Analyze(path) : null;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // Образ заблокирован или недоступен — оценка без анализа файла, наблюдение продолжается.
                    }

                    var score = MonitorEvasionPolicy.Score(finding, new EvasionScoreContext
                    {
                        FileFlagged = scan is { Verdict: Verdict.Malicious or Verdict.Suspicious, Detections.Count: > 0 },
                        FileScore = scan?.Score?.Value ?? 0,
                        TrustedSigned = TrustedPublishers.IsTrusted(scan?.Signature),
                        UserWritableLocation = MonitorEvasionPolicy.IsUserWritableLocation(path),
                        ImageMissing = path is not null && !File.Exists(path),
                        UserObjects = details.UserObjects,
                    });
                    worst = Math.Max(worst, score.Score);
                    results.Add(new
                    {
                        kind = finding.Kind.ToString(),
                        finding.Pid,
                        finding.Name,
                        path,
                        finding.Monitor,
                        finding.BaselineCores,
                        finding.QuietCores,
                        reactionSeconds = finding.Reaction.TotalSeconds,
                        resumeSeconds = finding.ResumeDelay?.TotalSeconds,
                        finding.CycleCount,
                        score = score.Score,
                        score.AllowAutoAction,
                        score.Factors,
                        userObjects = details.UserObjects,
                    });
                    if (!opts.Json)
                    {
                        Console.WriteLine($"{DateTime.Now:HH:mm:ss}  [{(score.Score >= 50 ? "!" : "i")}] {finding.Describe()}");
                        Console.WriteLine($"           Образ: {path ?? "-"}; балл {score.Score}/100; автоматическое действие службы: {(score.AllowAutoAction && score.Score >= 80 ? "да" : "нет, решает пользователь")}.");
                        Console.WriteLine($"           Факторы: {string.Join("; ", score.Factors)}.");
                    }
                }
            }
            while (timer.WaitForNextTickAsync(stop.Token).AsTask().GetAwaiter().GetResult());
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            Console.CancelKeyPress -= onCancel;
        }

        var stats = detector.Stats;
        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { stats.Samples, stats.MonitorOpenings, findings = results }, JsonOptions));
        }
        else
        {
            Console.WriteLine($"Итог: замеров {stats.Samples}, открытий мониторинга {stats.MonitorOpenings}, находок {results.Count}.");
        }

        return worst >= 50 ? ExitDetected : ExitOk;
    }

    /// <summary>
    /// <c>gpu-usage [секунды]</c> — кто нагружает видеокарту и процессор, без Диспетчера задач (скрытый майнер его не увидит):
    /// средняя и максимальная нагрузка за время замера, путь к образу. Только чтение.
    /// </summary>
    private static int GpuUsage(CliOptions opts)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Замер нагрузки видеокарты доступен только в Windows (счётчики GPU Engine).");
            return ExitError;
        }

        var seconds = 30;
        if (opts.Target is not null && (!int.TryParse(opts.Target, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) || seconds is < 3 or > 3600))
        {
            Console.Error.WriteLine("Ошибка: длительность — число секунд от 3 до 3600.");
            return ExitError;
        }

        return RunGpuUsage(opts, seconds);
    }

    [SupportedOSPlatform("windows")]
    private static int RunGpuUsage(CliOptions opts, int seconds)
    {
        using var sampler = new WindowsProcessActivitySampler();
        var stats = new Dictionary<(int Pid, long Create), (string Name, double GpuSum, double GpuMax, int GpuSamples, long CpuFirst, long CpuLast, TimeSpan First, TimeSpan Last)>();
        if (!opts.Json)
        {
            Console.WriteLine($"Замер нагрузки {seconds} с (Диспетчер задач не нужен; закрывать его не обязательно, но лучше закрыть)…");
        }

        for (var i = 0; i <= seconds; i++)
        {
            var snapshot = sampler.Capture();
            foreach (var p in snapshot.Processes.Where(p => p.Pid > 0))
            {
                var key = (p.Pid, p.CreateTimeTicks);
                if (!stats.TryGetValue(key, out var s))
                {
                    s = (p.Name, 0, 0, 0, p.CpuTimeTicks, p.CpuTimeTicks, snapshot.Clock, snapshot.Clock);
                }

                if (p.GpuPercent >= 0)
                {
                    s.GpuSum += p.GpuPercent;
                    s.GpuMax = Math.Max(s.GpuMax, p.GpuPercent);
                    s.GpuSamples++;
                }

                s.CpuLast = p.CpuTimeTicks;
                s.Last = snapshot.Clock;
                stats[key] = s;
            }

            if (i < seconds)
            {
                Thread.Sleep(1000);
            }
        }

        var inspector = new WindowsEvasionProcessInspector();
        var rows = stats
            .Select(kv =>
            {
                var span = (kv.Value.Last - kv.Value.First).Ticks;
                return new
                {
                    kv.Key.Pid,
                    kv.Value.Name,
                    GpuAvg = kv.Value.GpuSamples > 0 ? kv.Value.GpuSum / kv.Value.GpuSamples : 0,
                    kv.Value.GpuMax,
                    CpuCores = span > 0 ? (kv.Value.CpuLast - kv.Value.CpuFirst) / (double)span : 0,
                };
            })
            .Where(r => r.GpuMax >= 1 || r.CpuCores >= 0.2)
            .OrderByDescending(r => r.GpuAvg)
            .ThenByDescending(r => r.CpuCores)
            .Take(20)
            .Select(r => new { r.Pid, r.Name, r.GpuAvg, r.GpuMax, r.CpuCores, Path = inspector.GetImagePath(r.Pid) })
            .ToList();

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { seconds, gpuUnavailable = sampler.GpuUnavailable, processes = rows }, JsonOptions));
            return ExitOk;
        }

        if (sampler.GpuUnavailable is { } off)
        {
            Console.WriteLine($"Нагрузка видеокарты недоступна: {off}. Показан только процессор.");
        }

        Console.WriteLine($"{"PID",7}  {"ГП ср.",7}  {"ГП макс",7}  {"ЦП ядер",7}  Процесс и путь");
        foreach (var r in rows)
        {
            Console.WriteLine($"{r.Pid,7}  {r.GpuAvg,6:0.0}%  {r.GpuMax,6:0.0}%  {r.CpuCores,7:0.00}  {r.Name}  {r.Path ?? "-"}");
        }

        if (rows.Count == 0)
        {
            Console.WriteLine("Заметной нагрузки на видеокарту и процессор нет.");
        }

        return ExitOk;
    }
}
