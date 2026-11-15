using System.Diagnostics;
using Sentinel.Core.Scanning;
using Sentinel.Core.Scanning.Pool;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class ScanPoolTests
{
    private sealed class ThreadWorkerLauncher(Func<string, FileScanResult> analyze) : IWorkerLauncher
    {
        public int Started;

        public IWorkerProcess Start(string pipeName, int parentPid)
        {
            Interlocked.Increment(ref Started);
            var cts = new CancellationTokenSource();
            var task = Task.Run(async () =>
            {
                try
                {
                    await ScanWorkerHost.RunAsync(pipeName, parentPid, analyze, cancellationToken: cts.Token);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // «аварийное завершение» рабочего: канал закрывается без ответа
                }
            });
            return new Handle(cts, task);
        }

        private sealed class Handle(CancellationTokenSource cts, Task task) : IWorkerProcess
        {
            public bool HasExited => task.IsCompleted;

            public void Kill() => cts.Cancel();

            public void Dispose() => cts.Dispose();
        }
    }

    private sealed class ThrowingLauncher : IWorkerLauncher
    {
        public IWorkerProcess Start(string pipeName, int parentPid) => throw new InvalidOperationException("нет Sentinel.Cli.exe");
    }

    private static FileScanResult Fake(string path) => new() { Path = path, Size = 1, Sha256 = new string('a', 64), Verdict = Verdict.Clean };

    private static async Task<List<PoolResult>> Run(IScanPool pool, IEnumerable<string> files, ManualResetEventSlim? gate = null, CancellationToken ct = default)
    {
        var results = new List<PoolResult>();
        await pool.RunAsync(files, r =>
        {
            results.Add(r);
            return ValueTask.CompletedTask;
        }, gate, ct);
        return results;
    }

    private static string[] Paths(int count) => Enumerable.Range(0, count).Select(i => $"/virtual/file{i}.exe").ToArray();

    [Fact]
    public async Task FileScanResult_SurvivesThePipeProtocol_Roundtrip()
    {
        using var tmp = new TempDir();
        var analyzer = new FileAnalyzer(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), new UnavailableSignatureVerifier());
        var original = analyzer.Analyze(tmp.Write("x.exe", SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, WritableText = true, TextSize = 0x4000,
            ImportedFunctions = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] })));

        using var ms = new MemoryStream();
        await WorkerProtocol.WriteAsync(ms, new WorkerMessage { Type = "result", Id = 7, Path = original.Path, Result = original });
        ms.Position = 0;
        var copy = (await WorkerProtocol.ReadAsync(ms))!;

        Assert.Equal(7, copy.Id);
        Assert.Equal(original.Sha256, copy.Result!.Sha256);
        Assert.Equal(original.Verdict, copy.Result.Verdict);
        Assert.Equal(original.Score!.Value, copy.Result.Score!.Value);
        Assert.Equal(original.Detections.Select(d => d.Name), copy.Result.Detections.Select(d => d.Name));
        Assert.Equal(original.Pe!.Info!.Sections.Count, copy.Result.Pe!.Info!.Sections.Count);
        Assert.Equal(original.Signature!.Status, copy.Result.Signature!.Status);
    }

    [Fact]
    public async Task Protocol_RejectsOversizedAndTruncatedFrames()
    {
        using var huge = new MemoryStream([0xFF, 0xFF, 0xFF, 0x7F]);
        await Assert.ThrowsAsync<InvalidDataException>(() => WorkerProtocol.ReadAsync(huge));
        using var cut = new MemoryStream([10, 0, 0, 0, 1, 2]);
        await Assert.ThrowsAsync<IOException>(() => WorkerProtocol.ReadAsync(cut));
        using var empty = new MemoryStream();
        Assert.Null(await WorkerProtocol.ReadAsync(empty));
    }

    [Fact]
    public async Task InProcessPool_ScansEverythingInParallel()
    {
        var concurrent = 0;
        var maxConcurrent = 0;
        var pool = new InProcessScanPool(path =>
        {
            var now = Interlocked.Increment(ref concurrent);
            int seen;
            while (now > (seen = Volatile.Read(ref maxConcurrent)) && Interlocked.CompareExchange(ref maxConcurrent, now, seen) != seen)
            {
            }

            Thread.Sleep(15);
            Interlocked.Decrement(ref concurrent);
            return Fake(path);
        }, workerCount: 4);

        var results = await Run(pool, Paths(120));

        Assert.Equal(120, results.Count);
        Assert.Equal(120, results.Select(r => r.Path).Distinct().Count());
        Assert.True(maxConcurrent >= 2, $"ожидалась параллельная работа, максимум одновременно: {maxConcurrent}");
        Assert.Equal(ScanPoolMode.InProcess, pool.Mode);
    }

    [Fact]
    public async Task InProcessPool_ReportsAnalyzerExceptionsAsScanError_AndContinues()
    {
        var pool = new InProcessScanPool(path => path.EndsWith("/file5.exe", StringComparison.Ordinal) ? throw new IOException("повреждён") : Fake(path), 4);
        var results = await Run(pool, Paths(20));
        Assert.Equal(20, results.Count);
        var failed = Assert.Single(results, r => r.Error is not null);
        Assert.StartsWith("ScanError", failed.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Pause_StopsNewWork_AndResumeContinues()
    {
        var scanned = 0;
        var gate = new ManualResetEventSlim(true);
        var pool = new InProcessScanPool(path =>
        {
            Interlocked.Increment(ref scanned);
            Thread.Sleep(5);
            return Fake(path);
        }, 4);
        var seen = 0;
        var run = pool.RunAsync(Paths(2000), _ =>
        {
            Interlocked.Increment(ref seen);
            return ValueTask.CompletedTask;
        }, gate, CancellationToken.None);

        while (Volatile.Read(ref seen) < 20)
        {
            await Task.Delay(5);
        }

        gate.Reset();
        await Task.Delay(300); // доработать то, что уже взято
        var atPause = Volatile.Read(ref scanned);
        await Task.Delay(300);
        Assert.True(Volatile.Read(ref scanned) - atPause <= 8, "после паузы новые файлы не берутся");
        Assert.False(run.IsCompleted);

        gate.Set();
        await run.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(2000, seen);
    }

    [Fact]
    public async Task Stop_CancelsQuickly_EvenWhilePaused()
    {
        var gate = new ManualResetEventSlim(false);
        using var cts = new CancellationTokenSource();
        var pool = new InProcessScanPool(Fake, 4);
        var run = Run(pool, Paths(5000), gate, cts.Token);
        await Task.Delay(100);
        var stopwatch = Stopwatch.StartNew();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task VerdictCache_SkipsCleanUnchangedFiles_OnSecondRun()
    {
        using var tmp = new TempDir();
        var files = Enumerable.Range(0, 30).Select(i => tmp.WriteText($"f{i}.exe", "content" + i)).ToArray();
        var cachePath = Path.Combine(tmp.Path, "scan_cache.bin");
        var calls = 0;
        FileScanResult Analyze(string p)
        {
            Interlocked.Increment(ref calls);
            return Fake(p);
        }

        var first = await Run(new InProcessScanPool(Analyze, 4, new ScanVerdictCache(cachePath, "fp")), files);
        Assert.Equal(30, calls);
        Assert.DoesNotContain(first, r => r.FromCache);

        File.AppendAllText(files[3], "changed");
        var second = await Run(new InProcessScanPool(Analyze, 4, new ScanVerdictCache(cachePath, "fp")), files);
        Assert.Equal(31, calls); // перепроверен только изменённый файл
        Assert.Equal(29, second.Count(r => r.FromCache));
    }

    [Fact]
    public async Task MultiProcess_ProcessesAllFiles_ThroughIsolatedWorkers()
    {
        var launcher = new ThreadWorkerLauncher(Fake);
        await using var pool = new MultiProcessScanCoordinator(launcher, 4);

        var results = await Run(pool, Paths(200));

        Assert.Equal(200, results.Count);
        Assert.All(results, r => Assert.NotNull(r.Result));
        Assert.Equal(4, launcher.Started);
        Assert.Equal(0, pool.WorkerRestarts);
        Assert.Equal(ScanPoolMode.MultiProcess, pool.Mode);
    }

    [Fact]
    public async Task MultiProcess_WorkerCrash_IsLoggedAsScanError_AndReplacedWithoutStoppingTheScan()
    {
        var launcher = new ThreadWorkerLauncher(path => path.EndsWith("/file13.exe", StringComparison.Ordinal) ? throw new BadImageFormatException("повреждённый PE") : Fake(path));
        await using var pool = new MultiProcessScanCoordinator(launcher, 3);

        var results = await Run(pool, Paths(60));

        Assert.Equal(60, results.Count);
        var failed = Assert.Single(results, r => r.Error is not null);
        Assert.EndsWith("/file13.exe", failed.Path, StringComparison.Ordinal);
        Assert.Contains("ScanError", failed.Error, StringComparison.Ordinal);
        Assert.Equal(59, results.Count(r => r.Result is not null));
        Assert.Equal(1, pool.WorkerRestarts);
        Assert.True(launcher.Started >= 4, "взамен упавшего поднят новый рабочий");
    }

    [Fact]
    public async Task MultiProcess_HungWorker_IsKilledByTimeout_AndReplaced()
    {
        var launcher = new ThreadWorkerLauncher(path =>
        {
            if (path.EndsWith("/file2.exe", StringComparison.Ordinal))
            {
                Thread.Sleep(5000);
            }

            return Fake(path);
        });
        await using var pool = new MultiProcessScanCoordinator(launcher, 2, fileTimeout: TimeSpan.FromMilliseconds(300));

        var results = await Run(pool, Paths(10));

        Assert.Equal(10, results.Count);
        Assert.Single(results, r => r.Error is not null && r.Path.EndsWith("/file2.exe", StringComparison.Ordinal));
        Assert.True(pool.WorkerRestarts >= 1);
    }

    [Fact]
    public async Task MultiProcess_WhenWorkersCannotStart_FallsBackToInProcessAnalyzer()
    {
        await using var pool = new MultiProcessScanCoordinator(new ThrowingLauncher(), 3, inProcessFallback: Fake);

        var results = await Run(pool, Paths(25));

        Assert.Equal(25, results.Count);
        Assert.All(results, r => Assert.NotNull(r.Result));
        Assert.Equal(25, pool.FallbackScans);
    }

    [Fact]
    public async Task WorkerHost_ExitsWithinAboutAHalfSecondWhenParentDisappears()
    {
        var parentGoneNotified = new TaskCompletionSource();
        var stopwatch = Stopwatch.StartNew();

        // Родитель «исчез» сразу: канала нет, подключение ждало бы 15 с, но сторожевой поток завершает рабочего.
        var code = await ScanWorkerHost.RunAsync($"Sentinel.Test.{Guid.NewGuid():N}", 999_999, Fake,
            isParentAlive: _ => false, onParentGone: () => parentGoneNotified.TrySetResult()).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(0, code);
        await parentGoneNotified.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3), $"завершение заняло {stopwatch.Elapsed}");
    }

    [Fact]
    public void WorkerHost_DetectsLiveAndDeadProcesses()
    {
        Assert.True(ScanWorkerHost.IsProcessAlive(Environment.ProcessId));
        Assert.False(ScanWorkerHost.IsProcessAlive(int.MaxValue - 7));
    }

    [Fact]
    public void Factory_PicksModeByPresenceOfSentinelCli()
    {
        using var tmp = new TempDir();
        using var withoutCli = new TempDir();
        tmp.WriteText("Sentinel.Cli.exe", "stub");

        var portable = ScanPoolFactory.Create(Fake, "rules", tmp.Path, null, baseDirectory: withoutCli.Path);
        var installed = ScanPoolFactory.Create(Fake, "rules", tmp.Path, null, baseDirectory: tmp.Path);

        Assert.Equal(ScanPoolMode.InProcess, portable.Mode);
        Assert.Equal(ScanPoolMode.MultiProcess, installed.Mode);
        Assert.InRange(portable.WorkerCount, 4, 8);
        Assert.Equal(portable.WorkerCount, installed.WorkerCount);
    }
}
