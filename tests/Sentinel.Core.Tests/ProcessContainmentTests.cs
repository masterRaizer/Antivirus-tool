using System.Diagnostics;
using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Behavioral;
using Sentinel.Core.Detection;
using Sentinel.Core.Realtime;
using Sentinel.Core.Remediation;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Tests;

/// <summary>Подставная изоляция потоков: проходит тот же барьер, пишет вызовы в общий журнал порядка.</summary>
internal sealed class FakeProcessContainment(List<string> log, int threadsPerProcess = 3) : IProcessContainment
{
    public HashSet<int> Suspended { get; } = [];

    public ContainmentResult SuspendProcess(int processId, string? processName = null, string? executablePath = null)
    {
        if (ContainmentBarrier.Check(processId, processName, executablePath) is { } denied)
        {
            log.Add($"denied:{processId}");
            return ContainmentResult.SelfDefense(processId, denied);
        }

        log.Add($"suspend:{processId}");
        var added = Suspended.Add(processId);
        return new ContainmentResult(true, processId, added ? threadsPerProcess : 0, 0, [processId], false, null);
    }

    public ContainmentResult ResumeProcess(int processId)
    {
        log.Add($"resume:{processId}");
        Suspended.Remove(processId);
        return new ContainmentResult(true, processId, threadsPerProcess, 0, [processId], false, null);
    }

    public ContainmentResult SuspendProcessTree(int rootProcessId, string? rootProcessName = null, string? rootExecutablePath = null) =>
        SuspendProcess(rootProcessId, rootProcessName, rootExecutablePath);
}

/// <summary>Завершение поверх <see cref="FakeProcessHost"/> с журналом порядка и возможностью выбросить исключение.</summary>
internal sealed class RecordingTerminator(FakeProcessHost host, List<string> log) : IProcessTerminator
{
    public HashSet<int> ThrowOn { get; } = [];

    public ProviderResult Terminate(int pid)
    {
        if (ThrowOn.Contains(pid))
        {
            throw new InvalidOperationException($"Сбой завершения PID {pid}.");
        }

        log.Add($"terminate:{pid}");
        return host.Terminate(pid);
    }
}

// Барьер изоляции читает общий список PID, защищённых драйвером: тесты KernelGuardStateGroup не должны идти параллельно.
[Collection(KernelGuardStateGroup.Name)]
public class ProcessContainmentEngineTests
{
    private sealed class Bench : IDisposable
    {
        public DispatcherBench Inner { get; } = new();
        public List<string> Log { get; } = [];
        public FakeProcessContainment Containment { get; }
        public RecordingTerminator Terminator { get; }

        public Bench()
        {
            Containment = new FakeProcessContainment(Log);
            Terminator = new RecordingTerminator(Inner.Host, Log);
        }

        public FakeProcessHost Host => Inner.Host;

        public RemediationEngine Engine(Func<FalsePositiveGuard>? guard = null, bool dryRun = false) => new(
            Inner.Whitelist,
            new RemediationOptions
            {
                RollbackManifestPath = Path.Combine(Inner.DataDir, "rollback_manifest.json"),
                CurrentProcessId = 999_999,
                DryRun = dryRun,
                FalsePositiveGuard = guard,
            },
            Inner.Host, Terminator, Inner.Registry, new FakeTaskEditor(), Inner.Defender, containment: Containment);

        public string Temp(string name) => Path.Combine(Inner.Tmp.Path, "Temp", name);

        public void Dispose() => Inner.Dispose();
    }

    [Fact]
    public void WholeTree_IsSuspendedBeforeAnyTermination()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "miner.exe", b.Temp("miner.exe"))
            .Add(5001, 5000, "watchdog.exe", b.Temp("watchdog.exe"))
            .Add(5002, 5001, "helper.exe", b.Temp("helper.exe"));

        var tree = b.Engine().TerminateProcessTree(5000);

        Assert.Equal(RemediationStatus.Done, tree.Status);
        Assert.Equal(
            ["suspend:5000", "suspend:5001", "suspend:5002", "terminate:5000", "terminate:5001", "terminate:5002"],
            b.Log);
        Assert.Equal(9, tree.SuspendedThreadCount);
        Assert.Equal([5000, 5001, 5002], tree.SuspendedProcessIds);
        Assert.Empty(tree.ResumedProcessIds);
        Assert.Contains("приостановлено потоков: 9", tree.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("lsass.exe", @"C:\Windows\System32\lsass.exe")]
    [InlineData("csrss.exe", @"C:\Windows\System32\csrss.exe")]
    [InlineData("smss.exe", @"C:\Windows\System32\smss.exe")]
    [InlineData("wininit.exe", @"C:\Windows\System32\wininit.exe")]
    [InlineData("services.exe", @"C:\Windows\System32\services.exe")]
    [InlineData("svchost.exe", @"C:\Windows\System32\svchost.exe")]
    [InlineData("explorer.exe", @"C:\Windows\explorer.exe")]
    [InlineData("Sentinel.Service.exe", @"C:\Program Files\Sentinel\Sentinel.Service.exe")]
    [InlineData("Sentinel.App.exe", @"C:\Program Files\Sentinel\Sentinel.App.exe")]
    [InlineData("helper.exe", @"C:\ProgramData\Sentinel\helper.exe")]
    public void CriticalProcessGuard_BlocksBeforeSuspension(string name, string path)
    {
        using var b = new Bench();
        b.Host.Add(6000, 1, name, path);

        var tree = b.Engine().TerminateProcessTree(6000);

        Assert.Equal(RemediationStatus.Blocked, tree.Status);
        Assert.Empty(b.Log); // ни приостановки, ни завершения
        Assert.Empty(b.Host.Killed);
    }

    [Fact]
    public void ProtectedChild_IsNeitherSuspendedNorTerminated()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "dropper.exe", b.Temp("dropper.exe"))
            .Add(5001, 5000, "lsass.exe", @"C:\Windows\System32\lsass.exe");

        var tree = b.Engine().TerminateProcessTree(5000);

        Assert.Equal(["suspend:5000", "terminate:5000"], b.Log);
        Assert.Contains(tree.Processes, p => p.Process.Pid == 5001 && p.Status == RemediationStatus.Blocked);
    }

    [Fact]
    public void FalsePositiveGuard_AllowedPath_BlocksBeforeSuspension()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "tool.exe", b.Temp("tool.exe"));
        var allowed = new AllowedExclusions { Paths = [Path.GetDirectoryName(b.Temp("tool.exe"))!] };

        var tree = b.Engine(() => new FalsePositiveGuard(allowed)).TerminateProcessTree(5000);

        Assert.Equal(RemediationStatus.Blocked, tree.Status);
        Assert.Contains("FalsePositiveGuard", tree.Message, StringComparison.Ordinal);
        Assert.Empty(b.Log);
    }

    [Fact]
    public void FalsePositiveGuard_TrustedSignature_BlocksAutoAction_ButNotUserConfirmed()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "signed.exe", b.Temp("signed.exe"));
        var engine = b.Engine(() => new FalsePositiveGuard());
        var context = new GuardContext { Score = 85, HasValidTrustedSignature = true };

        var auto = engine.TerminateProcessTree(5000, context);
        Assert.Equal(RemediationStatus.Blocked, auto.Status);
        Assert.Empty(b.Log);

        var confirmed = engine.TerminateProcessTree(5000, context, userConfirmed: true);
        Assert.Equal(RemediationStatus.Done, confirmed.Status);
        Assert.Equal(["suspend:5000", "terminate:5000"], b.Log);
    }

    [Fact]
    public void FalsePositiveGuard_ShadowMode_BlocksAutoAction()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "x.exe", b.Temp("x.exe"));

        var tree = b.Engine(() => new FalsePositiveGuard())
            .TerminateProcessTree(5000, new GuardContext { Score = 100, ShadowMode = true });

        Assert.Equal(RemediationStatus.Blocked, tree.Status);
        Assert.Empty(b.Log);
    }

    [Fact]
    public void ExceptionDuringTermination_ResumesEverySuspendedProcess()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "miner.exe", b.Temp("miner.exe")).Add(5001, 5000, "watchdog.exe", b.Temp("watchdog.exe"));
        b.Terminator.ThrowOn.Add(5000);

        Assert.Throws<InvalidOperationException>(() => b.Engine().TerminateProcessTree(5000));

        Assert.Equal(["suspend:5000", "suspend:5001", "resume:5000", "resume:5001"], b.Log);
        Assert.Empty(b.Containment.Suspended); // ничего не осталось «замороженным»
    }

    [Fact]
    public void FailedTermination_ResumesOnlyThatProcess()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "miner.exe", b.Temp("miner.exe")).Add(5001, 5000, "stuck.exe", b.Temp("stuck.exe"));
        b.Host.Unkillable.Add(5001);

        var tree = b.Engine().TerminateProcessTree(5000);

        Assert.Equal(["suspend:5000", "suspend:5001", "terminate:5000", "terminate:5001", "resume:5001"], b.Log);
        Assert.Equal([5001], tree.ResumedProcessIds);
    }

    [Fact]
    public void DryRun_DoesNotSuspend()
    {
        using var b = new Bench();
        b.Host.Add(5000, 1, "miner.exe", b.Temp("miner.exe"));

        var tree = b.Engine(dryRun: true).TerminateProcessTree(5000);

        Assert.Equal(RemediationStatus.WouldDo, tree.Status);
        Assert.Empty(b.Log);
    }

    [Fact]
    public void DefaultConstructor_FallsBackToNullContainment()
    {
        using var b = new DispatcherBench();
        b.Host.Add(5000, 1, "miner.exe", Path.Combine(b.Tmp.Path, "Temp", "miner.exe"));

        Assert.IsType<NullProcessContainment>(b.Engine.Containment);
        var tree = b.Engine.TerminateProcessTree(5000);
        Assert.Equal(RemediationStatus.Done, tree.Status);
        Assert.Equal(0, tree.SuspendedThreadCount);
    }

    [Fact]
    public async Task Dispatcher_MaliciousProcess_GuardsSuspendTerminateThenQuarantine()
    {
        using var b = new Bench();
        var path = b.Inner.Tmp.Write(Path.Combine("Temp", "miner.exe"), Eicar.CreateTestFileBytes());
        b.Host.Add(5000, 1, "miner.exe", path).Add(5001, 5000, "watchdog.exe", b.Temp("watchdog.exe"));
        var dispatcher = new RealtimeEventDispatcher(b.Inner.Quarantine, b.Engine(() => new FalsePositiveGuard()), b.Inner.Allowed);
        var scan = new FileScanResult
        {
            Path = path,
            Sha256 = Hashing.FileHasher.ComputeSha256(path),
            Verdict = Verdict.Malicious,
            Detections = [new Scanning.Detection("EICAR-Test-File", Severity.High, "test", DetectionSource.Builtin, null, "Тест.", [])],
        };
        var entry = new ProcessAuditEntry(
            new ProcessSnapshot { Pid = 5000, Name = "miner.exe", ExecutablePath = path },
            [AuditFinding.Create("PROC-FILE-EICAR", Severity.High, "Детект", "Синтетика.")],
            scan);

        var threat = await dispatcher.DispatchProcessAsync(entry);

        Assert.Equal(ThreatStatus.Terminated, threat!.Status);
        Assert.Equal(["suspend:5000", "suspend:5001", "terminate:5000", "terminate:5001"], b.Log);
        Assert.False(File.Exists(path)); // карантин — после завершения дерева
        var record = Assert.Single(await b.Inner.Quarantine.ListAsync());
        Assert.Contains("потоки приостановлены до завершения: 6", record.Reason, StringComparison.Ordinal);
        Assert.Contains("приостановлено потоков", threat.ActionMessage, StringComparison.Ordinal);
    }
}

public class ProcessContainmentPrimitivesTests
{
    [Theory]
    [InlineData(0, "System Idle Process", null)]
    [InlineData(4, "System", null)]
    [InlineData(700, "lsass.exe", null)]
    [InlineData(701, "lsass.exe", @"C:\Windows\System32\lsass.exe")]
    [InlineData(702, "svchost.exe", @"C:\Windows\System32\svchost.exe")]
    [InlineData(703, "explorer.exe", @"C:\Windows\explorer.exe")]
    [InlineData(704, "Sentinel.Service.exe", null)]
    [InlineData(705, "agent.exe", @"C:\Program Files\Sentinel\agent.exe")]
    public void Barrier_DeniesSystemAndSentinel(int pid, string name, string? path) =>
        Assert.NotNull(ContainmentBarrier.Check(pid, name, path));

    [Theory]
    [InlineData("svchost.exe", @"C:\Temp\svchost.exe")]
    [InlineData("lsass.exe", @"C:\Users\Public\lsass.exe")]
    [InlineData("miner.exe", @"C:\Users\u\AppData\Roaming\miner.exe")]
    public void Barrier_AllowsMasqueradeAndUserProcesses(string name, string path) =>
        Assert.Null(ContainmentBarrier.Check(8000, name, path));

    [Fact]
    public void Barrier_DeniesOwnProcess() =>
        Assert.NotNull(ContainmentBarrier.Check(Environment.ProcessId, "testhost", "/tmp/testhost"));

    [Fact]
    public void NullContainment_RespectsBarrier_AndNeverThrows()
    {
        var c = NullProcessContainment.Instance;
        Assert.True(c.SuspendProcess(700, "lsass.exe").SkippedBySelfDefense);
        var user = c.SuspendProcessTree(8000, "miner.exe", @"C:\Temp\miner.exe");
        Assert.False(user.Success);
        Assert.False(user.SkippedBySelfDefense);
        Assert.True(c.ResumeProcess(8000).Success);
    }

    [Fact]
    public void Scope_ResumesOnlyNotTerminated_AndDisposeIsIdempotent()
    {
        var log = new List<string>();
        var scope = new ProcessSuspensionScope(new FakeProcessContainment(log, threadsPerProcess: 2));
        scope.Suspend(8000, "a.exe", @"C:\Temp\a.exe");
        scope.Suspend(8001, "b.exe", @"C:\Temp\b.exe");
        scope.Suspend(700, "lsass.exe", @"C:\Windows\System32\lsass.exe");
        scope.MarkTerminated(8000);

        scope.Dispose();
        scope.Dispose();

        Assert.Equal(4, scope.SuspendedThreadCount);
        Assert.Equal(["suspend:8000", "suspend:8001", "denied:700", "resume:8001"], log);
        Assert.Equal([8001], scope.ResumedProcessIds);
        Assert.Throws<ObjectDisposedException>(() => scope.Suspend(8002));
    }
}

public class WindowsProcessContainmentIntegrationTests
{
    [WindowsFact]
    public void SuspendResume_RealChildProcess()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var ping = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "PING.EXE");
        using var process = Process.Start(new ProcessStartInfo(ping, "-n 30 127.0.0.1")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;
        try
        {
            var containment = new WindowsProcessContainment();

            var suspended = containment.SuspendProcess(process.Id, "PING.EXE", ping);
            Assert.True(suspended.Success, suspended.FailureReason);
            Assert.True(suspended.SuspendedThreadCount >= 1);
            Assert.False(suspended.SkippedBySelfDefense);

            var again = containment.SuspendProcess(process.Id, "PING.EXE", ping);
            Assert.Equal(0, again.SuspendedThreadCount); // повторный вызов не накручивает счётчик приостановки

            var resumed = containment.ResumeProcess(process.Id);
            Assert.True(resumed.Success, resumed.FailureReason);
            Assert.Equal(suspended.SuspendedThreadCount, resumed.SuspendedThreadCount);

            Assert.True(containment.SuspendProcessTree(4, "System").SkippedBySelfDefense);
            Assert.True(containment.SuspendProcess(Environment.ProcessId).SkippedBySelfDefense);
        }
        finally
        {
            process.Kill(entireProcessTree: true);
            Assert.True(process.WaitForExit(10_000));
        }
    }
}
