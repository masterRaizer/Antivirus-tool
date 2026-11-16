using System.Runtime.CompilerServices;
using Sentinel.Core.Behavioral;
using Sentinel.Core.Detection;
using Sentinel.Core.Monitoring;
using Sentinel.Core.Realtime;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>Подставной источник: отдаёт заранее заданные события старта процессов и завершает поток.</summary>
internal sealed class FakeProcessCreationEventSource(params ProcessCreationEvent[] events) : IProcessCreationEventSource
{
    public string Mode => "fake";

    public bool Disposed { get; private set; }

    public async IAsyncEnumerable<ProcessCreationEvent> ReadEventsAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var e in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return e;
        }
    }

    public ValueTask DisposeAsync()
    {
        Disposed = true;
        return ValueTask.CompletedTask;
    }
}

public class ProcessStartMonitorTests
{
    private static ProcessCreationEvent Started(int pid, string name, string path, string commandLine = "", int parent = 100) =>
        new(pid, parent, name, path, commandLine, DateTimeOffset.UtcNow);

    private static FileAnalyzer Analyzer(DispatcherBench b) =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), FakeVerifier.WithStatus(SignatureStatus.NotSigned), b.Whitelist);

    private static ProcessStartMonitor Monitor(DispatcherBench b, bool shadow = false, BehavioralCorrelationEngine? correlation = null) =>
        new(new FakeProcessCreationEventSource(), b.Dispatcher, correlation ?? new BehavioralCorrelationEngine(), Analyzer(b),
            shadowMode: () => shadow);

    [Theory]
    [InlineData(1234, "svchost.exe", @"C:\Windows\System32\svchost.exe", "-k netsvcs -p")]
    [InlineData(700, "lsass.exe", @"C:\Windows\System32\lsass.exe", "")]
    [InlineData(4, "System", "", "")]
    [InlineData(5100, "Sentinel.Service.exe", @"C:\Program Files\Sentinel\Sentinel.Service.exe", "")]
    public async Task ProtectedSystemOrOwnProcess_IsSkippedWithoutAnalysis(int pid, string name, string path, string commandLine)
    {
        using var b = new DispatcherBench();
        b.Host.Add(pid, 1, name, path);
        var monitor = Monitor(b);

        var outcome = await monitor.InspectAsync(Started(pid, name, path, commandLine));

        Assert.Equal(ProcessStartDecision.Protected, outcome.Decision);
        Assert.Empty(outcome.Findings);
        Assert.Null(outcome.Threat);
        Assert.Empty(b.Raised);
        Assert.Empty(b.Host.Killed);
        Assert.Equal(1, monitor.Skipped);
    }

    [Fact]
    public async Task FakeSvchostInTemp_WithEicar_IsTerminatedAndQuarantined()
    {
        using var b = new DispatcherBench();
        var path = b.Tmp.Write(Path.Combine("Temp", "svchost.exe"), Eicar.CreateTestFileBytes());
        b.Host.Add(4321, 100, "svchost.exe", path).Add(4400, 4321, "child.exe", Path.Combine(b.Tmp.Path, "Temp", "child.exe"));
        var monitor = Monitor(b);

        var outcome = await monitor.InspectAsync(Started(4321, "svchost.exe", path, "svchost.exe -k fake"));

        Assert.Equal(ProcessStartDecision.Act, outcome.Decision);
        Assert.Equal(100, outcome.Score);
        Assert.Contains(outcome.Findings, f => f.Id is "PROC-IMPERSONATION" or "PROC-START-MASQUERADE");
        var threat = Assert.IsType<ThreatEvent>(outcome.Threat);
        Assert.Equal(ProcessStartMonitor.Source, threat.Source);
        Assert.Equal(4321, threat.ProcessId);
        Assert.Equal(ThreatStatus.Terminated, threat.Status);
        Assert.NotNull(threat.QuarantineId);
        Assert.Contains(4321, b.Host.Killed);
        Assert.Contains(4400, b.Host.Killed); // дерево процессов останавливается целиком
        Assert.False(File.Exists(path));
        var record = Assert.Single(await b.Quarantine.ListAsync());
        Assert.Equal(path, record.OriginalPath);
    }

    [Fact]
    public async Task MasqueradeWithoutPayload_GetsElevatedRisk_NoImmunity()
    {
        using var b = new DispatcherBench();
        var monitor = Monitor(b);

        // Файла нет: риск складывается только из маскировки (имя lsass вне System32).
        var outcome = await monitor.InspectAsync(Started(6100, "lsass.exe", @"C:\Users\Public\lsass.exe"));

        Assert.NotEqual(ProcessStartDecision.Protected, outcome.Decision);
        Assert.True(outcome.Score >= 80, $"балл {outcome.Score}");
        Assert.Equal(ProcessStartDecision.Act, outcome.Decision);
        Assert.Contains(outcome.Findings, f => f.Severity >= Severity.High);
    }

    [Fact]
    public async Task ObfuscatedCommandLine_IsRecordedByCorrelationEngine()
    {
        using var b = new DispatcherBench();
        var correlation = new BehavioralCorrelationEngine();
        var monitor = Monitor(b, correlation: correlation);
        const string ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

        var outcome = await monitor.InspectAsync(Started(7100, "powershell.exe", ps,
            "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="));

        Assert.NotNull(outcome.Correlation);
        Assert.Equal(CorrelationChain.WeaponizedArtifact, outcome.Correlation!.Chain);
        Assert.Contains(outcome.Findings, f => f.Id == "PROC-BH-02");
        Assert.Equal(1, correlation.Count);
        Assert.NotEqual(ProcessStartDecision.Clean, outcome.Decision);
    }

    [Fact]
    public async Task CleanProcess_NoFindings_NoEvents()
    {
        using var b = new DispatcherBench();
        var path = b.Tmp.Write(Path.Combine("apps", "notes.exe"), "plain text, not a PE"u8.ToArray());
        var monitor = Monitor(b);

        var outcome = await monitor.InspectAsync(Started(8100, "notes.exe", path, "notes.exe readme.txt"));

        Assert.Equal(ProcessStartDecision.Clean, outcome.Decision);
        Assert.Empty(b.Raised);
    }

    [Fact]
    public async Task AllowedExclusion_SkipsProcess()
    {
        using var b = new DispatcherBench();
        var path = b.Tmp.Write(Path.Combine("Temp", "svchost.exe"), Eicar.CreateTestFileBytes());
        b.Allowed.AddPath(Path.GetDirectoryName(path)!);
        b.Host.Add(4321, 100, "svchost.exe", path);

        var outcome = await Monitor(b).InspectAsync(Started(4321, "svchost.exe", path));

        Assert.Equal(ProcessStartDecision.Allowed, outcome.Decision);
        Assert.Empty(b.Host.Killed);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task ShadowMode_HighRisk_WaitsForUserDecision_NothingTerminated()
    {
        using var b = new DispatcherBench();
        var path = b.Tmp.Write(Path.Combine("Temp", "svchost.exe"), Eicar.CreateTestFileBytes());
        b.Host.Add(4321, 100, "svchost.exe", path);

        var outcome = await Monitor(b, shadow: true).InspectAsync(Started(4321, "svchost.exe", path));

        Assert.Equal(ProcessStartDecision.AskUser, outcome.Decision);
        Assert.Equal(ThreatStatus.PendingDecision, outcome.Threat!.Status);
        Assert.Empty(b.Host.Killed);
        Assert.True(File.Exists(path));
        Assert.Single(b.Dispatcher.Pending());
    }

    [Fact]
    public async Task RunAsync_ProcessesAllEvents_AndHonoursDisabledProtection()
    {
        using var b = new DispatcherBench();
        var source = new FakeProcessCreationEventSource(
            Started(1234, "svchost.exe", @"C:\Windows\System32\svchost.exe"),
            Started(6100, "lsass.exe", @"C:\Users\Public\lsass.exe"));
        var monitor = new ProcessStartMonitor(source, b.Dispatcher, new BehavioralCorrelationEngine(), Analyzer(b));
        var seen = new List<ProcessStartOutcome>();
        monitor.Inspected += seen.Add;

        await monitor.RunAsync(() => false);
        Assert.Empty(seen);

        await monitor.RunAsync(() => true);
        Assert.Equal([ProcessStartDecision.Protected, ProcessStartDecision.Act], seen.Select(s => s.Decision));
        Assert.Equal(2, monitor.Processed);
    }

    [Fact]
    public async Task Runtime_ProcessStartMonitor_RecordsChainAndDispatches()
    {
        await using var bench = new RuntimeBench();
        var ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var source = new FakeProcessCreationEventSource(
            Started(7100, "powershell.exe", ps, "powershell -enc SQBFAFgA"));

        await bench.Runtime.CreateProcessStartMonitor(source).RunAsync(() => true);

        Assert.Equal(1, bench.Runtime.ProcessStartsInspected);
        Assert.Contains(bench.Runtime.GetBehavioralStatus().RecentChains, c => c.Contains("BH-02", StringComparison.Ordinal));
        Assert.Contains(bench.Raised, t => t.Source == ProcessStartMonitor.Source && t.ProcessId == 7100);
    }

    [Fact]
    public async Task Runtime_WithoutSource_ReturnsImmediately()
    {
        await using var bench = new RuntimeBench();
        var logs = new List<string>();
        bench.Runtime.Log += logs.Add;

        await bench.Runtime.RunProcessStartMonitorAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains(logs, l => l.Contains("недоступен", StringComparison.Ordinal));
    }
}

public class PollingProcessCreationEventSourceTests
{
    [Fact]
    public void FirstTick_IsBaseline_ThenOnlyNewProcessesAreReported()
    {
        var current = new List<ProcessIdentity> { new(10, 1, "a.exe"), new(11, 1, "b.exe") };
        var enriched = new List<int>();
        var source = new PollingProcessCreationEventSource(
            () => current.ToArray(),
            id =>
            {
                enriched.Add(id.Pid);
                return new ProcessCreationEvent(id.Pid, id.ParentPid, id.Name, $@"C:\Apps\{id.Name}", $"{id.Name} --x", DateTimeOffset.UtcNow);
            });

        Assert.Empty(source.Poll());

        current.Add(new ProcessIdentity(12, 10, "c.exe"));
        var created = Assert.Single(source.Poll());
        Assert.Equal(12, created.ProcessId);
        Assert.Equal(10, created.ParentProcessId);
        Assert.Equal(@"C:\Apps\c.exe", created.ExecutablePath);
        Assert.Equal([12], enriched); // подробности — только для нового PID

        Assert.Empty(source.Poll());

        // PID 11 завершился и выдан повторно другому образу — это новый процесс.
        current.RemoveAll(p => p.Pid == 11);
        Assert.Empty(source.Poll());
        current.Add(new ProcessIdentity(11, 12, "d.exe"));
        Assert.Equal("d.exe", Assert.Single(source.Poll()).ProcessName);
    }

    [Fact]
    public void EnrichFailure_ReportsKnownFields()
    {
        var current = new List<ProcessIdentity>();
        var source = new PollingProcessCreationEventSource(() => current.ToArray(), _ => throw new InvalidOperationException("exited"));
        source.Poll();
        current.Add(new ProcessIdentity(20, 4, "gone.exe"));

        var created = Assert.Single(source.Poll());
        Assert.Equal("gone.exe", created.ProcessName);
        Assert.Equal(string.Empty, created.ExecutablePath);
    }

    [Fact]
    public async Task ReadEventsAsync_StopsOnCancellation()
    {
        var source = new PollingProcessCreationEventSource(() => [], _ => throw new InvalidOperationException(), TimeSpan.FromMilliseconds(10));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var count = 0;
        await foreach (var _ in source.ReadEventsAsync(cts.Token))
        {
            count++;
        }

        Assert.Equal(0, count);
    }
}

public class ProcessStartCorrelationTests
{
    [Fact]
    public void DroppedUnsignedFile_ExecutedImmediately_IsBh04()
    {
        var engine = new BehavioralCorrelationEngine();
        engine.ReportFileWritten(@"C:\Users\u\AppData\Local\Temp\upd.exe", false);

        var finding = engine.ReportProcessStart(@"C:\Users\u\AppData\Local\Temp\upd.exe", "upd.exe", false);

        Assert.Equal(CorrelationChain.DropAndExecute, finding!.Chain);
    }

    [Fact]
    public void FreshUnsignedAutorunTarget_Started_IsBh03()
    {
        var engine = new BehavioralCorrelationEngine();
        engine.ReportAutorunEntry("Run", @"C:\Users\u\AppData\Roaming\svc\host.exe", false);

        var finding = engine.ReportProcessStart(@"C:\Users\u\AppData\Roaming\svc\host.exe", "host.exe", false);

        Assert.Equal(CorrelationChain.PersistenceUnsignedProfile, finding!.Chain);
    }

    [Fact]
    public void SignedOrOrdinaryStart_IsNotCorrelated()
    {
        var engine = new BehavioralCorrelationEngine();
        engine.ReportFileWritten(@"C:\Users\u\AppData\Local\Temp\setup.exe", true);

        Assert.Null(engine.ReportProcessStart(@"C:\Users\u\AppData\Local\Temp\setup.exe", "setup.exe /S", true));
        Assert.Null(engine.ReportProcessStart(@"C:\Program Files\App\app.exe", "app.exe --open file.txt", false));
    }
}
