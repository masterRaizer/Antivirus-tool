using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Detection;
using Sentinel.Core.Realtime;
using Sentinel.Core.Remediation;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class AllowedExclusionsTests
{
    [Fact]
    public void Load_MissingFile_ReturnsEmpty()
    {
        using var tmp = new TempDir();
        Assert.True(AllowedExclusionStore.ForDataDirectory(tmp.Path).Load().IsEmpty);
    }

    [Fact]
    public void Load_ReadsPathsAndProcesses_WithCommentsAndAnyCase()
    {
        using var tmp = new TempDir();
        var file = tmp.WriteText("allowed_exclusions.json", """
            {
              // пользовательские настройки
              "Paths": [ "C:\\Dev\\Tools", "  ", "c:\\dev\\tools" ],
              "processes": [ "mytool.exe", "D:\\Apps\\Agent\\agent.exe" ],
            }
            """);
        var allowed = new AllowedExclusionStore(file).Load();

        Assert.Equal(["C:\\Dev\\Tools"], allowed.Paths);
        Assert.True(allowed.IsPathAllowed(@"c:\dev\tools\sub\build.exe"));
        Assert.True(allowed.IsPathAllowed(@"C:\Dev\Tools"));
        Assert.False(allowed.IsPathAllowed(@"C:\Dev\ToolsEvil\x.exe"));
        Assert.True(allowed.IsProcessAllowed("MyTool.exe", @"C:\Temp\mytool.exe"));
        Assert.True(allowed.IsProcessAllowed(null, @"d:\apps\agent\agent.exe"));
        Assert.False(allowed.IsProcessAllowed("agent.exe", @"C:\Temp\agent.exe"));
    }

    [Fact]
    public void Load_CorruptedFile_Throws()
    {
        using var tmp = new TempDir();
        var file = tmp.WriteText("allowed_exclusions.json", "{ not json");
        Assert.Throws<System.Text.Json.JsonException>(() => new AllowedExclusionStore(file).Load());
    }

    [Fact]
    public void AddPath_PersistsAtomically_AndDeduplicates()
    {
        using var tmp = new TempDir();
        var store = AllowedExclusionStore.ForDataDirectory(tmp.Path);
        store.AddPath(@"C:\Work");
        store.AddPath(@"c:\work");
        store.AddProcess("tool.exe");

        var reloaded = AllowedExclusionStore.ForDataDirectory(tmp.Path).Load();
        Assert.Single(reloaded.Paths);
        Assert.Equal(["tool.exe"], reloaded.Processes);
        Assert.False(File.Exists(store.Path + ".tmp"));
    }

    [Theory]
    [InlineData(DefenderExclusionKind.Path, @"C:\Dev\Tools", true)]
    [InlineData(DefenderExclusionKind.Path, @"C:\Dev\Tools\bin", true)]
    [InlineData(DefenderExclusionKind.Path, @"C:\Dev", false)] // шире разрешённого
    [InlineData(DefenderExclusionKind.Path, @"C:\Dev\Tools\*", false)]
    [InlineData(DefenderExclusionKind.Process, "mytool.exe", true)]
    [InlineData(DefenderExclusionKind.Process, "powershell.exe", false)]
    [InlineData(DefenderExclusionKind.Process, @"C:\Dev\Tools\cl.exe", true)]
    [InlineData(DefenderExclusionKind.Extension, "exe", false)]
    [InlineData(DefenderExclusionKind.IpAddress, "10.0.0.1", false)]
    public void IsAllowed_MatchesDefenderExclusions(DefenderExclusionKind kind, string value, bool expected)
    {
        var allowed = new AllowedExclusions { Paths = [@"C:\Dev\Tools"], Processes = ["mytool.exe"] };
        Assert.Equal(expected, allowed.IsAllowed(new DefenderExclusion(kind, value, "key")));
    }
}

/// <summary>Стенд диспетчера: реальные карантин и движок нейтрализации поверх синтетических провайдеров.</summary>
internal sealed class DispatcherBench : IDisposable
{
    public TempDir Tmp { get; } = new();
    public FakeProcessHost Host { get; } = new();
    public InMemoryRegistryProvider Registry { get; } = new();
    public FakeDefender Defender { get; } = new();
    public SystemWhitelist Whitelist { get; }
    public QuarantineManager Quarantine { get; }
    public RemediationEngine Engine { get; }
    public AllowedExclusionStore Allowed { get; }
    public RealtimeEventDispatcher Dispatcher { get; }
    public List<ThreatEvent> Raised { get; } = [];
    public List<ThreatEvent> Updated { get; } = [];

    public string DataDir => Path.Combine(Tmp.Path, "data");

    public DispatcherBench()
    {
        Whitelist = new SystemWhitelist(FakeVerifier.WithStatus(SignatureStatus.NotSigned), new WhitelistOptions());
        Quarantine = new QuarantineManager(Whitelist, new QuarantineOptions { QuarantineDirectory = Path.Combine(DataDir, "Quarantine") });
        Engine = new RemediationEngine(
            Whitelist,
            new RemediationOptions { RollbackManifestPath = Path.Combine(DataDir, "rollback_manifest.json"), CurrentProcessId = 999_999 },
            Host, Host, Registry, new FakeTaskEditor(), Defender);
        Allowed = AllowedExclusionStore.ForDataDirectory(DataDir);
        Dispatcher = new RealtimeEventDispatcher(Quarantine, Engine, Allowed);
        Dispatcher.ThreatRaised += Raised.Add;
        Dispatcher.ThreatUpdated += Updated.Add;
    }

    public FileScanResult Flagged(string name, Severity severity)
    {
        var path = Tmp.Write(Path.Combine("drop", name), Eicar.CreateTestFileBytes());
        return new FileScanResult
        {
            Path = path,
            Size = new FileInfo(path).Length,
            Sha256 = Hashing.FileHasher.ComputeSha256(path),
            Entropy = 4.5,
            Verdict = severity >= Severity.High ? Verdict.Malicious : Verdict.Suspicious,
            Detections = [new Scanning.Detection("Test.Synthetic", severity, "test", DetectionSource.Signature, "SNT-TEST-0001", "Синтетическая находка.", [])],
        };
    }

    public void Dispose()
    {
        Quarantine.Dispose();
        Tmp.Dispose();
    }
}

public class RealtimeEventDispatcherTests
{
    [Theory]
    [InlineData(Severity.High)]
    [InlineData(Severity.Critical)]
    public async Task File_HighOrCritical_IsQuarantinedImmediately(Severity severity)
    {
        using var b = new DispatcherBench();
        var scan = b.Flagged("evil.exe", severity);

        var threat = await b.Dispatcher.DispatchFileAsync(scan);

        Assert.NotNull(threat);
        Assert.Equal(ThreatStatus.Quarantined, threat.Status);
        Assert.NotNull(threat.QuarantineId);
        Assert.False(File.Exists(scan.Path));
        Assert.Empty(b.Dispatcher.Pending());
        Assert.Equal(threat, Assert.Single(b.Raised));
        Assert.Contains("SNT-TEST-0001", threat.Reason);
        Assert.Equal(scan.Sha256, threat.Sha256);
    }

    [Fact]
    public async Task File_Medium_WaitsForUserDecision_AndStaysOnDisk()
    {
        using var b = new DispatcherBench();
        var scan = b.Flagged("maybe.exe", Severity.Medium);

        var threat = await b.Dispatcher.DispatchFileAsync(scan);

        Assert.Equal(ThreatStatus.PendingDecision, threat!.Status);
        Assert.True(File.Exists(scan.Path));
        Assert.Equal(threat.Id, Assert.Single(b.Dispatcher.Pending()).Id);
    }

    [Fact]
    public async Task File_Low_IsOnlyLogged()
    {
        using var b = new DispatcherBench();
        var threat = await b.Dispatcher.DispatchFileAsync(b.Flagged("note.txt", Severity.Low));

        Assert.Equal(ThreatStatus.Detected, threat!.Status);
        Assert.Empty(b.Dispatcher.Pending());
    }

    [Fact]
    public async Task File_Clean_ProducesNoEvent()
    {
        using var b = new DispatcherBench();
        var clean = b.Flagged("ok.txt", Severity.High) with { Verdict = Verdict.Clean, Detections = [] };
        Assert.Null(await b.Dispatcher.DispatchFileAsync(clean));
        Assert.Empty(b.Raised);
    }

    [Fact]
    public async Task PendingFile_ReportedAgain_IsNotDuplicated()
    {
        using var b = new DispatcherBench();
        var scan = b.Flagged("maybe.exe", Severity.Medium);

        var first = await b.Dispatcher.DispatchFileAsync(scan);
        var second = await b.Dispatcher.DispatchFileAsync(scan);

        Assert.Equal(first!.Id, second!.Id);
        Assert.Single(b.Raised);
        Assert.Single(b.Dispatcher.Snapshot());
    }

    [Fact]
    public async Task Resolve_Quarantine_IsolatesPendingFile()
    {
        using var b = new DispatcherBench();
        var scan = b.Flagged("maybe.exe", Severity.Medium);
        var pending = await b.Dispatcher.DispatchFileAsync(scan);

        var resolved = await b.Dispatcher.ResolveAsync(pending!.Id, ThreatDecision.Quarantine);

        Assert.Equal(ThreatStatus.Quarantined, resolved.Status);
        Assert.False(File.Exists(scan.Path));
        Assert.Empty(b.Dispatcher.Pending());
        Assert.Equal(resolved, Assert.Single(b.Updated));
        var record = Assert.Single(await b.Quarantine.ListAsync());
        Assert.Equal(resolved.QuarantineId, record.Id);
    }

    [Fact]
    public async Task Resolve_Allow_AddsToExclusions_AndSuppressesFutureEvents()
    {
        using var b = new DispatcherBench();
        var scan = b.Flagged("tool.exe", Severity.Medium);
        var pending = await b.Dispatcher.DispatchFileAsync(scan);

        var resolved = await b.Dispatcher.ResolveAsync(pending!.Id, ThreatDecision.Allow);

        Assert.Equal(ThreatStatus.Allowed, resolved.Status);
        Assert.True(File.Exists(scan.Path));
        Assert.Contains(scan.Path, b.Allowed.Load().Paths);
        Assert.Null(await b.Dispatcher.DispatchFileAsync(scan));

        // Даже критичная находка по разрешённому пути не изолируется.
        Assert.Null(await b.Dispatcher.DispatchFileAsync(scan with { Detections = b.Flagged("x", Severity.Critical).Detections }));
        Assert.True(File.Exists(scan.Path));
    }

    [Fact]
    public async Task Resolve_Twice_IsIdempotent_AndUnknownIdThrows()
    {
        using var b = new DispatcherBench();
        var pending = await b.Dispatcher.DispatchFileAsync(b.Flagged("maybe.exe", Severity.Medium));

        await b.Dispatcher.ResolveAsync(pending!.Id, ThreatDecision.Quarantine);
        var again = await b.Dispatcher.ResolveAsync(pending.Id, ThreatDecision.Allow);

        Assert.Equal(ThreatStatus.Quarantined, again.Status);
        Assert.True(b.Allowed.Load().IsEmpty);
        Assert.Single(b.Updated);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => b.Dispatcher.ResolveAsync("nope", ThreatDecision.Allow));
    }

    [Fact]
    public async Task Process_High_TreeIsTerminated_AndImageQuarantined()
    {
        using var b = new DispatcherBench();
        var scan = b.Flagged("miner.exe", Severity.High);
        b.Host.Add(900, 4, "explorer.exe").Add(4100, 900, "miner.exe", scan.Path).Add(4101, 4100, "worker.exe");
        var entry = new ProcessAuditEntry(
            b.Host.GetProcesses().Single(p => p.Pid == 4100),
            [AuditFinding.Create("PROC-MINER-CMD", Severity.High, "Майнер", "Командная строка майнера.")],
            scan);

        var threat = await b.Dispatcher.DispatchProcessAsync(entry);

        Assert.Equal(ThreatStatus.Terminated, threat!.Status);
        Assert.Equal([4100, 4101], b.Host.Killed.Order());
        Assert.True(b.Host.IsRunning(900));
        Assert.False(File.Exists(scan.Path));
        Assert.NotNull(threat.QuarantineId);
        Assert.Equal(4100, threat.ProcessId);
    }

    [Fact]
    public async Task Process_Medium_IsQueued_AndAllowKeepsItRunning()
    {
        using var b = new DispatcherBench();
        b.Host.Add(5000, 4, "tool.exe", @"C:\Tools\tool.exe");
        var entry = new ProcessAuditEntry(
            b.Host.GetProcesses()[0],
            [AuditFinding.Create("PROC-HIGH-CPU", Severity.Medium, "Высокая нагрузка", "CPU 95%.")],
            null);

        var pending = await b.Dispatcher.DispatchProcessAsync(entry);
        Assert.Equal(ThreatStatus.PendingDecision, pending!.Status);
        Assert.Empty(b.Host.Killed);

        var resolved = await b.Dispatcher.ResolveAsync(pending.Id, ThreatDecision.Allow);
        Assert.Equal(ThreatStatus.Allowed, resolved.Status);
        Assert.True(b.Host.IsRunning(5000));
        Assert.Null(await b.Dispatcher.DispatchProcessAsync(entry));
    }

    [Fact]
    public async Task Exclusion_High_IsRemoved_Medium_IsQueued_AllowedIsIgnored()
    {
        using var b = new DispatcherBench();
        var wide = new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Users\Public", "key");
        var narrow = new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Dev\Tools", "key");
        var mine = new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Work", "key");
        b.Defender.Exclusions.AddRange([(wide.Kind, wide.Value), (narrow.Kind, narrow.Value), (mine.Kind, mine.Value)]);
        b.Allowed.AddPath(@"C:\Work");

        var removed = await b.Dispatcher.DispatchExclusionAsync(wide, AuditFinding.Create("CFG-DEFENDER-EXCL", Severity.High, "t", "d"));
        var queued = await b.Dispatcher.DispatchExclusionAsync(narrow, AuditFinding.Create("CFG-DEFENDER-EXCL", Severity.Medium, "t", "d"));
        var ignored = await b.Dispatcher.DispatchExclusionAsync(mine, AuditFinding.Create("CFG-DEFENDER-EXCL", Severity.High, "t", "d"));

        Assert.Equal(ThreatStatus.Cleaned, removed!.Status);
        Assert.Equal(ThreatStatus.PendingDecision, queued!.Status);
        Assert.Null(ignored);
        Assert.Equal([(narrow.Kind, narrow.Value), (mine.Kind, mine.Value)], b.Defender.Exclusions);
        Assert.Single(b.Engine.ListRollbackEntries());
    }

    [Fact]
    public void DryRunEngine_IsRejected()
    {
        using var b = new DispatcherBench();
        var dry = new RemediationEngine(b.Whitelist,
            new RemediationOptions { RollbackManifestPath = Path.Combine(b.DataDir, "r.json"), DryRun = true });
        Assert.Throws<ArgumentException>(() => new RealtimeEventDispatcher(b.Quarantine, dry, b.Allowed));
    }
}

public class ResponseCoordinatorAllowedTests
{
    [Fact]
    public async Task HandleConfig_KeepsUserAllowedExclusions_AndTheirFiles()
    {
        using var b = new DispatcherBench();
        var allowedDir = Path.Combine(b.Tmp.Path, "work");
        var foreignDir = Path.Combine(b.Tmp.Path, "public");
        var mine = b.Tmp.Write(Path.Combine("work", "tool.exe"), Eicar.CreateTestFileBytes());
        var evil = b.Tmp.Write(Path.Combine("public", "evil.exe"), Eicar.CreateTestFileBytes());
        var keep = new DefenderExclusion(DefenderExclusionKind.Path, allowedDir, "Paths");
        var drop = new DefenderExclusion(DefenderExclusionKind.Path, foreignDir, "Paths");
        var keepProcess = new DefenderExclusion(DefenderExclusionKind.Process, "mytool.exe", "Processes");
        b.Defender.Exclusions.AddRange([(keep.Kind, keep.Value), (drop.Kind, drop.Value), (keepProcess.Kind, keepProcess.Value)]);

        var analyzer = new FileAnalyzer(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)),
            FakeVerifier.WithStatus(SignatureStatus.NotSigned), b.Whitelist);
        var config = new ConfigAuditReport(
        [
            new ConfigFinding(ConfigArea.DefenderExclusion, AuditFinding.Create("CFG-DEFENDER-EXCL", Severity.High, "a", "a")),
            new ConfigFinding(ConfigArea.DefenderExclusion, AuditFinding.Create("CFG-DEFENDER-EXCL", Severity.High, "b", "b")),
            new ConfigFinding(ConfigArea.DefenderExclusion, AuditFinding.Create("CFG-DEFENDER-EXCL", Severity.High, "c", "c")),
        ])
        { DefenderExclusions = [keep, drop, keepProcess] };
        var scan = new ExclusionPriorityScanner(analyzer, new ProcessAuditor(new ProcessAuditorOptions(), analyzer)).Scan(config.DefenderExclusions, []);
        var report = new ReportBuilder("audit-config --remediate");
        report.AddConfigAudit(config).AddExclusionScan(scan);
        var allowed = new AllowedExclusions { Paths = [allowedDir], Processes = ["mytool.exe"] };

        await new ResponseCoordinator(b.Quarantine, b.Engine, report, allowed: allowed).HandleConfigAsync(config, scan);

        Assert.Equal([(keep.Kind, keep.Value), (keepProcess.Kind, keepProcess.Value)], b.Defender.Exclusions);
        Assert.True(File.Exists(mine));
        Assert.False(File.Exists(evil));
        var built = report.Build(TimeSpan.Zero, "remediate");
        Assert.Equal(FindingActionStatus.Skipped, built.Findings.Single(f => f.Key == ReportBuilder.ExclusionKey(keep)).ActionStatus);
        Assert.Equal(ResponseCoordinator.AllowedByUserMessage, built.Findings.Single(f => f.Key == ReportBuilder.FileKey(mine)).ActionMessage);
        Assert.Equal(FindingActionStatus.Cleaned, built.Findings.Single(f => f.Key == ReportBuilder.ExclusionKey(drop)).ActionStatus);
        Assert.Equal(FindingActionStatus.Quarantined, built.Findings.Single(f => f.Key == ReportBuilder.FileKey(evil)).ActionStatus);
    }
}
