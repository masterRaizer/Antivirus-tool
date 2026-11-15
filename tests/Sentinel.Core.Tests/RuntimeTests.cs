using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Detection;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Remediation;
using Sentinel.Core.Reporting;
using Sentinel.Core.Runtime;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

internal sealed class FakeTelemetry : ITelemetryProvider
{
    public TelemetryReading Next { get; set; } = new(25, 50, 5, 4L << 30, 8L << 30);

    public bool Disposed { get; private set; }

    public TelemetryReading Read() => Next;

    public void Dispose() => Disposed = true;
}

/// <summary>Стенд рантайма: настоящие анализатор, карантин и движок; платформенные источники — синтетические.</summary>
internal sealed class RuntimeBench : IAsyncDisposable
{
    public TempDir Tmp { get; } = new();
    public FakeProcessHost Host { get; } = new();
    public InMemoryRegistryProvider Registry { get; } = new();
    public FakeDefender Defender { get; } = new();
    public FakeTelemetry Telemetry { get; } = new();
    public List<PersistenceEntry> Persistence { get; } = [];
    public List<(DefenderExclusion Exclusion, Severity Severity)> Exclusions { get; } = [];
    public SentinelRuntime Runtime { get; }
    public List<ScanProgress> Progress { get; } = [];
    public List<ThreatEvent> Raised { get; } = [];

    public string DataDir => Path.Combine(Tmp.Path, "data");

    public string ScanDir => Path.Combine(Tmp.Path, "scan");

    public RuntimeBench(bool withPlatform = true, FileMonitorOptions? monitor = null)
    {
        var verifier = FakeVerifier.WithStatus(SignatureStatus.NotSigned);
        var whitelist = new SystemWhitelist(verifier, new WhitelistOptions());
        var analyzer = new FileAnalyzer(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), verifier, whitelist);
        Directory.CreateDirectory(ScanDir);
        Runtime = new SentinelRuntime(new SentinelRuntimeOptions
        {
            DataDirectory = DataDir,
            Mode = "standalone",
            Analyzer = analyzer,
            Quarantine = new QuarantineManager(whitelist, new QuarantineOptions { QuarantineDirectory = Path.Combine(DataDir, "Quarantine") }),
            Engine = withPlatform
                ? new RemediationEngine(whitelist,
                    new RemediationOptions { RollbackManifestPath = Path.Combine(DataDir, "rollback_manifest.json"), CurrentProcessId = 999_999 },
                    Host, Host, Registry, new FakeTaskEditor(), Defender)
                : null,
            Processes = withPlatform ? Host : null,
            PersistenceAudit = withPlatform ? () => new PersistenceAuditReport(Persistence.ToArray()) : null,
            ConfigAudit = withPlatform
                ? () => new ConfigAuditReport(Exclusions
                    .Select(e => new ConfigFinding(ConfigArea.DefenderExclusion, AuditFinding.Create("CFG-DEFENDER-EXCL", e.Severity, "Исключение", "Нештатное исключение.")))
                    .ToArray()) { DefenderExclusions = Exclusions.Select(e => e.Exclusion).ToArray() }
                : null,
            Telemetry = Telemetry,
            Monitor = monitor ?? new FileMonitorOptions(),
            QuickScanRoots = [new ScanRoot(ScanDir)],
            FullScanRoots = [new ScanRoot(ScanDir)],
            RulesLoaded = 7,
        });
        Runtime.ScanProgressChanged += p => { lock (Progress) { Progress.Add(p); } };
        Runtime.ThreatRaised += t => { lock (Raised) { Raised.Add(t); } };
    }

    public string Drop(string name, byte[] content) => Tmp.Write(Path.Combine("scan", name), content);

    public async Task<ScanProgress> ScanAsync(ScanRequest request)
    {
        var started = await Runtime.StartScanAsync(request);
        Assert.True(started.Success, started.Message);
        await Runtime.ScanCompletion.WaitAsync(TimeSpan.FromSeconds(30));
        return Runtime.CurrentScan;
    }

    public static async Task WaitAsync(Func<bool> condition, string what = "условие")
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Не дождались: {what}.");
            await Task.Delay(20);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await Runtime.DisposeAsync();
        Tmp.Dispose();
    }
}

public class SentinelRuntimeScanTests
{
    [Fact]
    public async Task CustomScan_QuarantinesMalware_SavesReport_AndReportsProgress()
    {
        await using var b = new RuntimeBench();
        var eicar = b.Drop("eicar.com", Eicar.CreateTestFileBytes());
        var clean = b.Drop(Path.Combine("docs", "readme.txt"), "Hello, Sentinel!"u8.ToArray());
        b.Drop("stub.exe", SyntheticArtifacts.BuildPe());

        var done = await b.ScanAsync(new ScanRequest(ScanMode.Custom, b.ScanDir));

        Assert.Equal(ScanState.Completed, done.State);
        Assert.Equal(3, done.Scanned);
        Assert.Equal(3, done.Total);
        Assert.Equal(100, done.Percent);
        Assert.Equal(1, done.Threats);
        Assert.NotNull(done.ReportId);
        Assert.False(File.Exists(eicar));
        Assert.True(File.Exists(clean));

        var threat = Assert.Single(await b.Runtime.GetThreatsAsync());
        Assert.Equal(ThreatStatus.Quarantined, threat.Status);
        Assert.Equal("scan", threat.Source);
        Assert.Equal(eicar, Assert.Single(await b.Runtime.GetQuarantineAsync()).OriginalPath);

        lock (b.Progress)
        {
            Assert.Contains(b.Progress, p => p.State == ScanState.Running && p.Stage == "Файлы" && p.CurrentItem.StartsWith(b.ScanDir, StringComparison.Ordinal));
            Assert.Equal(ScanState.Completed, b.Progress[^1].State);
        }

        var summary = Assert.Single(await b.Runtime.GetReportsAsync());
        Assert.Equal(done.ReportId, summary.Id);
        Assert.Equal(3, summary.Checked);
        Assert.Equal(1, summary.Found);
        Assert.Equal(1, summary.Quarantined);

        var html = await b.Runtime.ExportReportAsync(summary.Id, ReportFormat.Html);
        var json = await b.Runtime.ExportReportAsync(summary.Id, ReportFormat.Json);
        Assert.EndsWith(".html", html.FileName);
        Assert.Contains("<html", html.Content, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("eicar.com", html.Content);
        var report = ReportGenerator.FromJson(json.Content);
        Assert.Equal(FindingActionStatus.Quarantined, Assert.Single(report.Findings).ActionStatus);

        var status = await b.Runtime.GetStatusAsync();
        Assert.Equal(3, status.FilesChecked);
        Assert.Equal(1, status.Quarantined);
        Assert.Equal(7, status.RulesLoaded);
        Assert.True(status.RemediationAvailable);
    }

    [Fact]
    public async Task Restore_ReturnsFileFromQuarantine()
    {
        await using var b = new RuntimeBench();
        var eicar = b.Drop("eicar.com", Eicar.CreateTestFileBytes());
        await b.ScanAsync(new ScanRequest(ScanMode.Custom, eicar));
        var item = Assert.Single(await b.Runtime.GetQuarantineAsync());

        var restored = await b.Runtime.RestoreQuarantineAsync(item.Id);

        Assert.True(restored.Success, restored.Message);
        Assert.Equal(Eicar.CreateTestFileBytes(), File.ReadAllBytes(eicar));
        Assert.True(Assert.Single(await b.Runtime.GetQuarantineAsync()).Restored);
        Assert.False((await b.Runtime.RestoreQuarantineAsync("missing")).Success);
    }

    [Fact]
    public async Task QuickScan_CoversProcessesAutorunsAndExclusions_AndRollbackCanBeUndone()
    {
        await using var b = new RuntimeBench();
        var miner = b.Drop("miner.exe", Eicar.CreateTestFileBytes());
        b.Host.Add(900, 4, "explorer.exe").Add(4100, 900, "miner.exe", miner);
        var run = new RegistryKeyPath(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run");
        b.Registry.Set(run, "Updater", @"C:\Users\Public\upd.exe", RegistryValueKind.Sz);
        b.Persistence.Add(new PersistenceEntry
        {
            Kind = PersistenceKind.RegistryRun,
            Location = run.ToString(),
            Name = "Updater",
            Command = @"C:\Users\Public\upd.exe",
            Findings = [AuditFinding.Create("PERS-USER-WRITABLE", Severity.High, "Автозапуск из каталога пользователя", "Подозрительно.")],
        });
        var wide = new DefenderExclusion(DefenderExclusionKind.Path, Path.Combine(b.Tmp.Path, "nowhere"), "Paths");
        var mine = new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Work", "Paths");
        b.Exclusions.AddRange([(wide, Severity.High), (mine, Severity.High)]);
        b.Defender.Exclusions.AddRange([(wide.Kind, wide.Value), (mine.Kind, mine.Value)]);
        b.Runtime.Dispatcher.AllowedStore.AddPath(@"C:\Work");

        var done = await b.ScanAsync(new ScanRequest(ScanMode.Quick));

        Assert.Equal(ScanState.Completed, done.State);
        var threats = await b.Runtime.GetThreatsAsync();
        Assert.Contains(threats, t => t.Kind == ThreatKind.Process && t.Status == ThreatStatus.Terminated && t.ProcessId == 4100);
        Assert.Contains(threats, t => t.Kind == ThreatKind.Persistence && t.Status == ThreatStatus.Cleaned);
        Assert.Contains(threats, t => t.Kind == ThreatKind.DefenderExclusion && t.Status == ThreatStatus.Cleaned);
        Assert.Equal([4100], b.Host.Killed);
        Assert.False(File.Exists(miner));
        Assert.Null(b.Registry.GetValue(run, "Updater"));
        Assert.Equal([(mine.Kind, mine.Value)], b.Defender.Exclusions); // разрешённое пользователем исключение сохранено
        lock (b.Progress)
        {
            Assert.Contains(b.Progress, p => p.Stage == "Автозагрузка и реестр" && p.CurrentItem.Contains("CurrentVersion", StringComparison.Ordinal));
            Assert.Contains(b.Progress, p => p.Stage == "Процессы");
        }

        var rollback = await b.Runtime.GetRollbackAsync();
        Assert.Equal(2, rollback.Count);
        var registryEntry = rollback.Single(r => r.Kind == nameof(RollbackKind.RegistryValue));
        var undone = await b.Runtime.UndoRollbackAsync(registryEntry.Id);
        Assert.True(undone.Success, undone.Message);
        Assert.NotNull(b.Registry.GetValue(run, "Updater"));
        Assert.True((await b.Runtime.GetRollbackAsync()).Single(r => r.Id == registryEntry.Id).Undone);
    }

    [Fact]
    public async Task PauseResumeStop_ControlRunningScan()
    {
        await using var b = new RuntimeBench();
        for (var i = 0; i < 40; i++)
        {
            b.Drop($"f{i:00}.txt", "data"u8.ToArray());
        }

        // Пауза ставится из обработчика первого же события этапа «Файлы» — рабочий поток остановится на следующем объекте.
        var paused = 0;
        b.Runtime.ScanProgressChanged += p =>
        {
            if (p is { State: ScanState.Running, Stage: "Файлы" } && Interlocked.Exchange(ref paused, 1) == 0)
            {
                Assert.True(b.Runtime.PauseScanAsync().GetAwaiter().GetResult().Success);
            }
        };

        Assert.False((await b.Runtime.PauseScanAsync()).Success);
        Assert.True((await b.Runtime.StartScanAsync(new ScanRequest(ScanMode.Custom, b.ScanDir))).Success);
        Assert.False((await b.Runtime.StartScanAsync(new ScanRequest(ScanMode.Quick))).Success); // вторая проверка отклоняется
        await RuntimeBench.WaitAsync(() => b.Runtime.CurrentScan.State == ScanState.Paused, "пауза");
        var frozen = b.Runtime.CurrentScan.Scanned;
        await Task.Delay(150);
        Assert.Equal(frozen, b.Runtime.CurrentScan.Scanned);
        Assert.True(frozen < 40);

        Assert.True((await b.Runtime.ResumeScanAsync()).Success);
        await b.Runtime.ScanCompletion.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(ScanState.Completed, b.Runtime.CurrentScan.State);
        Assert.Equal(40, b.Runtime.CurrentScan.Scanned);

        // Остановка приостановленной проверки.
        Interlocked.Exchange(ref paused, 0);
        Assert.True((await b.Runtime.StartScanAsync(new ScanRequest(ScanMode.Full))).Success);
        await RuntimeBench.WaitAsync(() => b.Runtime.CurrentScan.State == ScanState.Paused, "вторая пауза");
        Assert.True((await b.Runtime.StopScanAsync()).Success);
        await b.Runtime.ScanCompletion.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(ScanState.Cancelled, b.Runtime.CurrentScan.State);
        Assert.True(b.Runtime.CurrentScan.Scanned < 40);
        Assert.Equal(2, (await b.Runtime.GetReportsAsync()).Count); // отчёт сохраняется и для остановленной проверки
    }

    [Fact]
    public async Task CustomScan_InvalidPath_IsRejected()
    {
        await using var b = new RuntimeBench();
        Assert.False((await b.Runtime.StartScanAsync(new ScanRequest(ScanMode.Custom))).Success);
        Assert.False((await b.Runtime.StartScanAsync(new ScanRequest(ScanMode.Custom, Path.Combine(b.Tmp.Path, "absent")))).Success);
        Assert.Equal(ScanState.Idle, b.Runtime.CurrentScan.State);
    }

    [Fact]
    public async Task WithoutPlatformProviders_RuntimeDegradesGracefully()
    {
        await using var b = new RuntimeBench(withPlatform: false);
        b.Drop("eicar.com", Eicar.CreateTestFileBytes());

        var done = await b.ScanAsync(new ScanRequest(ScanMode.Quick));

        Assert.Equal(ScanState.Completed, done.State);
        Assert.Equal(1, done.Threats); // карантин работает на любой ОС
        Assert.Empty(await b.Runtime.GetProcessesAsync());
        Assert.NotNull((await b.Runtime.GetStartupAsync()).Note);
        Assert.False((await b.Runtime.UndoRollbackAsync("x")).Success);
        Assert.False((await b.Runtime.CleanStartupItemAsync("x")).Success);
        Assert.False((await b.Runtime.GetStatusAsync()).RemediationAvailable);
    }
}

public class SentinelRuntimeRealtimeTests
{
    [Fact]
    public async Task InspectFile_QuarantinesMalware_AndIgnoresCleanOrMissing()
    {
        await using var b = new RuntimeBench();
        var eicar = b.Drop("dropped.com", Eicar.CreateTestFileBytes());
        var clean = b.Drop("note.txt", "ok"u8.ToArray());

        var threat = await b.Runtime.InspectFileAsync(eicar);

        Assert.Equal(ThreatStatus.Quarantined, threat!.Status);
        Assert.Equal("realtime", threat.Source);
        Assert.Null(await b.Runtime.InspectFileAsync(clean));
        Assert.Null(await b.Runtime.InspectFileAsync(eicar)); // файл уже в карантине
        Assert.Equal(2, (await b.Runtime.GetStatusAsync()).FilesChecked);
    }

    [Fact]
    public async Task FileMonitor_DetectsDroppedFile_AndRespectsRealtimeToggle()
    {
        var watched = new TempDir();
        await using var b = new RuntimeBench(monitor: new FileMonitorOptions { Directories = [watched.Path], Debounce = TimeSpan.FromMilliseconds(100) });
        using var cts = new CancellationTokenSource();
        var loop = b.Runtime.RunFileMonitorAsync(cts.Token);
        try
        {
            await RuntimeBench.WaitAsync(() => b.Runtime.GetStatusAsync().GetAwaiter().GetResult().WatchedDirectories.Count == 1, "запуск наблюдения");

            var dropped = watched.Write("payload.com", Eicar.CreateTestFileBytes());
            await RuntimeBench.WaitAsync(() => { lock (b.Raised) { return b.Raised.Count == 1; } }, "находка монитора");
            Assert.False(File.Exists(dropped));
            lock (b.Raised)
            {
                Assert.Equal(ThreatStatus.Quarantined, b.Raised[0].Status);
            }

            // Защита приостановлена — наблюдение снято, новый файл остаётся на месте.
            Assert.True((await b.Runtime.SetRealtimeProtectionAsync(false)).Success);
            Assert.Empty((await b.Runtime.GetStatusAsync()).WatchedDirectories);
            var ignored = watched.Write("second.com", Eicar.CreateTestFileBytes());
            await Task.Delay(500);
            Assert.True(File.Exists(ignored));

            Assert.True((await b.Runtime.SetRealtimeProtectionAsync(true)).Success);
            Assert.Single((await b.Runtime.GetStatusAsync()).WatchedDirectories);
        }
        finally
        {
            await cts.CancelAsync();
            await loop;
            watched.Dispose();
        }
    }

    [Fact]
    public async Task RealtimeSetting_IsPersistedAcrossRestarts()
    {
        var b = new RuntimeBench();
        await b.Runtime.SetRealtimeProtectionAsync(false);
        Assert.Contains("false", File.ReadAllText(Path.Combine(b.DataDir, "settings.json")), StringComparison.OrdinalIgnoreCase);
        await b.DisposeAsync();
    }

    [Fact]
    public async Task AuditNewProcesses_ChecksEachProcessOnce_AndReactsToNewOnes()
    {
        await using var b = new RuntimeBench();
        b.Host.Add(900, 4, "explorer.exe").Add(901, 900, "notepad.exe");

        Assert.Equal(2, await b.Runtime.AuditNewProcessesAsync());
        Assert.Equal(0, await b.Runtime.AuditNewProcessesAsync());

        var miner = b.Drop("svc.exe", Eicar.CreateTestFileBytes());
        b.Host.Add(4100, 900, "svc.exe", miner);
        Assert.Equal(1, await b.Runtime.AuditNewProcessesAsync());

        Assert.Equal(3, (await b.Runtime.GetStatusAsync()).ProcessesChecked);
        var threat = Assert.Single(await b.Runtime.GetThreatsAsync());
        Assert.Equal(ThreatKind.Process, threat.Kind);
        Assert.Equal(ThreatStatus.Terminated, threat.Status);
        Assert.Equal([4100], b.Host.Killed);
        Assert.False(File.Exists(miner));
    }

    [Fact]
    public async Task AuditPersistenceAndConfig_QueuesMediumFindings_AndDoesNotRepeatThem()
    {
        await using var b = new RuntimeBench();
        var narrow = new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Dev\Tools", "Paths");
        b.Exclusions.Add((narrow, Severity.Medium));
        b.Defender.Exclusions.Add((narrow.Kind, narrow.Value));

        await b.Runtime.AuditPersistenceAndConfigAsync();
        await b.Runtime.AuditPersistenceAndConfigAsync();

        var pending = Assert.Single(await b.Runtime.GetThreatsAsync());
        Assert.Equal(ThreatStatus.PendingDecision, pending.Status);
        Assert.Equal(1, (await b.Runtime.GetStatusAsync()).PendingDecisions);
        Assert.Single(b.Defender.Exclusions);

        // Решение пользователя: оставить. Исключение попадает в белый список и перестаёт подсвечиваться.
        var resolved = await b.Runtime.ResolveThreatAsync(pending.Id, ThreatDecision.Allow);
        Assert.Equal(ThreatStatus.Allowed, resolved.Status);
        var row = Assert.Single((await b.Runtime.GetStartupAsync(refresh: true)).Items);
        Assert.False(row.Flagged);
        Assert.False(row.CanClean);
    }

    [Fact]
    public async Task Startup_ListsEntries_HighlightsUnsigned_AndCleansFlaggedOnes()
    {
        await using var b = new RuntimeBench();
        var target = b.Drop("agent.exe", SyntheticArtifacts.BuildPe());
        var run = new RegistryKeyPath(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run");
        b.Registry.Set(run, "Agent", target, RegistryValueKind.Sz);
        b.Persistence.Add(new PersistenceEntry
        {
            Kind = PersistenceKind.RegistryRun,
            Location = run.ToString(),
            Name = "Agent",
            Command = target,
            ResolvedTarget = target,
            FileScan = new FileScanResult { Path = target, Verdict = Verdict.Clean, Signature = new SignatureVerificationResult(SignatureStatus.NotSigned, SignatureSource.None, null, null, null, null, 0, "нет подписи") },
            Findings = [AuditFinding.Create("PERS-UNSIGNED", Severity.Medium, "Неподписанный автозапуск", "Нет подписи.")],
        });
        b.Persistence.Add(new PersistenceEntry { Kind = PersistenceKind.Service, Location = @"HKLM\SYSTEM\CurrentControlSet\Services\Spooler", Name = "Spooler" });

        var snapshot = await b.Runtime.GetStartupAsync();

        Assert.Equal(2, snapshot.Items.Count);
        var flagged = snapshot.Items[0];
        Assert.True(flagged is { Flagged: true, NotSigned: true, CanClean: true, Category: "Автозапуск" });
        Assert.True(snapshot.Items[1] is { Flagged: false, CanClean: false, Category: "Служба" });
        Assert.Same(snapshot, await b.Runtime.GetStartupAsync()); // без refresh — из кэша

        var cleaned = await b.Runtime.CleanStartupItemAsync(flagged.Key);
        Assert.True(cleaned.Success, cleaned.Message);
        Assert.Null(b.Registry.GetValue(run, "Agent"));
        Assert.False((await b.Runtime.CleanStartupItemAsync("unknown-key")).Success);
    }

    [Fact]
    public async Task Telemetry_SamplesAreBroadcast_AndHistoryIsBounded()
    {
        await using var b = new RuntimeBench();
        var seen = new List<TelemetrySample>();
        b.Runtime.TelemetryUpdated += seen.Add;
        b.Telemetry.Next = new TelemetryReading(-1, 62.5, 12, 5, 8);

        for (var i = 0; i < 130; i++)
        {
            b.Runtime.SampleTelemetry();
        }

        var history = await b.Runtime.GetTelemetryHistoryAsync();
        Assert.Equal(120, history.Count);
        Assert.Equal(130, seen.Count);
        Assert.Equal(0, history[0].CpuPercent); // недоступный показатель отображается нулём
        Assert.Equal(62.5, history[0].RamPercent);
    }

    [Fact]
    public async Task Runtime_ServedOverNamedPipe_BehavesLikeLocalBackend()
    {
        await using var b = new RuntimeBench();
        var eicar = b.Drop("eicar.com", Eicar.CreateTestFileBytes());
        var pipe = "sentinel-rt-" + Guid.NewGuid().ToString("N");
        using var cts = new CancellationTokenSource();
        await using var server = new SentinelIpcServer(b.Runtime, new IpcServerOptions { PipeName = pipe });
        var serving = server.RunAsync(cts.Token);
        SentinelIpcClient? client = null;
        for (var i = 0; i < 50 && client is null; i++)
        {
            client = await SentinelIpcClient.TryConnectAsync(pipe, TimeSpan.FromSeconds(1));
        }

        Assert.NotNull(client);
        try
        {
            var progress = new List<ScanProgress>();
            var raised = new List<ThreatEvent>();
            client.ScanProgressChanged += p => { lock (progress) { progress.Add(p); } };
            client.ThreatRaised += t => { lock (raised) { raised.Add(t); } };

            Assert.True((await client.StartScanAsync(new ScanRequest(ScanMode.Custom, b.ScanDir))).Success);
            await RuntimeBench.WaitAsync(() => { lock (progress) { return progress.Exists(p => p.State == ScanState.Completed); } }, "завершение по IPC");
            await RuntimeBench.WaitAsync(() => { lock (raised) { return raised.Count == 1; } }, "находка по IPC");

            Assert.False(File.Exists(eicar));
            var item = Assert.Single(await client.GetQuarantineAsync());
            Assert.True((await client.RestoreQuarantineAsync(item.Id)).Success);
            Assert.True(File.Exists(eicar));
            var report = Assert.Single(await client.GetReportsAsync());
            Assert.Contains("eicar.com", (await client.ExportReportAsync(report.Id, ReportFormat.Html)).Content);
            await Assert.ThrowsAsync<IpcRemoteException>(() => client.ExportReportAsync(@"..\..\secret", ReportFormat.Json));
        }
        finally
        {
            await client.DisposeAsync();
            await cts.CancelAsync();
            await serving;
        }
    }
}

public class RealtimeInfrastructureTests
{
    [Theory]
    [InlineData(@"C:\Users\u\AppData\Local\Temp\dropper.exe", false)]
    [InlineData(@"C:\Users\u\Downloads\setup.exe", false)]
    [InlineData(@"C:\Windows\System32\drivers\etc\hosts", false)]
    [InlineData(@"C:\Windows\System32\Tasks\Updater", false)]
    [InlineData(@"C:\Windows\Prefetch\CMD.EXE-1234.pf", true)]
    [InlineData(@"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Cache\f_0001", true)]
    [InlineData(@"C:\Windows\System32\winevt\Logs\Security.evtx", true)]
    [InlineData(@"C:\ProgramData\Sentinel\Quarantine\ab12.qtn", true)]
    [InlineData(@"C:\Users\u\Documents\~$report.docx", true)]
    [InlineData(@"C:\Users\u\app\debug.LOG", true)]
    [InlineData(@"D:\src\repo\.git\index", true)]
    [InlineData("", true)]
    public void NoiseFilter_SeparatesSystemNoiseFromInterestingFiles(string path, bool noise) =>
        Assert.Equal(noise, FileNoiseFilter.IsNoise(path, new FileMonitorOptions()));

    [Fact]
    public void NoiseFilter_DefaultOptions_ExcludeOwnDataDirectory()
    {
        var options = FileMonitorOptions.CreateDefault(@"D:\SentinelData");
        Assert.True(FileNoiseFilter.IsNoise(@"d:\sentineldata\rollback_manifest.json", options));
        Assert.False(FileNoiseFilter.IsNoise(@"D:\SentinelDataEvil\x.exe", options));
    }

    [Fact]
    public void Debouncer_ReleasesFileOnlyAfterQuietPeriod_AndCoalescesBursts()
    {
        var t0 = new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);
        var debouncer = new FileChangeDebouncer(TimeSpan.FromMilliseconds(500), capacity: 2);

        Assert.True(debouncer.Touch(@"C:\a.exe", t0));
        Assert.True(debouncer.Touch(@"c:\A.EXE", t0.AddMilliseconds(400))); // тот же файл — срок переносится
        Assert.Empty(debouncer.Drain(t0.AddMilliseconds(600)));
        Assert.True(debouncer.Touch(@"C:\b.exe", t0.AddMilliseconds(600)));
        Assert.False(debouncer.Touch(@"C:\c.exe", t0.AddMilliseconds(600))); // переполнение
        Assert.Equal(1, debouncer.Dropped);

        Assert.Equal([@"C:\a.exe"], debouncer.Drain(t0.AddMilliseconds(900)));
        Assert.Equal([@"C:\b.exe"], debouncer.Drain(t0.AddMilliseconds(1100)));
        Assert.Equal(0, debouncer.PendingCount);
    }

    [Fact]
    public void ProcTelemetry_ParsesCpuAndDiskCounters()
    {
        Assert.Equal((1100L, 2000L), ProcTelemetryProvider.ParseCpu("cpu  500 0 400 1000 100 0 0 0 0 0"));
        Assert.Null(ProcTelemetryProvider.ParseCpu("intr 1 2 3"));
        Assert.Equal(700, ProcTelemetryProvider.ParseDiskIoMs(
        [
            "   8       0 sda 100 0 200 30 40 0 50 60 0 500 90 0 0 0 0",
            "   8       1 sda1 100 0 200 30 40 0 50 60 0 499 90 0 0 0 0",
            " 259       0 nvme0n1 1 0 2 3 4 0 5 6 0 200 9 0 0 0 0",
            " 259       1 nvme0n1p1 1 0 2 3 4 0 5 6 0 199 9 0 0 0 0",
            "   7       0 loop0 1 0 2 3 4 0 5 6 0 999 9 0 0 0 0",
        ]));
    }

    [Fact]
    public void ProcTelemetry_ComputesLoadBetweenTwoReadings()
    {
        using var tmp = new TempDir();
        tmp.WriteText("stat", "cpu  100 0 100 800 0 0 0 0 0 0\n");
        tmp.WriteText("meminfo", "MemTotal:       8000000 kB\nMemFree: 1 kB\nMemAvailable:   2000000 kB\n");
        tmp.WriteText("diskstats", "   8       0 sda 1 0 2 3 4 0 5 6 0 100 9 0 0 0 0\n");
        using var provider = new ProcTelemetryProvider(tmp.Path);

        var first = provider.Read();
        tmp.WriteText("stat", "cpu  150 0 150 900 0 0 0 0 0 0\n"); // +200 тиков, из них 100 простоя
        var second = provider.Read();

        Assert.Equal(0, first.CpuPercent);
        Assert.Equal(50, second.CpuPercent, 3);
        Assert.Equal(75, second.RamPercent, 3);
        Assert.Equal(8000000L * 1024, second.RamTotalBytes);
        Assert.InRange(second.DiskPercent, 0, 100);
    }

    [Fact]
    public void ReportStore_RejectsPathLikeIdentifiers()
    {
        using var tmp = new TempDir();
        var store = new ReportStore(Path.Combine(tmp.Path, "Reports"));
        Assert.Empty(store.List());
        Assert.Throws<ArgumentException>(() => store.Export("../x", ReportFormat.Json));
        Assert.Throws<ArgumentException>(() => store.Export(@"C:\Windows\win", ReportFormat.Json));
        Assert.Throws<KeyNotFoundException>(() => store.Export("20261115-000000-abcdef", ReportFormat.Html));
    }
}
