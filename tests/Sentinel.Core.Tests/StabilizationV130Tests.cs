using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Auditors.Memory;
using Sentinel.Core.Behavioral;
using Sentinel.Core.Detection;
using Sentinel.Core.Kernel;
using Sentinel.Core.Monitoring;
using Sentinel.Core.Protection;
using Sentinel.Core.Remediation;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using static Sentinel.Core.Auditors.Memory.MemoryConstants;

namespace Sentinel.Core.Tests;

/// <summary>D4: пути образов из ядра приводятся к Win32 до сравнения со штатными каталогами.</summary>
public class NtPathNormalizationTests
{
    [Theory]
    [InlineData(@"\SystemRoot\System32\Conhost.exe", @"C:\Windows\System32\Conhost.exe")]
    [InlineData(@"\systemroot\system32\smss.exe", @"C:\Windows\system32\smss.exe")]
    [InlineData(@"\??\C:\Windows\System32\cmd.exe", @"C:\Windows\System32\cmd.exe")]
    [InlineData(@"\GLOBAL??\C:\Tools\a.exe", @"C:\Tools\a.exe")]
    [InlineData(@"\DosDevices\D:\x.exe", @"D:\x.exe")]
    [InlineData(@"\??\UNC\srv\share\b.exe", @"\\srv\share\b.exe")]
    public void KernelForms_BecomeWin32(string input, string expected) =>
        Assert.Equal(expected, NtPath.ToWin32(input, null, @"C:\Windows"));

    [Fact]
    public void SystemRoot_UsesWindowsDirectoryOfThisOs()
    {
        Assert.Equal(NtPath.DefaultWindowsDirectory + @"\System32\conhost.exe", NtPath.ToWin32(@"\SystemRoot\System32\conhost.exe"));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(@"C:\Windows", NtPath.DefaultWindowsDirectory);
        }
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\cmd.exe", true)]
    [InlineData(@"\\server\share\a.exe", true)]
    [InlineData(@"\SystemRoot\System32\cmd.exe", false)]
    [InlineData(@"\Device\HarddiskVolume3\x.exe", false)]
    [InlineData(@"\\?\C:\x.exe", false)]
    [InlineData("", false)]
    public void IsWin32_DistinguishesKernelForms(string path, bool expected) => Assert.Equal(expected, NtPath.IsWin32(path));

    [Fact]
    public void SystemProcessPolicy_AcceptsKernelPathOfConhost()
    {
        var policy = SystemProcessPolicy.CreateDefault(@"C:\Windows");
        Assert.True(policy.IsInAllowedLocation("Conhost.exe", @"\SystemRoot\System32\Conhost.exe"));
        Assert.True(policy.IsInAllowedLocation("conhost.exe", @"\??\C:\Windows\System32\conhost.exe"));
        Assert.False(policy.IsInAllowedLocation("conhost.exe", @"\??\C:\Temp\conhost.exe"));
    }

    [Fact]
    public void CriticalProcessGuard_ProtectsSystemProcessReportedWithKernelPath()
    {
        Assert.True(CriticalProcessGuard.IsProtectedProcess(612, "csrss.exe", @"\SystemRoot\System32\csrss.exe"));
        Assert.False(CriticalProcessGuard.IsProtectedProcess(613, "csrss.exe", @"\??\C:\Temp\csrss.exe"));
    }

    [Theory]
    [InlineData(@"\SystemRoot\System32\Conhost.exe", "Conhost.exe")]
    [InlineData(@"\??\C:\Windows\System32\conhost.exe", "conhost.exe")]
    [InlineData(@"\SystemRoot\System32\svchost.exe", "svchost.exe")]
    public async Task ProcessStartMonitor_LegitimateSystemProcessFromKernel_IsNotImpersonation(string kernelPath, string name)
    {
        using var b = new DispatcherBench();
        b.Host.Add(7700, 600, name, kernelPath);
        var monitor = new ProcessStartMonitor(new FakeProcessCreationEventSource(), b.Dispatcher, new BehavioralCorrelationEngine(), null);

        var outcome = await monitor.InspectAsync(new ProcessCreationEvent(7700, 600, name, kernelPath, $"{name} 0xffffffff -ForceV1", DateTimeOffset.UtcNow));

        Assert.DoesNotContain(outcome.Findings, f => f.Id is "PROC-IMPERSONATION" or "PROC-START-MASQUERADE");
        Assert.NotEqual(ProcessStartDecision.Act, outcome.Decision);
        Assert.Empty(b.Host.Killed);
    }

    [Fact]
    public async Task KernelSource_ResolvesDevicePathThroughResolver()
    {
        var bridge = new FakeKernelBridge { DisconnectAfterReads = 1 };
        bridge.Events.Enqueue(new KernelProcessEvent(KernelProcessEventKind.Create, 8800, 1, DateTimeOffset.UtcNow,
            @"\Device\HarddiskVolume9\Apps\tool.exe", "tool.exe"));
        await using var source = new KernelProcessCreationEventSource(bridge, pollInterval: TimeSpan.FromMilliseconds(5),
            resolveImagePath: pid => pid == 8800 ? @"C:\Apps\tool.exe" : null);

        ProcessCreationEvent? first = null;
        await foreach (var e in source.ReadEventsAsync(CancellationToken.None))
        {
            first = e;
            break;
        }

        Assert.Equal(@"C:\Apps\tool.exe", first!.ExecutablePath);
        Assert.Equal("tool.exe", first.ProcessName);
    }
}

/// <summary>D3: при остановке драйвера дескриптор отпускается сразу, служба переходит в профиль User-Mode и переподключается.</summary>
[Collection(KernelGuardStateGroup.Name)]
public class KernelDisconnectTests
{
    [Theory]
    [InlineData(2, true)]
    [InlineData(6, true)]
    [InlineData(31, true)]
    [InlineData(433, true)]
    [InlineData(995, true)]
    [InlineData(1167, true)]
    [InlineData(5, false)]
    [InlineData(1314, false)]
    public void DriverGoneErrors_AreClassified(int error, bool gone) => Assert.Equal(gone, KernelProtocol.IsDriverGoneError(error));

    [Fact]
    public async Task StopPending_ReleasesHandleImmediately_AndFallsBackToUserMode()
    {
        var bridge = new FakeKernelBridge();
        await using var bench = new RuntimeBench(kernelBridge: () => bridge);
        var infos = new List<string>();
        bench.Runtime.Info += m => { lock (infos) { infos.Add(m); } };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var loop = bench.Runtime.RunKernelBridgeAsync(cts.Token);

        await RuntimeBench.WaitAsync(() => bridge.Sent.Count > 0, "синхронизация PID с драйвером");
        Assert.NotEmpty(CriticalProcessGuard.KernelProtectedProcessIds);

        bridge.StopRequested = true; // sc stop SentinelDrv
        await RuntimeBench.WaitAsync(() => bridge.Disposed, "освобождение дескриптора драйвера");

        Assert.False(bench.Runtime.KernelBridge.IsConnected);
        Assert.StartsWith(KernelDriverStatus.NotLoadedMessage, bench.Runtime.GetKernelStatus().Message, StringComparison.Ordinal);
        Assert.Empty(CriticalProcessGuard.KernelProtectedProcessIds);
        lock (infos)
        {
            Assert.Contains(infos, m => m.Contains("Драйвер ядра отключён", StringComparison.Ordinal));
        }

        await cts.CancelAsync();
        await loop;
    }

    [Fact]
    public async Task DriverStartedLater_IsReconnectedAutomatically()
    {
        var connected = new FakeKernelBridge();
        var calls = 0;
        IKernelBridge Factory() => Interlocked.Increment(ref calls) < 3 ? new NullKernelBridge() : connected;
        await using var bench = new RuntimeBench(kernelBridge: Factory);
        var infos = new List<string>();
        bench.Runtime.Info += m => { lock (infos) { infos.Add(m); } };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var loop = bench.Runtime.RunKernelBridgeAsync(cts.Token);

        await RuntimeBench.WaitAsync(() => connected.Sent.Count > 0, "переподключение и синхронизация PID");

        Assert.True(bench.Runtime.KernelBridge.IsConnected);
        lock (infos)
        {
            Assert.Contains(infos, m => m.Contains("Драйвер ядра подключён", StringComparison.Ordinal));
        }

        await cts.CancelAsync();
        await loop;
    }

    [Fact]
    public async Task ReleaseKernelBridge_ClosesHandle_AndStopsReconnecting()
    {
        var bridge = new FakeKernelBridge();
        var created = 0;
        await using var bench = new RuntimeBench(kernelBridge: () => { Interlocked.Increment(ref created); return bridge; });
        Assert.True(bench.Runtime.KernelBridge.IsConnected);

        bench.Runtime.ReleaseKernelBridge(); // StopAsync службы

        Assert.True(bridge.Disposed);
        Assert.False(bench.Runtime.KernelBridge.IsConnected);
        await bench.Runtime.RunKernelBridgeAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, created);
    }
}

/// <summary>D5: Sentinel, запущенный не из Program Files, не изолирует и не отключает сам себя.</summary>
public class OwnInstallationSelfProtectionTests
{
    private const string Image = @"C:\Sentinel-v1.3.0\Sentinel.Service.exe";

    [Theory]
    [InlineData(@"C:\Sentinel-v1.3.0\Sentinel.Service.exe", true)]
    [InlineData(@"c:\sentinel-v1.3.0\sentinel.service.exe", true)]
    [InlineData(@"C:\Sentinel-v1.3.0\sentinel.exe", true)]
    [InlineData(@"C:\Sentinel-v1.3.0\Sentinel.App.exe", true)]
    [InlineData(@"C:\Sentinel-v1.3.0\rules\miners.json", true)]
    [InlineData(@"C:\Sentinel-v1.3.0\data\threat_hashes.bin", true)]
    [InlineData(@"C:\Sentinel-v1.3.0\evil.exe", false)]          // чужой файл рядом — проверяется как обычно
    [InlineData(@"C:\Sentinel-v1.3.0\sub\Sentinel.App.exe", false)]
    [InlineData(@"C:\Users\u\Downloads\sentinel.exe", false)]
    public void OwnInstallationFiles_AreRecognized(string path, bool expected) =>
        Assert.Equal(expected, SelfProtection.IsOwnInstallationFile(path, Image));

    [Fact]
    public void WithoutSentinelImage_NothingExtraIsProtected()
    {
        Assert.False(SelfProtection.IsOwnInstallationFile(@"C:\Sentinel-v1.3.0\Sentinel.Service.exe", null));
        Assert.Null(SelfProtection.CurrentSentinelImagePath); // тестовый процесс — не образ Sentinel
    }

    [Theory]
    [InlineData("SentinelService", true)]
    [InlineData("sentineldrv", true)]
    [InlineData("SentinelUpdater", false)]
    [InlineData(null, false)]
    public void OwnServiceNames(string? name, bool expected) => Assert.Equal(expected, SelfProtection.IsOwnServiceName(name));

    private static PersistenceEntry OwnServiceEntry(string name = "SentinelService") => new()
    {
        Kind = PersistenceKind.Service,
        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{name}",
        Name = name,
        Command = Image,
        ResolvedTarget = Image,
        Findings =
        [
            AuditFinding.Create("PERS-FILE-HEURISTIC", Severity.High, "Эвристика", "Синтетика."),
            AuditFinding.Create("PERS-FILE-UNSIGNED", Severity.Medium, "Без подписи", "Синтетика."),
        ],
    };

    [Theory]
    [InlineData("SentinelService")]
    [InlineData("SentinelDrv")]
    public void RemediationEngine_NeverDisablesOwnService(string name)
    {
        using var b = new DispatcherBench();

        var action = b.Engine.RollbackPersistence(OwnServiceEntry(name));

        Assert.Equal(RemediationStatus.Blocked, action.Status);
        Assert.Contains("самозащита", action.Message, StringComparison.Ordinal);
        Assert.Empty(b.Engine.ListRollbackEntries()); // ничего не изменено — нечего и откатывать
    }

    [Fact]
    public async Task Dispatcher_IgnoresOwnServiceEntry()
    {
        using var b = new DispatcherBench();

        Assert.Null(await b.Dispatcher.DispatchPersistenceAsync(OwnServiceEntry()));
        Assert.Empty(b.Raised);
    }
}

/// <summary>D6: правила загружаются без дублей; вложенная копия каталога правил даёт именно те предупреждения, что были в отчёте.</summary>
public class RulesLayoutTests
{
    [Fact]
    public void ShippedRules_HaveUniqueIds()
    {
        var rules = RuleLoader.LoadDirectory(RepoPaths.RulesDirectory);

        Assert.DoesNotContain(rules.Errors, e => e.ToString().Contains("Дублирующийся id", StringComparison.Ordinal));
        Assert.False(Directory.Exists(Path.Combine(RepoPaths.RulesDirectory, "rules")));
        Assert.Equal(rules.Rules.Count, rules.Rules.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void NestedRulesCopy_ProducesDuplicateIdErrors()
    {
        using var tmp = new TempDir();
        var root = Path.Combine(tmp.Path, "rules");
        CopyDirectory(RepoPaths.RulesDirectory, root);
        CopyDirectory(RepoPaths.RulesDirectory, Path.Combine(root, "rules")); // то, что делал publish-windows.ps1 до исправления

        var rules = RuleLoader.LoadDirectory(root);

        Assert.Contains(rules.Errors, e => e.ToString().Contains("Дублирующийся id", StringComparison.Ordinal));
    }

    [Fact]
    public void PublishScript_CopiesFolderContents_AndRejectsNestedFolders()
    {
        var script = File.ReadAllText(Path.Combine(Path.GetDirectoryName(RepoPaths.RulesDirectory)!, "scripts", "publish-windows.ps1"));

        Assert.DoesNotContain("Copy-Item $rules (Join-Path $Output 'rules')", script, StringComparison.Ordinal);
        Assert.Contains("Copy-Item (Join-Path $source '*') $destination -Recurse -Force", script, StringComparison.Ordinal);
        Assert.Contains(@"'rules\rules', 'data\data'", script, StringComparison.Ordinal);
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        }
    }
}

/// <summary>D7: отложенная повторная проверка памяти ловит RWX-нагрузку, выделенную уже после старта процесса.</summary>
public class DelayedMemoryRescanTests
{
    private const string PowerShell = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    private static ProcessStartMonitor Monitor(DispatcherBench b, FakeMemoryReader reader, TimeSpan? delay = null, int maxPending = 32) =>
        new(new FakeProcessCreationEventSource(), b.Dispatcher, new BehavioralCorrelationEngine(), null,
            options: new ProcessStartMonitorOptions
            {
                Auditor = new ProcessAuditorOptions
                {
                    MemoryScanner = new MemoryIntegrityScanner(reader, new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory))),
                },
                MemoryRescanDelay = delay ?? TimeSpan.FromMilliseconds(30),
                MaxPendingMemoryRescans = maxPending,
            });

    private static ProcessCreationEvent Start(int pid, string name, string path, string commandLine = "") =>
        new(pid, 100, name, path, commandLine, DateTimeOffset.UtcNow);

    [Fact]
    public async Task PayloadAllocatedAfterStart_IsCaughtByRescan()
    {
        using var b = new DispatcherBench();
        var reader = new FakeMemoryReader();
        var monitor = Monitor(b, reader);
        var rescanned = new List<ProcessStartOutcome>();
        monitor.MemoryRescanned += o => { lock (rescanned) { rescanned.Add(o); } };

        var first = await monitor.InspectAsync(Start(9100, "powershell.exe", PowerShell, "powershell.exe -File .\\test-memory-scanner.ps1"));
        Assert.Equal(ProcessStartDecision.Clean, first.Decision); // при старте региона ещё нет
        Assert.Equal(1, monitor.MemoryRescansScheduled);

        // Через ~1–2 с сценарий выделяет MEM_PRIVATE + PAGE_EXECUTE_READWRITE и кладёт туда EICAR.
        reader.Add(9100, unchecked((nint)0x2_9100_0000L), MemoryPayloads.With(MemoryPayloads.JitCode(64 * 1024), 0x200, Eicar.CreateTestFileBytes()),
            MEM_PRIVATE, PAGE_EXECUTE_READWRITE);
        await monitor.DrainMemoryRescansAsync().WaitAsync(TimeSpan.FromSeconds(10));

        var outcome = Assert.Single(rescanned);
        Assert.Contains(outcome.Findings, f => f.Id == "MEM-YARA-MATCH");
        Assert.NotNull(outcome.Threat);
        Assert.Contains(b.Raised, t => t.ProcessId == 9100);
    }

    [Fact]
    public async Task CleanRescan_RaisesNothing()
    {
        using var b = new DispatcherBench();
        var reader = new FakeMemoryReader().Add(9200, 0x10000, MemoryPayloads.JitCode(64 * 1024), MEM_PRIVATE, PAGE_EXECUTE_READWRITE);
        var monitor = Monitor(b, reader);
        var rescanned = 0;
        monitor.MemoryRescanned += _ => Interlocked.Increment(ref rescanned);

        await monitor.InspectAsync(Start(9200, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c dir"));
        await monitor.DrainMemoryRescansAsync().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(1, monitor.MemoryRescansScheduled);
        Assert.Equal(0, rescanned);
        Assert.Empty(b.Raised);
    }

    [Fact]
    public async Task OrdinaryOrProtectedProcesses_AreNotRescheduled()
    {
        using var b = new DispatcherBench();
        var monitor = Monitor(b, new FakeMemoryReader());

        await monitor.InspectAsync(Start(9300, "notepad.exe", @"C:\Windows\System32\notepad.exe"));  // не интерпретатор, образ не анализировался
        await monitor.InspectAsync(Start(9301, "lsass.exe", @"C:\Windows\System32\lsass.exe"));      // защищён — память не трогается

        Assert.Equal(0, monitor.MemoryRescansScheduled);
    }

    [Fact]
    public async Task QueueLimit_DropsExcessRescans()
    {
        using var b = new DispatcherBench();
        var monitor = Monitor(b, new FakeMemoryReader(), delay: TimeSpan.FromMilliseconds(200), maxPending: 1);

        await monitor.InspectAsync(Start(9400, "cmd.exe", @"C:\Windows\System32\cmd.exe"));
        await monitor.InspectAsync(Start(9401, "cmd.exe", @"C:\Windows\System32\cmd.exe"));
        await monitor.DrainMemoryRescansAsync().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(1, monitor.MemoryRescansScheduled);
        Assert.Equal(1, monitor.MemoryRescansDropped);
    }
}
