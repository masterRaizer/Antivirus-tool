using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Detection;
using Sentinel.Core.Remediation;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class RegistryKeyPathParseTests
{
    [Theory]
    [InlineData(RegistryHive.CurrentUser, @"Software\X", RegistryView.Default)]
    [InlineData(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", RegistryView.Registry32)]
    [InlineData(RegistryHive.Users, @"S-1-5-21\Software [odd] name", RegistryView.Registry64)]
    public void TryParse_RoundTripsToString(RegistryHive hive, string subKey, RegistryView view)
    {
        var original = new RegistryKeyPath(hive, subKey, view);
        Assert.True(RegistryKeyPath.TryParse(original.ToString(), out var parsed));
        Assert.Equal(original, parsed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("HKLM")]
    [InlineData(@"HKXX\Software")]
    [InlineData(@"C:\Windows\System32\drivers\etc\hosts")]
    [InlineData(@"HKLM\Software [Bogus]")]
    public void TryParse_RejectsInvalid(string? text)
    {
        Assert.False(RegistryKeyPath.TryParse(text, out _));
    }
}

public class HostsCleanerTests
{
    [Fact]
    public void Remove_DropsOnlyRequestedMappings_AndKeepsFormatting()
    {
        const string content = "# header\r\n127.0.0.1   localhost\r\n1.2.3.4 update.microsoft.com good.example # note\r\n5.6.7.8\tevil.example\r\n";
        var (cleaned, removed) = HostsCleaner.Remove(content, [("1.2.3.4", "update.microsoft.com"), ("5.6.7.8", "EVIL.example")]);
        Assert.Equal(2, removed);
        Assert.Equal("# header\r\n127.0.0.1   localhost\r\n1.2.3.4 good.example # note\r\n", cleaned);
    }

    [Fact]
    public void Remove_NoMatch_ReturnsContentUnchanged()
    {
        const string content = "127.0.0.1 localhost\n";
        var (cleaned, removed) = HostsCleaner.Remove(content, [("9.9.9.9", "nothing")]);
        Assert.Equal(0, removed);
        Assert.Equal(content, cleaned);
    }
}

public class RemediationEngineTests
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string WinlogonKey = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string IfeoKey = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
    private const int SelfPid = 999_999;

    private static FileAnalyzer Analyzer() =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), new UnavailableSignatureVerifier());

    private sealed class Fixture : IDisposable
    {
        public TempDir Tmp { get; } = new();
        public FakeProcessHost Host { get; } = new();
        public InMemoryRegistryProvider Registry { get; } = new();
        public FakeTaskEditor Tasks { get; } = new();
        public FakeDefender Defender { get; } = new();

        public string ManifestPath => Path.Combine(Tmp.Path, "state", "rollback_manifest.json");

        public RemediationEngine Engine(bool dryRun = false, IWhitelistProvider? whitelist = null) => new(
            whitelist ?? new FakeWhitelist(),
            new RemediationOptions { RollbackManifestPath = ManifestPath, DryRun = dryRun, CurrentProcessId = SelfPid },
            Host, Host, Registry, Tasks, Defender);

        public void Dispose() => Tmp.Dispose();
    }

    // ---- Дерево процессов -----------------------------------------------------

    [Fact]
    public void TerminateProcessTree_KillsRootFirst_ThenAllDescendants_ButNotSiblings()
    {
        using var f = new Fixture();
        f.Host.Add(100, 1, "explorer.exe", @"C:\Windows\explorer.exe")
            .Add(200, 100, "miner.exe", @"C:\Temp\miner.exe")
            .Add(201, 200, "worker.exe", @"C:\Temp\worker.exe")
            .Add(202, 201, "cmd.exe", @"C:\Temp\cmd.exe")
            .Add(203, 200, "helper.exe", @"C:\Temp\helper.exe")
            .Add(300, 100, "notepad.exe", @"C:\Windows\notepad.exe");

        var result = f.Engine().TerminateProcessTree(200);

        Assert.Equal(RemediationStatus.Done, result.Status);
        Assert.Equal(4, result.TerminatedCount);
        Assert.Equal(200, f.Host.Killed[0]);
        Assert.Equal([200, 201, 202, 203], f.Host.Killed.Order().ToArray());
        Assert.True(f.Host.IsRunning(100));
        Assert.True(f.Host.IsRunning(300));
    }

    [Fact]
    public void TerminateProcessTree_WhitelistedRoot_IsBlocked_NothingKilled()
    {
        using var f = new Fixture();
        const string lsass = @"C:\Windows\System32\lsass.exe";
        f.Host.Add(500, 4, "lsass.exe", lsass).Add(501, 500, "child.exe", @"C:\Temp\child.exe");

        var result = f.Engine(whitelist: new FakeWhitelist(lsass)).TerminateProcessTree(500);

        Assert.Equal(RemediationStatus.Blocked, result.Status);
        Assert.Empty(f.Host.Killed);
    }

    [Fact]
    public void TerminateProcessTree_WhitelistedDescendant_IsSkipped_OthersKilled()
    {
        using var f = new Fixture();
        const string conhost = @"C:\Windows\System32\conhost.exe";
        f.Host.Add(200, 1, "evil.exe", @"C:\Temp\evil.exe")
            .Add(201, 200, "conhost.exe", conhost)
            .Add(202, 201, "grandchild.exe", @"C:\Temp\g.exe");

        var result = f.Engine(whitelist: new FakeWhitelist(conhost)).TerminateProcessTree(200);

        Assert.Equal(RemediationStatus.Done, result.Status);
        Assert.Equal([200, 202], f.Host.Killed.Order().ToArray());
        Assert.Equal(RemediationStatus.Blocked, result.Processes.Single(p => p.Process.Pid == 201).Status);
        Assert.True(f.Host.IsRunning(201));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(SelfPid)]
    public void TerminateProcessTree_KernelAndSelf_AreBlocked(int pid)
    {
        using var f = new Fixture();
        f.Host.Add(pid, 0, "x.exe", @"C:\Temp\x.exe");
        Assert.Equal(RemediationStatus.Blocked, f.Engine().TerminateProcessTree(pid).Status);
        Assert.Empty(f.Host.Killed);
    }

    [Fact]
    public void TerminateProcessTree_NeverKillsItself_EvenAsDescendant()
    {
        using var f = new Fixture();
        f.Host.Add(200, 1, "shell.exe", @"C:\Temp\shell.exe").Add(SelfPid, 200, "sentinel.exe", @"C:\Tools\sentinel.exe");
        var result = f.Engine().TerminateProcessTree(200);
        Assert.Equal([200], f.Host.Killed.ToArray());
        Assert.Equal(RemediationStatus.Blocked, result.Processes.Single(p => p.Process.Pid == SelfPid).Status);
    }

    [Fact]
    public void TerminateProcessTree_SystemNameWithUnknownPath_IsProtected()
    {
        using var f = new Fixture();
        f.Host.Add(700, 4, "csrss.exe", null).Add(701, 4, "mystery.exe", null);
        Assert.Equal(RemediationStatus.Blocked, f.Engine().TerminateProcessTree(700).Status);
        Assert.Equal(RemediationStatus.Done, f.Engine().TerminateProcessTree(701).Status);
    }

    [Fact]
    public void TerminateProcessTree_IgnoresFalseChildren_FromReusedParentPid()
    {
        using var f = new Fixture();
        var t = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        f.Host.Add(200, 1, "evil.exe", @"C:\Temp\evil.exe", t)
            .Add(201, 200, "real-child.exe", @"C:\Temp\c.exe", t.AddSeconds(5))
            .Add(202, 200, "older-orphan.exe", @"C:\Apps\o.exe", t.AddHours(-3)); // родитель с PID 200 давно умер

        f.Engine().TerminateProcessTree(200);

        Assert.Equal([200, 201], f.Host.Killed.Order().ToArray());
        Assert.True(f.Host.IsRunning(202));
    }

    [Fact]
    public void TerminateProcessTree_MissingPid_IsSkipped_AndFailureIsReported()
    {
        using var f = new Fixture();
        Assert.Equal(RemediationStatus.Skipped, f.Engine().TerminateProcessTree(4242).Status);

        f.Host.Add(200, 1, "evil.exe", @"C:\Temp\evil.exe").Add(201, 200, "kid.exe", @"C:\Temp\kid.exe");
        f.Host.Unkillable.Add(200);
        var result = f.Engine().TerminateProcessTree(200);
        Assert.Equal(RemediationStatus.Failed, result.Status);
        Assert.Equal(1, result.TerminatedCount); // потомок всё равно остановлен
    }

    [Fact]
    public void TerminateProcessTree_DryRun_KillsNothing()
    {
        using var f = new Fixture();
        f.Host.Add(200, 1, "evil.exe", @"C:\Temp\evil.exe").Add(201, 200, "kid.exe", @"C:\Temp\kid.exe");
        var result = f.Engine(dryRun: true).TerminateProcessTree(200);
        Assert.Equal(RemediationStatus.WouldDo, result.Status);
        Assert.Equal(2, result.Processes.Count);
        Assert.Empty(f.Host.Killed);
    }

    // ---- Автозагрузка ---------------------------------------------------------

    [Fact]
    public void Rollback_RunKey_DeletesValue_BacksUp_AndUndoRestores()
    {
        using var f = new Fixture();
        var key = new RegistryKeyPath(RegistryHive.CurrentUser, RunKey);
        var command = f.Tmp.Write("payload.exe", Eicar.CreateTestFileBytes());
        var clean = f.Tmp.WriteText("clean.txt", "ok");
        f.Registry.Set(key, "Updater", command, RegistryValueKind.ExpandSz);
        f.Registry.Set(key, "OneDrive", clean);
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), f.Registry, analyzer: Analyzer()).Audit();
        var engine = f.Engine();

        var actions = engine.RollbackPersistence(report.Entries);

        var done = Assert.Single(actions, a => a.Status == RemediationStatus.Done);
        Assert.Null(f.Registry.GetValue(key, "Updater"));
        Assert.NotNull(f.Registry.GetValue(key, "OneDrive")); // штатная запись не тронута
        Assert.Contains(actions, a => a.Status == RemediationStatus.Skipped);

        var backup = Assert.Single(engine.ListRollbackEntries());
        Assert.Equal(done.RollbackId, backup.Id);
        Assert.Equal(RollbackKind.RegistryValue, backup.Kind);
        Assert.Equal(key.ToString(), backup.Target);
        Assert.Equal("Updater", backup.Name);
        Assert.True(backup.PreviousExisted);
        Assert.Equal(command, backup.PreviousValue);
        Assert.Equal(RegistryValueKind.ExpandSz, backup.PreviousValueKind);
        Assert.True(File.Exists(f.ManifestPath));

        // Отмена выполняется новым экземпляром движка — только по манифесту с диска.
        var undo = f.Engine().Undo(backup.Id[..8]);
        Assert.Equal(RemediationStatus.Done, undo.Status);
        var restored = f.Registry.GetValue(key, "Updater")!;
        Assert.Equal(command, restored.Value);
        Assert.Equal(RegistryValueKind.ExpandSz, restored.Kind);
        Assert.Equal(RemediationStatus.Skipped, f.Engine().Undo(backup.Id).Status);
    }

    [Fact]
    public void Rollback_Winlogon_ResetsToBaseline_HklmSet_HkcuDeleted()
    {
        using var f = new Fixture();
        var hklm = new RegistryKeyPath(RegistryHive.LocalMachine, WinlogonKey);
        var hkcu = new RegistryKeyPath(RegistryHive.CurrentUser, WinlogonKey);
        f.Registry.Set(hklm, "Shell", @"explorer.exe,C:\Temp\evil.exe");
        f.Registry.Set(hklm, "Userinit", @"C:\Windows\system32\userinit.exe,C:\Temp\evil.exe");
        f.Registry.Set(hkcu, "Shell", @"C:\Temp\shell.exe");
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), f.Registry).Audit();
        var engine = f.Engine();

        var actions = engine.RollbackPersistence(report.Flagged);

        Assert.Equal(3, actions.Count);
        Assert.All(actions, a => Assert.Equal(RemediationStatus.Done, a.Status));
        Assert.Equal("explorer.exe", f.Registry.GetValue(hklm, "Shell")!.Value);
        Assert.Equal(@"C:\Windows\system32\userinit.exe,", f.Registry.GetValue(hklm, "Userinit")!.Value);
        Assert.Null(f.Registry.GetValue(hkcu, "Shell"));
        Assert.Equal(3, engine.ListRollbackEntries().Count);

        // После отката повторный аудит чист.
        Assert.Equal(0, new PersistenceAuditor(new PersistenceAuditorOptions(), f.Registry).Audit().FlaggedCount);
    }

    [Fact]
    public void Rollback_Ifeo_RemovesDebugger()
    {
        using var f = new Fixture();
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, IfeoKey + @"\sethc.exe");
        f.Registry.Set(key, "Debugger", @"C:\Windows\System32\cmd.exe");
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), f.Registry).Audit();

        var actions = f.Engine().RollbackPersistence(report.Flagged);

        Assert.Contains(actions, a => a.Status == RemediationStatus.Done);
        Assert.Null(f.Registry.GetValue(key, "Debugger"));
        Assert.Equal(0, new PersistenceAuditor(new PersistenceAuditorOptions(), f.Registry).Audit().FlaggedCount);
    }

    [Fact]
    public void Rollback_Service_IsDisabledNotDeleted_AndWhitelistedTargetIsBlocked()
    {
        using var f = new Fixture();
        var evil = new RegistryKeyPath(RegistryHive.LocalMachine, ServicesKey + @"\EvilSvc");
        f.Registry.Set(evil, "ImagePath", @"C:\Temp\evil.exe");
        f.Registry.Set(evil, "Start", "2", RegistryValueKind.Dword);
        var entry = Assert.Single(new PersistenceAuditor(new PersistenceAuditorOptions(), f.Registry).Audit().Flagged);
        var engine = f.Engine();

        var action = engine.RollbackPersistence(entry);

        Assert.Equal(RemediationStatus.Done, action.Status);
        Assert.Equal("4", f.Registry.GetValue(evil, "Start")!.Value);
        Assert.Equal(@"C:\Temp\evil.exe", f.Registry.GetValue(evil, "ImagePath")!.Value);
        var backup = Assert.Single(engine.ListRollbackEntries());
        Assert.Equal("2", backup.PreviousValue);
        Assert.Equal(RegistryValueKind.Dword, backup.PreviousValueKind);

        Assert.Equal(RemediationStatus.Done, engine.Undo(backup.Id).Status);
        Assert.Equal("2", f.Registry.GetValue(evil, "Start")!.Value);

        // Та же служба, но её файл — доверенный системный: отключение запрещено.
        var blocked = f.Engine(whitelist: new FakeWhitelist(entry.ResolvedTarget!)).RollbackPersistence(entry);
        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        Assert.Equal("2", f.Registry.GetValue(evil, "Start")!.Value);
    }

    [Fact]
    public void Rollback_ScheduledTask_DeletesWithXmlBackup_AndUndoRecreates()
    {
        using var f = new Fixture();
        const string xml = "<Task><Actions><Exec><Command>powershell.exe</Command></Exec></Actions></Task>";
        f.Tasks.Tasks[@"\Evil"] = xml;
        var task = new ScheduledTaskInfo("Evil", @"\Evil", true,
            [new ScheduledTaskAction("powershell.exe", "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]);
        var entry = Assert.Single(new PersistenceAuditor(new PersistenceAuditorOptions(), tasks: new FakeTaskProvider(task)).Audit().Flagged);
        var engine = f.Engine();

        var action = engine.RollbackPersistence(entry);

        Assert.Equal(RemediationStatus.Done, action.Status);
        Assert.Empty(f.Tasks.Tasks);
        var backup = Assert.Single(engine.ListRollbackEntries());
        Assert.Equal(RollbackKind.ScheduledTask, backup.Kind);
        Assert.Equal(xml, backup.PreviousValue);

        Assert.Equal(RemediationStatus.Done, engine.Undo(backup.Id).Status);
        Assert.Equal(xml, f.Tasks.Tasks[@"\Evil"]);
    }

    [Fact]
    public void Rollback_ScheduledTask_WithoutBackup_IsNotDeleted()
    {
        using var f = new Fixture();
        var entry = new PersistenceEntry
        {
            Kind = PersistenceKind.ScheduledTask,
            Location = @"\Ghost",
            Name = "Ghost",
            Findings = [Audit.AuditFinding.Create("PERS-TEST", Severity.High, "t", "d")],
        };
        var engine = f.Engine();
        Assert.Equal(RemediationStatus.Failed, engine.RollbackPersistence(entry).Status);
        Assert.Empty(engine.ListRollbackEntries());
    }

    [Fact]
    public void Rollback_Hosts_RemovesFlaggedLines_SingleBackup_AndUndoRestoresExactContent()
    {
        using var f = new Fixture();
        const string original = "# Copyright (c) Microsoft\r\n127.0.0.1 localhost\r\n0.0.0.0 update.microsoft.com\r\n6.6.6.6 bank.example\r\n";
        var hosts = f.Tmp.WriteText("hosts", original);
        File.SetAttributes(hosts, File.GetAttributes(hosts) | FileAttributes.ReadOnly);
        var options = new PersistenceAuditorOptions { HostsFilePath = hosts };
        var report = new PersistenceAuditor(options).Audit();
        Assert.Equal(2, report.FlaggedCount);
        var engine = f.Engine();

        var action = Assert.Single(engine.RollbackPersistence(report.Flagged));

        Assert.Equal(RemediationStatus.Done, action.Status);
        Assert.Equal("# Copyright (c) Microsoft\r\n127.0.0.1 localhost\r\n", File.ReadAllText(hosts));
        Assert.True(File.GetAttributes(hosts).HasFlag(FileAttributes.ReadOnly)); // атрибут возвращён
        Assert.Equal(0, new PersistenceAuditor(options).Audit().FlaggedCount);

        var backup = Assert.Single(engine.ListRollbackEntries());
        Assert.Equal(RollbackKind.HostsFile, backup.Kind);
        Assert.Equal(original, backup.PreviousValue);

        Assert.Equal(RemediationStatus.Done, engine.Undo(backup.Id).Status);
        Assert.Equal(original, File.ReadAllText(hosts));
        File.SetAttributes(hosts, FileAttributes.Normal);
    }

    [Fact]
    public void Rollback_DryRun_ChangesNothing_AndWritesNoManifest()
    {
        using var f = new Fixture();
        var key = new RegistryKeyPath(RegistryHive.CurrentUser, RunKey);
        f.Registry.Set(key, "Updater", f.Tmp.Write("payload.exe", Eicar.CreateTestFileBytes()));
        f.Tasks.Tasks[@"\Evil"] = "<Task/>";
        f.Defender.Exclusions.Add((DefenderExclusionKind.Path, @"C:\Temp"));
        var hosts = f.Tmp.WriteText("hosts", "6.6.6.6 bank.example\n");
        var task = new ScheduledTaskInfo("Evil", @"\Evil", true, [new ScheduledTaskAction(@"C:\Temp\evil.exe", null)]);
        var report = new PersistenceAuditor(new PersistenceAuditorOptions { HostsFilePath = hosts }, f.Registry, new FakeTaskProvider(task), analyzer: Analyzer()).Audit();
        var engine = f.Engine(dryRun: true);

        var actions = engine.RollbackPersistence(report.Flagged).ToList();
        actions.Add(engine.RemoveDefenderExclusion(new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Temp", "k"), "CFG-DEFENDER-EXCL"));

        Assert.Equal(4, actions.Count);
        Assert.All(actions, a => Assert.Equal(RemediationStatus.WouldDo, a.Status));
        Assert.NotNull(f.Registry.GetValue(key, "Updater"));
        Assert.Single(f.Tasks.Tasks);
        Assert.Single(f.Defender.Exclusions);
        Assert.Empty(f.Defender.Calls);
        Assert.Equal("6.6.6.6 bank.example\n", File.ReadAllText(hosts));
        Assert.False(File.Exists(f.ManifestPath));
    }

    [Fact]
    public void Rollback_UnsupportedKind_IsSkippedWithExplanation()
    {
        using var f = new Fixture();
        var entry = new PersistenceEntry
        {
            Kind = PersistenceKind.WmiSubscription,
            Location = "root/subscription",
            Name = "x",
            Findings = [Audit.AuditFinding.Create("PERS-WMI", Severity.High, "t", "d")],
        };
        var action = f.Engine().RollbackPersistence(entry);
        Assert.Equal(RemediationStatus.Skipped, action.Status);
        Assert.False(string.IsNullOrEmpty(action.Message));
    }

    // ---- Исключения Defender --------------------------------------------------

    [Fact]
    public void RemoveDefenderExclusions_CallsWmiRemove_ForEveryKind_WithBackup()
    {
        using var f = new Fixture();
        DefenderExclusion[] exclusions =
        [
            new(DefenderExclusionKind.Path, @"C:\Users\Bob\AppData\Local\Temp", "k"),
            new(DefenderExclusionKind.Process, "powershell.exe", "k"),
            new(DefenderExclusionKind.Extension, "exe", "k"),
            new(DefenderExclusionKind.IpAddress, "203.0.113.7", "k"),
        ];
        f.Defender.Exclusions.AddRange(exclusions.Select(e => (e.Kind, e.Value)));
        var engine = f.Engine();

        var actions = engine.RemoveDefenderExclusions(exclusions, "CFG-DEFENDER-EXCL");

        Assert.All(actions, a => Assert.Equal(RemediationStatus.Done, a.Status));
        Assert.Empty(f.Defender.Exclusions);
        Assert.Equal(4, f.Defender.Calls.Count);
        Assert.All(f.Defender.Calls, c => Assert.StartsWith("Remove:", c));

        var backups = engine.ListRollbackEntries();
        Assert.Equal(["ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress"], backups.Select(b => b.Target).ToArray());
        Assert.All(backups, b => Assert.Equal(RollbackKind.DefenderExclusion, b.Kind));
        Assert.Equal("203.0.113.7", backups[3].PreviousValue);

        // Отмена возвращает исключение через MSFT_MpPreference.Add.
        Assert.Equal(RemediationStatus.Done, engine.Undo(backups[1].Id).Status);
        Assert.Equal((DefenderExclusionKind.Process, "powershell.exe"), Assert.Single(f.Defender.Exclusions));
    }

    [Fact]
    public void RemoveDefenderExclusion_ProviderFailure_IsReported_AndNothingLeftToUndo()
    {
        using var f = new Fixture();
        f.Defender.FailRemove = true;
        var engine = f.Engine();
        var action = engine.RemoveDefenderExclusion(new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Temp", "k"), "r");
        Assert.Equal(RemediationStatus.Failed, action.Status);
        Assert.Contains("0x800106ba", action.Message);
        Assert.Equal(RemediationStatus.Skipped, engine.Undo(Assert.Single(engine.ListRollbackEntries()).Id).Status);
    }

    [Fact]
    public void RemoveDefenderExclusion_FromPolicy_DeletesRegistryValue_NotWmi()
    {
        using var f = new Fixture();
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths");
        f.Registry.Set(key, @"D:\Stuff", "0");
        var exclusion = Assert.Single(new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), f.Registry).Audit().DefenderExclusions);
        Assert.True(exclusion.FromPolicy);
        var engine = f.Engine();

        var action = engine.RemoveDefenderExclusion(exclusion, "CFG-DEFENDER-EXCL");

        Assert.Equal(RemediationStatus.Done, action.Status);
        Assert.Empty(f.Defender.Calls);
        Assert.Null(f.Registry.GetValue(key, @"D:\Stuff"));
        Assert.Equal(RemediationStatus.Done, engine.Undo(action.RollbackId!).Status);
        Assert.Equal("0", f.Registry.GetValue(key, @"D:\Stuff")!.Value);
    }

    [Fact]
    public void Undo_UnknownId_Fails()
    {
        using var f = new Fixture();
        Assert.Equal(RemediationStatus.Failed, f.Engine().Undo("ffffffffffff").Status);
    }

    [Fact]
    public void Engine_WithoutProviders_FailsGracefully()
    {
        using var f = new Fixture();
        var engine = new RemediationEngine(new FakeWhitelist(), new RemediationOptions { RollbackManifestPath = f.ManifestPath });
        Assert.Equal(RemediationStatus.Failed, engine.TerminateProcessTree(1234).Status);
        Assert.Equal(RemediationStatus.Failed,
            engine.RemoveDefenderExclusion(new DefenderExclusion(DefenderExclusionKind.Path, "x", "k"), "r").Status);
    }

    [Fact]
    public void CreateDefault_OnNonWindows_Throws()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var f = new Fixture();
        Assert.Throws<PlatformNotSupportedException>(() =>
            RemediationEngine.CreateDefault(new FakeWhitelist(), RemediationOptions.CreateDefault(f.Tmp.Path)));
    }
}
