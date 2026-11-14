using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Detection;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

internal sealed class FakeTaskProvider(params ScheduledTaskInfo[] tasks) : ITaskSchedulerProvider
{
    public IReadOnlyList<ScheduledTaskInfo> GetTasks() => tasks;
}

internal sealed class FakeWmiProvider(WmiSubscriptionSnapshot snapshot) : IWmiSubscriptionProvider
{
    public WmiSubscriptionSnapshot GetSubscriptions() => snapshot;
}

public class PersistenceAuditorTests
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string WinlogonKey = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string IfeoKey = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    private static FileAnalyzer Analyzer() =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), new UnavailableSignatureVerifier());

    private static bool Has(PersistenceAuditReport r, string id) =>
        r.Entries.Any(e => e.Findings.Any(f => f.Id == id));

    [Fact]
    public void Audit_RunKeyWithEicarTarget_FlagsDetection()
    {
        using var tmp = new TempDir();
        var payload = tmp.Write("payload.exe", Eicar.CreateTestFileBytes());
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.CurrentUser, RunKey), "Updater", payload);

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg, analyzer: Analyzer()).Audit();

        var entry = Assert.Single(report.Entries, e => e.Kind == PersistenceKind.RegistryRun);
        Assert.Equal(Verdict.Malicious, entry.FileScan!.Verdict);
        Assert.Contains(entry.Findings, f => f.Id.StartsWith("PERS-FILE-", StringComparison.Ordinal));
    }

    [Fact]
    public void Audit_WinlogonShellHijack_FlagsHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, WinlogonKey), "Shell", "explorer.exe,C:\\Temp\\evil.exe");
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg).Audit();
        Assert.True(Has(report, "PERS-WINLOGON-SHELL"));
    }

    [Fact]
    public void Audit_WinlogonDefaultShell_NoFinding()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, WinlogonKey), "Shell", "explorer.exe");
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, WinlogonKey), "Userinit", @"C:\Windows\system32\userinit.exe,");
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg).Audit();
        Assert.False(Has(report, "PERS-WINLOGON-SHELL"));
        Assert.False(Has(report, "PERS-WINLOGON-USERINIT"));
    }

    [Fact]
    public void Audit_UserinitHijack_FlagsHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, WinlogonKey), "Userinit",
            @"C:\Windows\system32\userinit.exe,C:\Temp\evil.exe");
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg).Audit();
        Assert.True(Has(report, "PERS-WINLOGON-USERINIT"));
    }

    [Fact]
    public void Audit_IfeoDebugger_FlagsHijack()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, IfeoKey + @"\sethc.exe"), "Debugger", @"C:\Windows\System32\cmd.exe");
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg).Audit();
        Assert.True(Has(report, "PERS-IFEO-DEBUGGER"));
        var entry = Assert.Single(report.Entries, e => e.Kind == PersistenceKind.ImageFileExecutionOptions);
        Assert.Equal("sethc.exe", entry.Name);
    }

    [Fact]
    public void Audit_ServiceInUserWritableAutoStart_FlagsHigh()
    {
        var reg = new InMemoryRegistryProvider();
        var svc = new RegistryKeyPath(RegistryHive.LocalMachine, ServicesKey + @"\EvilSvc");
        reg.Set(svc, "ImagePath", @"C:\Temp\evil.exe");
        reg.Set(svc, "Start", "2", RegistryValueKind.Dword);
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg).Audit();
        var entry = Assert.Single(report.Entries, e => e.Kind == PersistenceKind.Service);
        Assert.Contains(entry.Findings, f => f.Id == "PERS-SERVICE-USERWRITABLE" && f.Severity == Severity.High);
    }

    [Fact]
    public void Audit_ServiceInSystem32_NotFlagged()
    {
        var reg = new InMemoryRegistryProvider();
        var svc = new RegistryKeyPath(RegistryHive.LocalMachine, ServicesKey + @"\GoodSvc");
        reg.Set(svc, "ImagePath", @"C:\Windows\System32\good.exe");
        reg.Set(svc, "Start", "2", RegistryValueKind.Dword);
        var options = new PersistenceAuditorOptions { TrustedBinaryDirectories = [@"C:\Windows\System32"] };
        var report = new PersistenceAuditor(options, reg).Audit();
        Assert.DoesNotContain(report.Entries, e => e.Kind == PersistenceKind.Service);
    }

    [Fact]
    public void Audit_ScheduledTaskWithEncodedPowerShell_Flags()
    {
        var task = new ScheduledTaskInfo("Evil", "\\Evil", true,
            [new ScheduledTaskAction("powershell.exe", "-w hidden -enc SQBFAFgA")]);
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), tasks: new FakeTaskProvider(task)).Audit();
        var entry = Assert.Single(report.Entries, e => e.Kind == PersistenceKind.ScheduledTask);
        Assert.Contains(entry.Findings, f => f.Id == "PROC-PS-ENCODED");
    }

    [Fact]
    public void Audit_WmiCommandLineConsumer_Flags()
    {
        var snapshot = new WmiSubscriptionSnapshot(
            [new WmiFilter("Flt", "SELECT * FROM __InstanceModificationEvent", "WQL")],
            [new WmiConsumer("Evil", "CommandLineEventConsumer", null, "powershell.exe -enc AAAA", null)]);
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), wmi: new FakeWmiProvider(snapshot)).Audit();
        Assert.True(Has(report, "PERS-WMI-CONSUMER"));
        Assert.True(Has(report, "PROC-PS-ENCODED"));
    }

    [Fact]
    public void Audit_StartupFolderWithEicar_FlagsDetection()
    {
        using var tmp = new TempDir();
        tmp.Write("payload.exe", Eicar.CreateTestFileBytes());
        var startupDir = System.IO.Path.GetDirectoryName(System.IO.Path.Combine(tmp.Path, "payload.exe"))!;
        var options = new PersistenceAuditorOptions { StartupDirectories = [startupDir] };
        var report = new PersistenceAuditor(options, analyzer: Analyzer()).Audit();
        var entry = Assert.Single(report.Entries, e => e.Kind == PersistenceKind.StartupFolder);
        Assert.Contains(entry.Findings, f => f.Id.StartsWith("PERS-FILE-", StringComparison.Ordinal));
    }

    [Fact]
    public void Audit_StartupLnkToUserWritable_Flags()
    {
        using var tmp = new TempDir();
        var lnk = SyntheticArtifacts.BuildShellLink(@"C:\Temp\dropper.exe", "-x");
        tmp.Write("hook.lnk", lnk);
        var options = new PersistenceAuditorOptions { StartupDirectories = [tmp.Path] };
        var report = new PersistenceAuditor(options).Audit();
        var entry = Assert.Single(report.Entries, e => e.Kind == PersistenceKind.StartupFolder);
        Assert.Equal(@"C:\Temp\dropper.exe", entry.ResolvedTarget);
        Assert.Contains(entry.Findings, f => f.Id == "PERS-STARTUP-USERWRITABLE");
    }

    [Fact]
    public void Audit_HostsFile_FlagsSecurityAndRedirect()
    {
        using var tmp = new TempDir();
        var hosts = tmp.WriteText("hosts", "0.0.0.0 update.microsoft.com\n203.0.113.9 bank.test\n127.0.0.1 localhost\n");
        var options = new PersistenceAuditorOptions { HostsFilePath = hosts };
        var report = new PersistenceAuditor(options).Audit();
        Assert.True(Has(report, "PERS-HOSTS-SECURITY"));
        Assert.True(Has(report, "PERS-HOSTS-REDIRECT"));
        // localhost (loopback, не защищённый домен) не помечается
        Assert.DoesNotContain(report.Entries, e => e.Kind == PersistenceKind.HostsFile && e.Name == "localhost");
    }

    [Fact]
    public void Audit_NoProviders_EmptyReport()
    {
        var report = new PersistenceAuditor(new PersistenceAuditorOptions()).Audit();
        Assert.Empty(report.Entries);
    }
}
