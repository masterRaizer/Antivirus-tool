using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Runtime;

namespace Sentinel.Core.Tests;

public class RecoveryModeTests
{
    private static BootProbes Probes(int metric = 0, string? safeboot = null, bool winpe = false, bool miniNt = false) => new(
        () => metric,
        name => name == "SAFEBOOT_OPTION" ? safeboot : null,
        path => winpe && path == RecoveryEnvironment.WinPeShellIni,
        key => miniNt && key == RecoveryEnvironment.MiniNtKey);

    [Fact]
    public void NormalBoot_IsDetectedAsNormal() => Assert.Equal(BootEnvironment.Normal, RecoveryEnvironment.Detect(Probes()));

    [Theory]
    [InlineData(1, null, BootEnvironment.SafeMode)]
    [InlineData(2, null, BootEnvironment.SafeModeWithNetworking)]
    [InlineData(0, "MINIMAL", BootEnvironment.SafeMode)]
    [InlineData(0, "Network", BootEnvironment.SafeModeWithNetworking)]
    [InlineData(0, "  ", BootEnvironment.Normal)]
    public void SafeMode_ByCleanBootMetricOrSafebootOption(int metric, string? option, BootEnvironment expected) =>
        Assert.Equal(expected, RecoveryEnvironment.Detect(Probes(metric, option)));

    [Fact]
    public void WinRe_ByWinPeShellIni_OrMiniNtKey_TakesPrecedence()
    {
        Assert.Equal(BootEnvironment.RecoveryEnvironment, RecoveryEnvironment.Detect(Probes(winpe: true)));
        Assert.Equal(BootEnvironment.RecoveryEnvironment, RecoveryEnvironment.Detect(Probes(metric: 1, miniNt: true)));
    }

    [Fact]
    public void FailingProbes_DoNotBreakDetection()
    {
        var probes = new BootProbes(
            () => throw new DllNotFoundException("user32"),
            _ => null,
            _ => throw new UnauthorizedAccessException(),
            _ => throw new System.Security.SecurityException());
        Assert.Equal(BootEnvironment.Normal, RecoveryEnvironment.Detect(probes));
    }

    [Fact]
    public void RecoveryModeFlags_AndDescriptions()
    {
        Assert.False(BootEnvironment.Normal.IsRecoveryMode());
        Assert.True(BootEnvironment.SafeMode.IsRecoveryMode());
        Assert.True(BootEnvironment.RecoveryEnvironment.IsRecoveryMode());
        Assert.Contains("WinRE", BootEnvironment.RecoveryEnvironment.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void CurrentLinuxProcess_IsNormal()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(BootEnvironment.Normal, RecoveryEnvironment.DetectCurrent());
        }
    }

    [Fact]
    public void DataDirectory_FallsBackToFirstWritableCandidate()
    {
        var chosen = DataDirectoryResolver.Choose(
            [@"C:\ProgramData\Sentinel", @"X:\Tools\SentinelData", @"C:\Users\Bob\AppData\Local\Sentinel"],
            path => !path.StartsWith(@"C:\ProgramData", StringComparison.Ordinal));
        Assert.Equal(@"X:\Tools\SentinelData", chosen);
    }

    [Fact]
    public void DataDirectory_RealProbe_SkipsUnwritableAndUsesPortableFolder()
    {
        using var tmp = new TempDir();
        var blocker = tmp.WriteText("not-a-directory", "file blocks directory creation");
        var portable = Path.Combine(tmp.Path, DataDirectoryResolver.PortableFolderName);

        var chosen = DataDirectoryResolver.Choose([Path.Combine(blocker, "Sentinel"), portable]);

        Assert.Equal(portable, chosen);
        Assert.True(Directory.Exists(portable));
        Assert.Empty(Directory.EnumerateFiles(portable)); // пробный файл удалён
    }

    [Fact]
    public void DefaultCandidates_StartWithProgramData_ThenPortableFolderNextToExecutable()
    {
        var candidates = DataDirectoryResolver.DefaultCandidates();
        Assert.Equal(SentinelRuntimeOptions.DefaultDataDirectory(), candidates[0]);
        Assert.Equal(Path.Combine(AppContext.BaseDirectory, "SentinelData"), candidates[1]);
        Assert.EndsWith("SentinelData", candidates[^1], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("C:", @"C:\")]
    [InlineData("  \"D:\\Windows\"  ", @"D:\Windows")]
    [InlineData(@"E:\", @"E:\")]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void ManualPath_IsNormalized(string? input, string? expected) =>
        Assert.Equal(expected, SentinelRuntime.NormalizeManualPath(input));

    private sealed class StoppedWmi : IWmiSubscriptionProvider
    {
        public WmiSubscriptionSnapshot GetSubscriptions() => throw new System.ComponentModel.Win32Exception(1062, "Служба winmgmt не запущена");
    }

    private sealed class StoppedScheduler : ITaskSchedulerProvider
    {
        public IReadOnlyList<ScheduledTaskInfo> GetTasks() => throw new UnauthorizedAccessException("Нет доступа к System32\\Tasks");
    }

    private sealed class StoppedDefender : IDefenderExclusionSource
    {
        public IReadOnlyList<DefenderExclusion> GetExclusions() => throw new InvalidOperationException("Defender недоступен");
    }

    private sealed class BrokenCertificateStore : ICertificateStoreProvider
    {
        public IReadOnlyList<CertificateInfo> GetRootCertificates() => throw new System.Security.Cryptography.CryptographicException("store");
    }

    [Fact]
    public void PersistenceAudit_SkipsStoppedServices_AndCompletesOtherSteps()
    {
        using var tmp = new TempDir();
        var hosts = tmp.WriteText("hosts", "203.0.113.9 bank.test\n");
        var registry = new InMemoryRegistryProvider();
        registry.Set(new RegistryKeyPath(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"), "Tool", @"C:\Users\Bob\AppData\Local\Temp\tool.exe");

        var report = new PersistenceAuditor(new PersistenceAuditorOptions { HostsFilePath = hosts }, registry, new StoppedScheduler(), new StoppedWmi()).Audit();

        Assert.Contains(report.Skipped, s => s.Step == "Подписки WMI" && s.Reason.Contains("winmgmt", StringComparison.Ordinal));
        Assert.Contains(report.Skipped, s => s.Step == "Планировщик задач");
        Assert.Contains(report.Entries, e => e.Kind == PersistenceKind.HostsFile);
        Assert.Contains(report.Entries, e => e.Name == "Tool");
    }

    [Fact]
    public void ConfigAudit_SkipsUnavailableDefenderAndCertificateStore_AndKeepsRegistryResults()
    {
        var registry = new InMemoryRegistryProvider();
        registry.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"), @"C:\Users\Public", "0");

        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), registry, new BrokenCertificateStore(), new StoppedDefender()).Audit();

        Assert.Single(report.DefenderExclusions); // реестр прочитан, хотя WMI-источник Defender недоступен
        Assert.Contains(report.Skipped, s => s.Step == "Корневые сертификаты");
        Assert.DoesNotContain(report.Skipped, s => s.Step == "Исключения Defender");
    }
}
