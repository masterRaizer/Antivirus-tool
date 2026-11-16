using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>1.3.2: одинаковые образы процессов и цели автозапуска анализируются за прогон один раз.</summary>
public class ScanSpeedV132Tests
{
    private static FileAnalyzer Analyzer(FakeVerifier verifier) =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), verifier);

    [Fact]
    public void ProcessAuditor_AnalyzesSharedImageOnce()
    {
        using var tmp = new TempDir();
        var exe = tmp.Write("svchost.exe", SyntheticArtifacts.BuildPe());
        var verifier = FakeVerifier.WithStatus(SignatureStatus.NotSigned);
        var auditor = new ProcessAuditor(new ProcessAuditorOptions(), Analyzer(verifier));
        var processes = Enumerable.Range(1, 40).Select(i => new ProcessSnapshot { Pid = 1000 + i, ParentPid = 4, Name = "worker.exe", ExecutablePath = exe }).ToList();

        Parallel.ForEach(processes, p => auditor.Audit([p]));

        Assert.Single(verifier.Calls);
    }

    [Fact]
    public void PersistenceAuditor_AnalyzesSharedServiceBinaryOnce()
    {
        using var tmp = new TempDir();
        var exe = tmp.Write(Path.Combine("Temp", "host.exe"), SyntheticArtifacts.BuildPe());
        var reg = new InMemoryRegistryProvider();
        for (var i = 0; i < 25; i++)
        {
            var key = new RegistryKeyPath(RegistryHive.LocalMachine, $@"SYSTEM\CurrentControlSet\Services\Svc{i}");
            reg.Set(key, "ImagePath", exe).Set(key, "Start", "2", RegistryValueKind.Dword);
        }

        var verifier = FakeVerifier.WithStatus(SignatureStatus.NotSigned);
        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg, analyzer: Analyzer(verifier)).Audit();

        Assert.Equal(25, report.Entries.Count(e => e.Kind == PersistenceKind.Service));
        Assert.Single(verifier.Calls);
    }
}

/// <summary>1.3.3: ImagePath удалённого временного драйвера Защитника не обрезается до «C:\ProgramData\Microsoft\Windows».</summary>
public class DefenderMissingDriverV133Tests
{
    private const string KslImage = @"\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}\MpKslDrv.sys";

    [Theory]
    [InlineData(@"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{0F1E2D3C}\MpKslDrv.sys",
        @"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{0F1E2D3C}\MpKslDrv.sys")]
    [InlineData(@"C:\Program Files\Removed App\app.exe --tray", @"C:\Program Files\Removed App\app.exe")]
    [InlineData(@"C:\Temp\x.exe -a", @"C:\Temp\x.exe")]
    public void MissingFile_ResolvesToFirstExecutableWord(string command, string expected) =>
        Assert.Equal(expected, CommandLineParser.ResolveExecutable(command, _ => false));

    [Fact]
    public void MissingDefenderKslDriver_IsNotUserWritableService()
    {
        var reg = new InMemoryRegistryProvider();
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\MpKslbffc8b48");
        reg.Set(key, "ImagePath", KslImage).Set(key, "Start", "3", RegistryValueKind.Dword);

        var options = new PersistenceAuditorOptions
        {
            FileExists = _ => false,
            TrustedBinaryDirectories = [@"C:\ProgramData\Microsoft\Windows Defender\Definition Updates"],
        };

        var report = new PersistenceAuditor(options, reg).Audit();

        Assert.DoesNotContain(report.Entries, e => e.Findings.Any(f => f.Id == "PERS-SERVICE-USERWRITABLE"));
    }
}
