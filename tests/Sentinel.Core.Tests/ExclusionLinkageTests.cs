using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Detection;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class DefenderExclusionTests
{
    private static DefenderExclusion Ex(DefenderExclusionKind kind, string value) => new(kind, value, "HKLM\\test");

    [Theory]
    [InlineData(@"C:\Users\Bob\AppData\Local\Temp", @"C:\Users\Bob\AppData\Local\Temp\a.exe", true)]
    [InlineData(@"C:\Users\Bob\AppData\Local\Temp\", @"c:/users/bob/appdata/local/temp/sub/a.exe", true)]
    [InlineData(@"C:\Users\Bob\AppData\Local\Temp", @"C:\Users\Bob\AppData\Local\Temporary\a.exe", false)]
    [InlineData(@"C:\Tools\miner.exe", @"C:\Tools\miner.exe", true)]
    [InlineData(@"C:\Tools\miner.exe", @"C:\Tools\miner.exe.bak", false)]
    [InlineData(@"C:\Users\*\Downloads", @"C:\Users\Bob\Downloads\x\a.exe", true)]
    [InlineData(@"C:\Users\*\Downloads", @"C:\Users\Bob\Documents\a.exe", false)]
    public void PathExclusion_CoversFile(string exclusion, string file, bool expected)
    {
        Assert.Equal(expected, Ex(DefenderExclusionKind.Path, exclusion).CoversFile(file));
    }

    [Theory]
    [InlineData("powershell.exe", "PowerShell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", true)]
    [InlineData("powershell.exe", "pwsh.exe", @"C:\Program Files\PowerShell\7\pwsh.exe", false)]
    [InlineData(@"C:\Temp\x.exe", "x.exe", @"c:\temp\X.EXE", true)]
    [InlineData(@"C:\Temp\x.exe", "x.exe", @"C:\Other\x.exe", false)]
    [InlineData(@"C:\Temp\x.exe", "x.exe", null, false)]
    [InlineData("xmr*.exe", "xmrig.exe", null, true)]
    public void ProcessExclusion_CoversProcess(string exclusion, string name, string? path, bool expected)
    {
        Assert.Equal(expected, Ex(DefenderExclusionKind.Process, exclusion).CoversProcess(name, path));
    }

    [Fact]
    public void ExtensionExclusion_CoversFilesByExtension_AndNeverProcesses()
    {
        var e = Ex(DefenderExclusionKind.Extension, ".EXE");
        Assert.True(e.CoversFile(@"C:\a\b.exe"));
        Assert.False(e.CoversFile(@"C:\a\b.dll"));
        Assert.False(e.CoversProcess("b.exe", @"C:\a\b.exe"));
        Assert.Equal("ExclusionExtension", e.PreferenceProperty);
    }

    [Fact]
    public void PreferenceProperty_MapsAllKinds()
    {
        Assert.Equal("ExclusionPath", Ex(DefenderExclusionKind.Path, "x").PreferenceProperty);
        Assert.Equal("ExclusionProcess", Ex(DefenderExclusionKind.Process, "x").PreferenceProperty);
        Assert.Equal("ExclusionIpAddress", Ex(DefenderExclusionKind.IpAddress, "10.0.0.1").PreferenceProperty);
    }
}

public class ExclusionLinkageTests
{
    private const string Root = @"SOFTWARE\Microsoft\Windows Defender\Exclusions\";
    private const string PolicyRoot = @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\";
    private const string MsSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    private static RegistryKeyPath Key(string sub, bool policy = false) =>
        new(RegistryHive.LocalMachine, (policy ? PolicyRoot : Root) + sub);

    private static FileAnalyzer Analyzer(ISignatureVerifier? verifier = null, IWhitelistProvider? whitelist = null, long maxScan = 64L * 1024 * 1024) =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)),
            verifier ?? new UnavailableSignatureVerifier(), whitelist, new FileAnalyzerOptions { MaxScanBytes = maxScan });

    private static ExclusionPriorityScanner Scanner(FileAnalyzer analyzer, ExclusionScanOptions? options = null) =>
        new(analyzer, new ProcessAuditor(new ProcessAuditorOptions(), analyzer), options);

    [Fact]
    public void Auditor_CollectsAllExclusionKinds_FromBothRoots()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(Key("Paths"), @"C:\Users\Bob\AppData\Local\Temp", "0");
        reg.Set(Key("Processes"), "powershell.exe", "0");
        reg.Set(Key("Extensions"), "exe", "0");
        reg.Set(Key("IpAddresses"), "203.0.113.7", "0");
        reg.Set(Key("Paths", policy: true), @"D:\Stuff", "0");

        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();

        Assert.Equal(5, report.DefenderExclusions.Count);
        Assert.Equal(5, report.CountOf(ConfigArea.DefenderExclusion));
        Assert.Contains(report.DefenderExclusions, e => e is { Kind: DefenderExclusionKind.IpAddress, Value: "203.0.113.7" });
        Assert.Contains(report.DefenderExclusions, e => e is { Kind: DefenderExclusionKind.Path, FromPolicy: true, Value: @"D:\Stuff" });
        Assert.All(report.DefenderExclusions.Where(e => e.Value != @"D:\Stuff"), e => Assert.False(e.FromPolicy));
    }

    [Fact]
    public void Auditor_InterpreterProcessExclusion_IsHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(Key("Processes"), @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "0");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        Assert.Equal(Severity.High, Assert.Single(report.Findings).Severity);
    }

    [Fact]
    public void ExcludedDirectory_IsDeepScanned_AndThreatsAreFound()
    {
        using var tmp = new TempDir();
        var excluded = Path.Combine(tmp.Path, "excluded");
        var eicar = tmp.Write(Path.Combine("excluded", "deep", "eicar.com"), Eicar.CreateTestFileBytes());
        var stub = tmp.Write(Path.Combine("excluded", "plain.exe"), SyntheticArtifacts.BuildPe());
        var script = tmp.WriteText(Path.Combine("excluded", "run.ps1"), "Write-Host hi");
        var text = tmp.WriteText(Path.Combine("excluded", "notes.txt"), "notes");
        tmp.Write("outside.exe", SyntheticArtifacts.BuildPe());

        var reg = new InMemoryRegistryProvider();
        reg.Set(Key("Paths"), excluded, "0");
        var config = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();

        var report = Scanner(Analyzer()).Scan(config.DefenderExclusions, []);

        var entry = Assert.Single(report.Entries);
        Assert.Equal(4, entry.Files.Count);
        Assert.All(entry.Files, f => Assert.NotNull(f.PriorityReason));
        Assert.Equal(Verdict.Malicious, entry.Files.Single(f => f.Path == eicar).Verdict);

        // Обычный неподписанный PE сам по себе чист, но под исключением защиты — подозрителен.
        var stubResult = entry.Files.Single(f => f.Path == stub);
        Assert.Equal(Verdict.Suspicious, stubResult.Verdict);
        Assert.Contains(stubResult.Detections, d => d.Name == "Heuristic.DefenderExcludedExecutable");
        Assert.Equal(Verdict.Suspicious, entry.Files.Single(f => f.Path == script).Verdict);

        var textResult = entry.Files.Single(f => f.Path == text);
        Assert.Equal(Verdict.Clean, textResult.Verdict);
        Assert.NotNull(textResult.Signature); // в глубоком режиме подпись проверяется у любого файла
        Assert.Equal(3, report.FlaggedFiles.Count());
    }

    [Fact]
    public void DeepScan_IgnoresRegularSizeLimit()
    {
        using var tmp = new TempDir();
        // Обычный лимит (16 байт) обрезает EICAR и детект теряется; глубокий режим читает файл целиком.
        var path = tmp.Write("eicar.com", Eicar.CreateTestFileBytes());
        var analyzer = Analyzer(maxScan: 16);

        var regular = analyzer.Analyze(path);
        var deep = analyzer.Analyze(path, new PriorityScanContext("ExclusionPath: test"));

        Assert.True(regular.Truncated);
        Assert.NotEqual(Verdict.Malicious, regular.Verdict);
        Assert.False(deep.Truncated);
        Assert.Equal(Verdict.Malicious, deep.Verdict);
        Assert.Equal(regular.Sha256, deep.Sha256);
    }

    [Fact]
    public void SignedExecutable_UnderExclusion_IsNotFlaggedByExclusionHeuristic()
    {
        using var tmp = new TempDir();
        var path = tmp.Write("vendor.exe", SyntheticArtifacts.BuildPe());
        var r = Analyzer(FakeVerifier.Valid("CN=Vendor")).Analyze(path, new PriorityScanContext("ExclusionPath: x"));
        Assert.Equal(Verdict.Clean, r.Verdict);
    }

    [Fact]
    public void MaxFilesPerExclusion_TruncatesAndReports()
    {
        using var tmp = new TempDir();
        for (var i = 0; i < 5; i++)
        {
            tmp.WriteText(Path.Combine("ex", $"f{i}.txt"), "x");
        }

        var exclusion = new DefenderExclusion(DefenderExclusionKind.Path, Path.Combine(tmp.Path, "ex"), "k");
        var report = Scanner(Analyzer(), new ExclusionScanOptions { MaxFilesPerExclusion = 3 }).Scan([exclusion], []);
        var entry = Assert.Single(report.Entries);
        Assert.True(entry.Truncated);
        Assert.Equal(3, entry.Files.Count);
    }

    [Fact]
    public void MissingPath_And_NonFileKinds_ProduceNotes()
    {
        using var tmp = new TempDir();
        DefenderExclusion[] exclusions =
        [
            new(DefenderExclusionKind.Path, Path.Combine(tmp.Path, "missing"), "k"),
            new(DefenderExclusionKind.Extension, "exe", "k"),
            new(DefenderExclusionKind.IpAddress, "203.0.113.7", "k"),
            new(DefenderExclusionKind.Process, "powershell.exe", "k"),
        ];
        var report = Scanner(Analyzer()).Scan(exclusions, []);
        Assert.Equal(4, report.Entries.Count);
        Assert.All(report.Entries, e =>
        {
            Assert.Empty(e.Files);
            Assert.False(string.IsNullOrEmpty(e.Note));
        });
    }

    [Fact]
    public void ProcessExclusionByFullPath_ScansImageFile_EvenWhenNotRunning()
    {
        using var tmp = new TempDir();
        var image = tmp.Write("tool.exe", SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x4000 }));
        var report = Scanner(Analyzer()).Scan([new DefenderExclusion(DefenderExclusionKind.Process, image, "k")], []);
        var file = Assert.Single(Assert.Single(report.Entries).Files);
        Assert.Contains(file.Detections, d => d.Name == "Heuristic.PackedUnsignedPE");
        Assert.Contains(file.Detections, d => d.Name == "Heuristic.DefenderExcludedExecutable");
    }

    [Fact]
    public void RunningProcesses_UnderExclusions_ArePrioritizedAndDeepScanned()
    {
        using var tmp = new TempDir();
        var excludedDir = Path.Combine(tmp.Path, "ex");
        var dropped = tmp.Write(Path.Combine("ex", "updater.exe"), SyntheticArtifacts.BuildPe());
        var normal = tmp.Write("normal.exe", SyntheticArtifacts.BuildPe());

        ProcessSnapshot[] processes =
        [
            new() { Pid = 10, Name = "normal.exe", ExecutablePath = normal },
            new() { Pid = 20, Name = "updater.exe", ExecutablePath = dropped },
            new() { Pid = 30, Name = "powershell.exe", ExecutablePath = null, CommandLine = "powershell.exe" },
        ];
        DefenderExclusion[] exclusions =
        [
            new(DefenderExclusionKind.Path, excludedDir, "k"),
            new(DefenderExclusionKind.Process, "PowerShell.exe", "k"),
        ];

        var report = Scanner(Analyzer()).Scan(exclusions, processes);

        // Приоритет: процессы под исключениями идут первыми.
        Assert.Equal([20, 30, 10], report.Processes.Entries.Select(e => e.Process.Pid).ToArray());
        Assert.Equal(2, report.ExcludedProcesses.Count());

        var updater = report.Processes.Entries[0];
        Assert.Contains(updater.Findings, f => f.Id == "PROC-DEFENDER-EXCLUDED");
        Assert.NotNull(updater.FileScan!.PriorityReason);
        Assert.Equal(Verdict.Suspicious, updater.FileScan.Verdict);

        var ps = report.Processes.Entries[1];
        Assert.Equal(Severity.High, ps.Findings.Single(f => f.Id == "PROC-DEFENDER-EXCLUDED").Severity);

        var regular = report.Processes.Entries[2];
        Assert.Empty(regular.MatchedExclusions);
        Assert.DoesNotContain(regular.Findings, f => f.Id == "PROC-DEFENDER-EXCLUDED");
        Assert.Null(regular.FileScan!.PriorityReason);

        // Файл образа привязан к записи своего исключения и не проверяется дважды.
        var pathEntry = report.Entries[0];
        Assert.Single(pathEntry.Files);
        Assert.Same(updater, Assert.Single(pathEntry.Processes));
    }

    [Fact]
    public void AuditWithoutExclusions_BehavesAsBefore()
    {
        var auditor = new ProcessAuditor();
        var report = auditor.Audit([new ProcessSnapshot { Pid = 1, Name = "a.exe", ExecutablePath = @"C:\a.exe" }]);
        Assert.Empty(Assert.Single(report.Entries).MatchedExclusions);
        Assert.Equal(0, report.FlaggedCount);
    }

    // ---- SystemWhitelist не доверяет исключениям Defender ----------------------

    [Fact]
    public void Whitelist_IgnoresDefenderExclusions_UnsignedFileInExcludedPathIsNotTrusted()
    {
        using var tmp = new TempDir();
        var system32 = Path.Combine(tmp.Path, "Windows", "System32");
        var excluded = Path.Combine(tmp.Path, "Users", "Public");
        var dropped = tmp.Write(Path.Combine("Users", "Public", "svchost.exe"), SyntheticArtifacts.BuildPe());
        var planted = tmp.Write(Path.Combine("Windows", "System32", "planted.exe"), SyntheticArtifacts.BuildPe());

        // Исключены и пользовательский каталог, и сам System32 — на доверие это влиять не должно.
        DefenderExclusion[] exclusions =
        [
            new(DefenderExclusionKind.Path, excluded, "k"),
            new(DefenderExclusionKind.Path, system32, "k"),
            new(DefenderExclusionKind.Extension, "exe", "k"),
        ];
        var verifier = FakeVerifier.WithStatus(SignatureStatus.NotSigned);
        var whitelist = new SystemWhitelist(verifier, new WhitelistOptions { ProtectedDirectories = [system32] });

        Assert.False(whitelist.Evaluate(dropped).IsWhitelisted);
        Assert.False(whitelist.Evaluate(planted).IsWhitelisted);

        var report = Scanner(Analyzer(verifier, whitelist)).Scan(exclusions, []);
        Assert.All(report.Entries.SelectMany(e => e.Files), f =>
        {
            Assert.NotEqual(Verdict.Trusted, f.Verdict);
            Assert.False(f.Whitelist!.IsWhitelisted);
        });
        Assert.Contains(report.FlaggedFiles, f => f.Path == planted);
    }

    [Fact]
    public void Whitelist_TrustsOnlyMicrosoftSignedFilesInProtectedDirectories_RegardlessOfExclusions()
    {
        using var tmp = new TempDir();
        var system32 = Path.Combine(tmp.Path, "Windows", "System32");
        var signedSystem = tmp.Write(Path.Combine("Windows", "System32", "kernel32.dll"), SyntheticArtifacts.BuildPe(new() { IsDll = true }));
        var signedOutside = tmp.Write(Path.Combine("Users", "Public", "ms-signed.exe"), SyntheticArtifacts.BuildPe());

        var msSigned = FakeVerifier.Valid(MsSubject);
        var whitelist = new SystemWhitelist(msSigned, new WhitelistOptions { ProtectedDirectories = [system32] });
        var thirdParty = new SystemWhitelist(FakeVerifier.Valid("CN=Evil Corp, O=Evil Corp"), new WhitelistOptions { ProtectedDirectories = [system32] });

        Assert.True(whitelist.Evaluate(signedSystem).IsWhitelisted);
        Assert.False(whitelist.Evaluate(signedOutside).IsWhitelisted);   // подпись Microsoft, но не системный каталог
        Assert.False(thirdParty.Evaluate(signedSystem).IsWhitelisted);   // системный каталог, но издатель не Microsoft

        // Наличие исключения не снимает доверия с легитимного системного файла и не добавляет его чужому.
        var report = Scanner(Analyzer(msSigned, whitelist)).Scan(
            [new DefenderExclusion(DefenderExclusionKind.Path, tmp.Path, "k")], []);
        var files = Assert.Single(report.Entries).Files;
        Assert.Equal(Verdict.Trusted, files.Single(f => f.Path == signedSystem).Verdict);
        Assert.Equal(Verdict.Clean, files.Single(f => f.Path == signedOutside).Verdict);
    }
}
