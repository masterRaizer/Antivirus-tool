using Sentinel.Core.Pe;
using Sentinel.Core.Scanning;
using Sentinel.Core.Scoring;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;

namespace Sentinel.Core.Tests;

public class ThreatScoringTests
{
    internal static PeInfo Pe(bool dll = false, bool managed = false, bool wx = false, string sectionName = ".text")
    {
        var flags = SectionCharacteristics.Code | SectionCharacteristics.Execute | SectionCharacteristics.Read;
        if (wx)
        {
            flags |= SectionCharacteristics.Write;
        }

        var dirs = Enumerable.Range(0, 16).Select(i => new PeDataDirectory(managed && i == 14 ? 0x2000u : 0, managed && i == 14 ? 0x48u : 0)).ToArray();
        return new PeInfo
        {
            Machine = PeMachine.Amd64, Is64Bit = true, IsDll = dll, Subsystem = PeSubsystem.WindowsGui, TimeDateStamp = DateTimeOffset.UnixEpoch,
            EntryPointRva = 0x1000, ImageBase = 0x140000000, SizeOfImage = 0x4000, CheckSum = 0, Characteristics = 0x22, DllCharacteristics = 0,
            Sections = [new PeSection(sectionName, 0x1000, 0x1000, 0x400, 0x1000, flags, 5)],
            DataDirectories = dirs, OverlayOffset = 0, OverlaySize = 0, Anomalies = [],
        };
    }

    private static ScoringInput Input(PeInfo pe, string path = @"C:\Users\Bob\AppData\Local\Temp\x.exe") => new() { Path = path, Pe = pe };

    [Fact]
    public void UnsignedManagedDllInTemp_WithHighEntropy_IsClean()
    {
        var score = ThreatScoringEngine.Evaluate(Input(Pe(dll: true, managed: true), @"C:\Users\Bob\AppData\Local\Temp\Lib.dll") with { Entropy = 7.9 });
        Assert.Equal(5, score.Value);
        Assert.Null(score.Level);
    }

    [Fact]
    public void UnsignedNativeExeWithInjectAndAutorun_IsHighOrCritical()
    {
        var input = Input(Pe()) with
        {
            Entropy = 7.8,
            PersistenceBound = true,
            ObfuscatedCommandLine = true,
            Imports = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" },
        };
        var score = ThreatScoringEngine.Evaluate(input);
        Assert.True(score.Value >= 85, score.Describe());
        Assert.True(score.Level >= Severity.High);
    }

    [Theory]
    [InlineData(5, null)]
    [InlineData(24, null)]
    [InlineData(25, Severity.Info)]
    [InlineData(44, Severity.Info)]
    [InlineData(45, Severity.Low)]
    [InlineData(64, Severity.Low)]
    [InlineData(65, Severity.Medium)]
    [InlineData(84, Severity.Medium)]
    [InlineData(85, Severity.High)]
    [InlineData(99, Severity.High)]
    [InlineData(100, Severity.Critical)]
    public void Thresholds_MatchSpecification(int score, Severity? expected) => Assert.Equal(expected, ThreatScoringEngine.LevelFor(score));

    [Fact]
    public void MicrosoftSigned_ScoresClean_EvenWithSuspiciousImports()
    {
        var input = Input(Pe(), @"C:\Windows\System32\x.exe") with
        {
            SignatureValid = true,
            MicrosoftTrusted = true,
            Imports = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "SetWindowsHookExW", "GetAsyncKeyState" },
        };
        Assert.Equal(0, ThreatScoringEngine.Evaluate(input).Value);
    }

    [Fact]
    public void UserAllowedFile_IsClean() =>
        Assert.Equal(0, ThreatScoringEngine.Evaluate(Input(Pe()) with { UserAllowed = true, Entropy = 7.9 }).Value);

    [Fact]
    public void DefinitiveMatch_IsCritical() =>
        Assert.Equal(Severity.Critical, ThreatScoringEngine.Evaluate(Input(Pe()) with { DefinitiveMatch = "EICAR" }).Level);

    [Fact]
    public void ApiClusters_AddExpectedPoints()
    {
        static IReadOnlySet<string> Names(params string[] n) => new HashSet<string>(n, StringComparer.OrdinalIgnoreCase);
        var pe = Pe();
        int Score(ScoringInput i) => ThreatScoringEngine.Evaluate(i with { SignatureValid = true }).Value;

        Assert.Equal(35, Score(Input(pe) with { Imports = Names("VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx") }));
        Assert.Equal(0, Score(Input(pe) with { Imports = Names("VirtualAllocEx", "WriteProcessMemory") })); // нет создания потока
        Assert.Equal(45, Score(Input(pe) with { Imports = Names("MiniDumpWriteDump"), Markers = Names("lsass") }));
        Assert.Equal(40, Score(Input(pe) with { Imports = Names("VirtualProtect"), Markers = Names("AmsiScanBuffer") }));
        Assert.Equal(25, Score(Input(pe) with { Imports = Names("SetWindowsHookExW", "GetAsyncKeyState") }));
    }

    [Fact]
    public void PackerSectionName_OrWritableExecutable_AddsTwenty()
    {
        var withName = ThreatScoringEngine.Evaluate(Input(Pe(sectionName: ".themida")) with { SignatureValid = true });
        var wx = ThreatScoringEngine.Evaluate(Input(Pe(wx: true)) with { SignatureValid = true });
        Assert.Equal(20, withName.Value);
        Assert.Equal(20, wx.Value);
    }

    [Fact]
    public void ImportReader_FindsFunctionNames_InSyntheticPe()
    {
        var bytes = SyntheticArtifacts.BuildPe(new() { ImportedFunctions = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] });
        using var ms = new MemoryStream(bytes);
        var info = PeParser.Parse(ms).Info!;
        var names = PeImportReader.ReadFunctionNames(ms, info);
        Assert.Contains("VirtualAllocEx", names);
        Assert.Contains("CreateRemoteThread", names);
        Assert.Equal(3, names.Count);
    }

    [Fact]
    public void Analyzer_DetectsInjectionImports_InUnsignedNativePe()
    {
        using var tmp = new TempDir();
        var bytes = SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, WritableText = true, TextSize = 0x4000,
            ImportedFunctions = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] });
        var analyzer = new FileAnalyzer(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), new Sentinel.Core.Trust.UnavailableSignatureVerifier());
        var r = analyzer.Analyze(tmp.Write("inj.exe", bytes), null, new ScoreContext(PersistenceBound: true));
        Assert.True(r.Score!.Value >= 85, r.Score.Describe());
        Assert.Equal(Verdict.Malicious, r.Verdict);
    }

    [Fact]
    public void ManagedImportTable_IsParsedFromManagedPe_Marker()
    {
        var bytes = SyntheticArtifacts.BuildPe(new() { Managed = true });
        using var ms = new MemoryStream(bytes);
        Assert.True(PeParser.Parse(ms).Info!.IsManaged);
    }
}

/// <summary>1.3.8: импорт EtwEventWrite — обычная трассировка (rtscom.dll на копии Windows с отчёта Katana), а не патчинг ETW.</summary>
public class EtwImportIsNotPatchingTests
{
    private static HashSet<string> Names(params string[] n) => new HashSet<string>(n, StringComparer.OrdinalIgnoreCase);

    private static ScoringInput Dll(IReadOnlySet<string> imports, IReadOnlySet<string> markers) => new()
    {
        Path = @"H:\Program Files\Common Files\microsoft shared\ink\rtscom.dll",
        Pe = ThreatScoringTests.Pe(dll: true),
        Imports = imports,
        Markers = markers,
    };

    [Fact]
    public void ImportedEtwEventWrite_WithVirtualProtect_IsNotAmsiEtwPatching()
    {
        var score = ThreatScoringEngine.Evaluate(Dll(Names("EtwEventWrite", "VirtualProtect", "GetProcAddress"), Names("EtwEventWrite")));
        Assert.DoesNotContain(score.Factors, f => f.Code == "API-AMSI-ETW");
    }

    [Fact]
    public void DynamicallyResolvedEtwEventWrite_WithVirtualProtect_IsPatching()
    {
        var score = ThreatScoringEngine.Evaluate(Dll(Names("VirtualProtect", "GetProcAddress"), Names("EtwEventWrite")));
        Assert.Contains(score.Factors, f => f.Code == "API-AMSI-ETW");
    }
}
