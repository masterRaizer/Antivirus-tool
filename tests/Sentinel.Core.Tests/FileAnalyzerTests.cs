using Sentinel.Core.Detection;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class FileAnalyzerTests
{
    private static FileAnalyzer Create(ISignatureVerifier? verifier = null, IWhitelistProvider? whitelist = null, long maxScan = 64L * 1024 * 1024) =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)),
            verifier ?? new UnavailableSignatureVerifier(), whitelist, new FileAnalyzerOptions { MaxScanBytes = maxScan });

    [Fact]
    public void Eicar_IsMalicious_WithSingleBuiltinDetection()
    {
        using var tmp = new TempDir();
        var r = Create().Analyze(tmp.Write("eicar.com", Eicar.CreateTestFileBytes()));

        Assert.Equal(Verdict.Malicious, r.Verdict);
        var d = Assert.Single(r.Detections);
        Assert.Equal(Eicar.DetectionName, d.Name);
        Assert.Equal(DetectionSource.Builtin, d.Source);
        Assert.Equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", r.Sha256);
    }

    [Fact]
    public void CleanText_IsClean()
    {
        using var tmp = new TempDir();
        var r = Create().Analyze(tmp.WriteText("readme.txt", "just text"));
        Assert.Equal(Verdict.Clean, r.Verdict);
        Assert.False(r.Pe!.IsPe);
        Assert.Null(r.Signature);
    }

    [Fact]
    public void PackedUnsignedPe_IsSuspicious_LowEntropyPeIsClean()
    {
        using var tmp = new TempDir();
        var analyzer = Create();
        var packed = analyzer.Analyze(tmp.Write("packed.exe", SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x4000 })));
        var plain = analyzer.Analyze(tmp.Write("plain.exe", SyntheticArtifacts.BuildPe()));

        Assert.Equal(Verdict.Suspicious, packed.Verdict);
        Assert.Contains(packed.Detections, d => d.Name == "Heuristic.PackedUnsignedPE");
        Assert.Equal(Verdict.Clean, plain.Verdict);
        Assert.Equal(SignatureStatus.Unsupported, plain.Signature!.Status);
    }

    [Fact]
    public void PackedPe_WithValidSignature_IsNotFlaggedByHeuristic()
    {
        using var tmp = new TempDir();
        var r = Create(FakeVerifier.Valid("CN=Vendor")).Analyze(
            tmp.Write("packed.exe", SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x4000 })));
        Assert.Equal(Verdict.Clean, r.Verdict);
    }

    [Fact]
    public void MinerConfig_MatchesRepositoryRule()
    {
        using var tmp = new TempDir();
        var r = Create().Analyze(tmp.Write("config.json", SyntheticArtifacts.MinerConfigSample()));
        Assert.Equal(Verdict.Malicious, r.Verdict);
        Assert.Contains(r.Detections, d => d.RuleId == "SNT-MINER-0001" && d.Hits.Count >= 2);
    }

    [Fact]
    public void WideStringStealerIndicators_InPe_MatchRule()
    {
        using var tmp = new TempDir();
        var strings = string.Join("\0", "\\Login Data", "Local State", "\"encrypted_key\"", "Google\\Chrome\\User Data", "Microsoft\\Edge\\User Data");
        var pe = SyntheticArtifacts.BuildPe(new() { DataContent = System.Text.Encoding.Unicode.GetBytes(strings) });
        var r = Create().Analyze(tmp.Write("s.exe", pe));
        Assert.Contains(r.Detections, d => d.RuleId == "SNT-STEALER-0001");
    }

    [Fact]
    public void WhitelistedFile_IsTrusted()
    {
        using var tmp = new TempDir();
        var prot = Path.Combine(tmp.Path, "sys");
        var file = tmp.Write("sys/a.exe", SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x4000 }));
        var verifier = FakeVerifier.Valid("CN=Microsoft Windows, O=Microsoft Corporation");
        var whitelist = new SystemWhitelist(verifier, new WhitelistOptions { ProtectedDirectories = [prot] });

        Assert.Equal(Verdict.Trusted, Create(verifier, whitelist).Analyze(file).Verdict);
    }

    [Fact]
    public void LargeFile_IsTruncatedForPatterns_ButHashCoversWholeFile()
    {
        using var tmp = new TempDir();
        var data = new byte[300_000];
        new Random(1).NextBytes(data);
        var path = tmp.Write("big.bin", data);

        var r = Create(maxScan: 100_000).Analyze(path);
        Assert.True(r.Truncated);
        Assert.Equal(300_000, r.Size);
        Assert.Equal(Hashing.FileHasher.ComputeSha256(data), r.Sha256);
    }

    [Fact]
    public void MissingFile_ReturnsErrorVerdict()
    {
        var r = Create().Analyze(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        Assert.Equal(Verdict.Error, r.Verdict);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public void AnalyzerDoesNotModifyFile()
    {
        using var tmp = new TempDir();
        var bytes = Eicar.CreateTestFileBytes();
        var path = tmp.Write("eicar.com", bytes);
        var before = File.GetLastWriteTimeUtc(path);
        _ = Create().Analyze(path);
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.Equal(before, File.GetLastWriteTimeUtc(path));
    }
}
