using System.Security.Cryptography;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.ThreatIntel;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>1.3.9: базы MD5/SHA-1 (VirusShare, ESET), выгрузка MalwareBazaar, потоковое слияние без загрузки базы в память.</summary>
public class ThreatDbV139Tests
{
    private static string Hex(int seed, int bytes)
    {
        var data = new byte[bytes];
        new Random(seed).NextBytes(data);
        return Convert.ToHexString(data).ToLowerInvariant();
    }

    [Fact]
    public void Md5AndSha1Databases_BuildOpenAndLookup()
    {
        using var tmp = new TempDir();
        var md5 = Hex(1, 16);
        var sha1 = Hex(2, 20);
        var sha256 = Hex(3, 32);
        ThreatHashEntry[] entries = [new(md5, "VirusShare"), new(sha1, "ESET.Gamaredon"), new(sha256, "MalwareBazaar.AgentTesla")];

        var md5Path = Path.Combine(tmp.Path, ThreatHashKinds.FileName(ThreatHashKind.Md5));
        Assert.Equal(1, ThreatHashDatabaseBuilder.BuildToFile(entries, DateTimeOffset.UnixEpoch, md5Path, ThreatHashKind.Md5));
        using var db = ThreatHashDatabase.Open(md5Path);
        Assert.Equal(ThreatHashKind.Md5, db.Kind);
        Assert.True(db.TryGetFamily(md5.ToUpperInvariant(), out var family));
        Assert.Equal("VirusShare", family);
        Assert.False(db.TryGetFamily(sha256, out _));
    }

    [Fact]
    public void Merge_EqualsFullRebuild_AndKeepsFamilyIds()
    {
        using var tmp = new TempDir();
        var existing = Enumerable.Range(0, 500).Select(i => new ThreatHashEntry(Hex(i, 32), $"Old.F{i % 7}")).ToArray();
        var fresh = Enumerable.Range(400, 300).Select(i => new ThreatHashEntry(Hex(i, 32), $"New.F{i % 5}")).ToArray();
        var basePath = Path.Combine(tmp.Path, "base.bin");
        ThreatHashDatabaseBuilder.BuildToFile(existing, DateTimeOffset.UnixEpoch, basePath);

        var mergedPath = Path.Combine(tmp.Path, "merged.bin");
        using (var baseDb = ThreatHashDatabase.Open(basePath))
        {
            Assert.Equal(700, ThreatHashDatabaseBuilder.MergeToFile(baseDb, fresh, DateTimeOffset.UnixEpoch.AddDays(1), mergedPath));
        }

        using var merged = ThreatHashDatabase.Open(mergedPath);
        Assert.Equal(700, merged.Count);
        var all = merged.Enumerate().ToList();
        Assert.Equal(all.Select(e => e.Sha256).Order(StringComparer.Ordinal), all.Select(e => e.Sha256)); // порядок для бинарного поиска
        Assert.True(merged.TryGetFamily(Hex(450, 32), out var overlap));
        Assert.StartsWith("Old.", overlap, StringComparison.Ordinal); // совпавший хеш сохраняет прежнее семейство
        Assert.True(merged.TryGetFamily(Hex(650, 32), out var added));
        Assert.StartsWith("New.", added, StringComparison.Ordinal);
        Assert.True(merged.TryGetFamily(Hex(3, 32), out _));
    }

    [Fact]
    public void Engine_Merge_RoutesByKind_AndAnalyzerFindsFileByMd5()
    {
        using var tmp = new TempDir();
        var sample = tmp.WriteText(Path.Combine("files", "old-virus.bin"), "synthetic sample known only by its MD5");
#pragma warning disable CA5351 // MD5 здесь — идентификатор образца в базе VirusShare, а не криптографическая защита
        var md5 = Convert.ToHexString(MD5.HashData(File.ReadAllBytes(sample))).ToLowerInvariant();
#pragma warning restore CA5351
        var data = Path.Combine(tmp.Path, "data");
        using var engine = new ThreatIntelligenceEngine(data);
        Assert.False(engine.HasLegacyHashes);

        var added = engine.Merge([new(md5, "VirusShare"), new(Hex(9, 32), "X")], DateTimeOffset.UtcNow, ThreatHashKind.Md5);
        Assert.Equal(1, added);
        Assert.True(engine.HasLegacyHashes);
        Assert.Equal(1, engine.CountOf(ThreatHashKind.Md5));
        Assert.Equal(0, engine.Count);

        var analyzer = new FileAnalyzer(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), new UnavailableSignatureVerifier(),
            threatIntel: engine);
        var result = analyzer.Analyze(sample);
        var detection = Assert.Single(result.Detections, d => d.Source == DetectionSource.ThreatIntel);
        Assert.Equal("ThreatDB.VirusShare", detection.Name);
        Assert.Contains("MD5", detection.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void MalwareBazaarCsv_IsParsedWithQuotedCommas_AndFamilies()
    {
        var sha = Hex(5, 32);
        var sha2 = Hex(6, 32);
        var csv = $"""
            ################################################################
            # MalwareBazaar full data dump (CSV)
            "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
            "2026-11-01 10:00:00", "{sha}", "{Hex(7, 16)}", "{Hex(8, 20)}", "abuse_ch", "invoice, final.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "61.0", "x", "y", "z"
            "2026-11-01 10:01:00", "{sha2}", "{Hex(9, 16)}", "{Hex(10, 20)}", "abuse_ch", "doc.xlsm", "xlsm", "application/vnd.ms-excel", "n/a", "n/a", "n/a", "x", "y", "z"
            """;
        var entries = ThreatFeedParsers.ParseMalwareBazaarCsv(new StringReader(csv)).ToList();

        Assert.Equal(2, entries.Count);
        Assert.Equal(new ThreatHashEntry(sha, "MalwareBazaar.AgentTesla"), entries[0]);
        Assert.Equal(new ThreatHashEntry(sha2, "MalwareBazaar.xlsm"), entries[1]);
    }

    [Fact]
    public void VirusShareAndAllKindsParsers_TakeOnlyWholeHashes()
    {
        var md5 = Hex(11, 16);
        var list = $"# VirusShare_00499.md5\n{md5}\n{ThreatFeedParsers.EmptyFileMd5}\nnot-a-hash\n";
        Assert.Equal([new ThreatHashEntry(md5, "VirusShare")], ThreatFeedParsers.ParseVirusShareList(new StringReader(list)).ToList());

        var sha256 = Hex(12, 32);
        var sha1 = Hex(13, 20);
        var all = ThreatFeedParsers.ParseHashListAllKinds($"{sha256}\n{sha1};x\nmd5: {md5}", "ESET.Test").ToList();
        Assert.Equal(3, all.Count); // 32-символьные куски внутри SHA-256 не считаются отдельными MD5
        Assert.Equal([ThreatHashKind.Sha256, ThreatHashKind.Sha1, ThreatHashKind.Md5], all.Select(e => ThreatHashKinds.Of(e.Sha256)!.Value));
    }

    [Fact]
    public void LegacyV1Sha256File_StillOpens()
    {
        var bundled = Path.Combine(Path.GetDirectoryName(RepoPaths.RulesDirectory)!, "data", "threat_hashes.bin");
        using var db = ThreatHashDatabase.Open(bundled);
        Assert.Equal(ThreatHashKind.Sha256, db.Kind);
        Assert.True(db.Count > 1000);
        Assert.True(db.TryGetFamily(ThreatFeedParsers.EicarSha256, out _));
    }
}
