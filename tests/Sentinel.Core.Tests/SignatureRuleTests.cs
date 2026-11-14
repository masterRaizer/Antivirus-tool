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
