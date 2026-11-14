using System.Globalization;

namespace Sentinel.Core.Signatures;

/// <summary>
/// Парсер текстовых правил в подмножестве синтаксиса YARA:
/// <code>
/// rule Name : tag1 tag2 {
///   meta:
///     id = "SNT-0001"  severity = "high"  category = "miner"  description = "..."  sha256 = "..."
///   strings:
///     $a = "stratum+tcp://" nocase wide ascii
///     $b = { 4D 5A ?? 00 }
///   condition:
///     uint16(0) == 0x5A4D and any of them
/// }
/// </code>
/// Неподдерживаемые конструкции (import, regex, jumps, модули) приводят к явной ошибке,
/// а не молча пропускаются.
/// </summary>
public static class YaraLikeRuleParser
{
    private static readonly char[] HashSeparators = [',', ';', ' '];

    public static IReadOnlyList<SignatureRule> Parse(string text, string sourceFile)
    {
        ArgumentNullException.ThrowIfNull(text);
        var lexer = new RuleLexer(text);
        var rules = new List<SignatureRule>();
        while (lexer.Peek().Kind != TokenKind.Eof)
        {
            rules.Add(ParseRule(lexer, sourceFile));
        }

        return rules;
    }

    private static SignatureRule ParseRule(RuleLexer lexer, string sourceFile)
    {
        var head = lexer.Next();
        if (head is { Kind: TokenKind.Identifier, Text: "import" or "include" })
        {
            throw new RuleFormatException($"Директива '{head.Text}' не поддерживается.", head.Line);
        }

        while (head is { Kind: TokenKind.Identifier, Text: "private" or "global" })
        {
            head = lexer.Next();
        }

        if (head is not { Kind: TokenKind.Identifier, Text: "rule" })
        {
            throw new RuleFormatException($"Ожидалось 'rule', получено '{RuleLexer.Describe(head)}'.", head.Line);
        }

        var nameToken = lexer.Expect(TokenKind.Identifier, "имя правила");
        var ruleLine = nameToken.Line;
        var tags = new List<string>();
        if (lexer.TryConsume(TokenKind.Colon))
        {
            while (lexer.Peek().Kind == TokenKind.Identifier)
            {
                tags.Add(lexer.Next().Text);
            }
        }

        lexer.Expect(TokenKind.LBrace, "'{'");

        string? id = null;
        var description = string.Empty;
        var severity = Severity.Medium;
        var category = "generic";
        var sha = new HashSet<string>(StringComparer.Ordinal);
        var patterns = new List<BytePattern>();
        var patternIds = new HashSet<string>(StringComparer.Ordinal);
        Condition? condition = null;

        while (true)
        {
            var section = lexer.Next();
            if (section.Kind == TokenKind.RBrace)
            {
                break;
            }

            if (section.Kind != TokenKind.Identifier)
            {
                throw new RuleFormatException($"Ожидался раздел meta/strings/condition, получено '{RuleLexer.Describe(section)}'.", section.Line);
            }

            lexer.Expect(TokenKind.Colon, "':'");
            switch (section.Text)
            {
                case "meta":
                    while (lexer.Peek() is { Kind: TokenKind.Identifier } key && !IsSectionName(key.Text))
                    {
                        lexer.Next();
                        lexer.Expect(TokenKind.Assign, "'='");
                        var value = lexer.Next();
                        var str = value.Kind switch
                        {
                            TokenKind.String => value.Text,
                            TokenKind.Integer => value.Number.ToString(CultureInfo.InvariantCulture),
                            TokenKind.Identifier when value.Text is "true" or "false" => value.Text,
                            _ => throw new RuleFormatException($"Некорректное значение meta '{key.Text}'.", value.Line),
                        };

                        switch (key.Text.ToLowerInvariant())
                        {
                            case "id": id = str; break;
                            case "description": description = str; break;
                            case "severity": severity = RuleFactory.ParseSeverity(str, value.Line); break;
                            case "category": category = str; break;
                            case "sha256":
                                foreach (var h in str.Split(HashSeparators, StringSplitOptions.RemoveEmptyEntries))
                                {
                                    sha.Add(RuleFactory.NormalizeSha256(h, value.Line));
                                }

                                break;
                        }
                    }

                    break;

                case "strings":
                    while (lexer.Peek().Kind == TokenKind.Variable)
                    {
                        var v = lexer.Next();
                        if (v.Text == "$" || v.Text.EndsWith('*'))
                        {
                            throw new RuleFormatException($"Недопустимый идентификатор строки '{v.Text}'.", v.Line);
                        }

                        if (!patternIds.Add(v.Text))
                        {
                            throw new RuleFormatException($"Повторное определение строки {v.Text}.", v.Line);
                        }

                        lexer.Expect(TokenKind.Assign, "'='");
                        patterns.AddRange(ParsePatternValue(lexer, v.Text));
                    }

                    break;

                case "condition":
                    condition = ConditionParser.ParseExpression(lexer);
                    break;

                default:
                    throw new RuleFormatException($"Неизвестный раздел '{section.Text}'.", section.Line);
            }
        }

        if (condition is null)
        {
            throw new RuleFormatException($"Правило {nameToken.Text}: отсутствует раздел condition.", ruleLine);
        }

        return RuleFactory.Build(id ?? nameToken.Text, nameToken.Text, description, severity, category, tags,
            patterns, sha, condition, sourceFile, ruleLine);
    }

    // Ключи meta и модификаторы строк не могут называться как разделы правила.
    private static bool IsSectionName(string text) => text is "meta" or "strings" or "condition";

    private static IEnumerable<BytePattern> ParsePatternValue(RuleLexer lexer, string id)
    {
        var c = lexer.PeekChar();
        if (c == '{')
        {
            var body = lexer.ReadHexBody();
            return [PatternBuilder.FromHex(id, body)];
        }

        if (c == '/')
        {
            throw new RuleFormatException($"Регулярные выражения ({id}) не поддерживаются.", lexer.Line);
        }

        var str = lexer.Expect(TokenKind.String, "строка или hex-строка");
        bool noCase = false, ascii = false, wide = false;
        while (lexer.Peek() is { Kind: TokenKind.Identifier } mod && !IsSectionName(mod.Text))
        {
            switch (mod.Text)
            {
                case "nocase": noCase = true; break;
                case "ascii": ascii = true; break;
                case "wide": wide = true; break;
                default:
                    throw new RuleFormatException($"Модификатор '{mod.Text}' не поддерживается.", mod.Line);
            }

            lexer.Next();
        }

        return PatternBuilder.FromText(id, str.Bytes!, str.Text, noCase, ascii, wide);
    }
}
