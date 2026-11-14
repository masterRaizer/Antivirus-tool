namespace Sentinel.Core.Signatures;

/// <summary>
/// Рекурсивный спуск для условий:
/// <code>
/// expr    := and ('or' and)*
/// and     := unary ('and' unary)*
/// unary   := 'not' unary | primary
/// primary := '(' expr ')' | 'true' | 'false'
///          | $id [ 'at' INT | 'in' '(' INT '..' INT ')' ]
///          | #id CMP INT
///          | ('any' | 'all' | INT) 'of' ('them' | '(' $sel (',' $sel)* ')')
///          | 'filesize' CMP INT
///          | ('uint8'|'uint16'|'uint32'|'uint16be'|'uint32be') '(' INT ')' CMP INT
/// </code>
/// </summary>
internal static class ConditionParser
{
    public static Condition Parse(string text)
    {
        var lexer = new RuleLexer(text);
        var result = ParseExpression(lexer);
        var rest = lexer.Peek();
        if (rest.Kind != TokenKind.Eof)
        {
            throw new RuleFormatException($"Лишний текст в условии: '{RuleLexer.Describe(rest)}'.", rest.Line);
        }

        return result;
    }

    /// <summary>Разбирает выражение до первого токена, который не может его продолжить.</summary>
    public static Condition ParseExpression(RuleLexer lexer)
    {
        var left = ParseAnd(lexer);
        while (lexer.PeekIdentifier("or"))
        {
            lexer.Next();
            left = new OrCondition(left, ParseAnd(lexer));
        }

        return left;
    }

    private static Condition ParseAnd(RuleLexer lexer)
    {
        var left = ParseUnary(lexer);
        while (lexer.PeekIdentifier("and"))
        {
            lexer.Next();
            left = new AndCondition(left, ParseUnary(lexer));
        }

        return left;
    }

    private static Condition ParseUnary(RuleLexer lexer)
    {
        if (lexer.PeekIdentifier("not"))
        {
            lexer.Next();
            return new NotCondition(ParseUnary(lexer));
        }

        return ParsePrimary(lexer);
    }

    private static Condition ParsePrimary(RuleLexer lexer)
    {
        var t = lexer.Next();
        switch (t.Kind)
        {
            case TokenKind.LParen:
                var inner = ParseExpression(lexer);
                lexer.Expect(TokenKind.RParen, "')'");
                return inner;

            case TokenKind.Variable:
                if (t.Text == "$" || t.Text.EndsWith('*'))
                {
                    throw new RuleFormatException($"'{t.Text}' допустим только внутри 'of (...)'.", t.Line);
                }

                if (lexer.PeekIdentifier("at"))
                {
                    lexer.Next();
                    var at = lexer.Expect(TokenKind.Integer, "смещение после 'at'");
                    return new PatternAtCondition(t.Text, checked((long)at.Number));
                }

                if (lexer.PeekIdentifier("in"))
                {
                    lexer.Next();
                    lexer.Expect(TokenKind.LParen, "'('");
                    var from = lexer.Expect(TokenKind.Integer, "начало диапазона");
                    lexer.Expect(TokenKind.Range, "'..'");
                    var to = lexer.Expect(TokenKind.Integer, "конец диапазона");
                    lexer.Expect(TokenKind.RParen, "')'");
                    if (to.Number < from.Number)
                    {
                        throw new RuleFormatException("Конец диапазона меньше начала.", to.Line);
                    }

                    return new PatternInCondition(t.Text, checked((long)from.Number), checked((long)to.Number));
                }

                return new PatternCondition(t.Text);

            case TokenKind.Count:
                var op = ParseCompare(lexer);
                var count = lexer.Expect(TokenKind.Integer, "число");
                return new PatternCountCondition("$" + t.Text[1..], op, count.Number);

            case TokenKind.Integer:
                return ParseOf(lexer, checked((int)t.Number), t.Line);

            case TokenKind.Identifier:
                return ParseKeyword(lexer, t);

            default:
                throw new RuleFormatException($"Неожиданный токен в условии: '{RuleLexer.Describe(t)}'.", t.Line);
        }
    }

    private static Condition ParseKeyword(RuleLexer lexer, Token t)
    {
        switch (t.Text)
        {
            case "true":
                return new BoolCondition(true);
            case "false":
                return new BoolCondition(false);
            case "any":
                return ParseOf(lexer, 1, t.Line);
            case "all":
                return ParseOf(lexer, null, t.Line);
            case "filesize":
                var op = ParseCompare(lexer);
                return new FileSizeCondition(op, lexer.Expect(TokenKind.Integer, "размер").Number);
            case "uint8":
            case "uint16":
            case "uint32":
            case "uint16be":
            case "uint32be":
                var size = t.Text switch { "uint8" => 1, "uint16" or "uint16be" => 2, _ => 4 };
                var bigEndian = t.Text.EndsWith("be", StringComparison.Ordinal);
                lexer.Expect(TokenKind.LParen, "'('");
                var offset = lexer.Expect(TokenKind.Integer, "смещение");
                lexer.Expect(TokenKind.RParen, "')'");
                var cmp = ParseCompare(lexer);
                var value = lexer.Expect(TokenKind.Integer, "значение");
                return new IntReadCondition(size, bigEndian, checked((long)offset.Number), cmp, value.Number);
            default:
                throw new RuleFormatException($"Неподдерживаемое ключевое слово или модуль в условии: '{t.Text}'.", t.Line);
        }
    }

    private static OfCondition ParseOf(RuleLexer lexer, int? required, int line)
    {
        if (!lexer.PeekIdentifier("of"))
        {
            throw new RuleFormatException("Ожидалось 'of'.", line);
        }

        lexer.Next();
        if (required is < 1)
        {
            throw new RuleFormatException("Количество в 'N of' должно быть не меньше 1.", line);
        }

        if (lexer.PeekIdentifier("them"))
        {
            lexer.Next();
            return new OfCondition(required, null);
        }

        lexer.Expect(TokenKind.LParen, "'them' или '('");
        var selectors = new List<string>();
        do
        {
            var v = lexer.Expect(TokenKind.Variable, "идентификатор строки");
            if (v.Text == "$")
            {
                throw new RuleFormatException("Анонимные строки не поддерживаются.", v.Line);
            }

            selectors.Add(v.Text);
        }
        while (lexer.TryConsume(TokenKind.Comma));

        lexer.Expect(TokenKind.RParen, "')'");
        return new OfCondition(required, selectors);
    }

    private static CompareOp ParseCompare(RuleLexer lexer)
    {
        var t = lexer.Next();
        return t.Kind switch
        {
            TokenKind.Eq => CompareOp.Eq,
            TokenKind.Ne => CompareOp.Ne,
            TokenKind.Lt => CompareOp.Lt,
            TokenKind.Le => CompareOp.Le,
            TokenKind.Gt => CompareOp.Gt,
            TokenKind.Ge => CompareOp.Ge,
            _ => throw new RuleFormatException($"Ожидался оператор сравнения, получено '{RuleLexer.Describe(t)}'.", t.Line),
        };
    }
}
