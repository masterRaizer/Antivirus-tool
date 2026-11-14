using System.Globalization;
using System.Text;

namespace Sentinel.Core.Signatures;

internal enum TokenKind
{
    Eof,
    Identifier,
    Variable,   // $a, $a*, $
    Count,      // #a
    String,
    Integer,
    LBrace,
    RBrace,
    LParen,
    RParen,
    Colon,
    Assign,
    Comma,
    Range,      // ..
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

internal readonly record struct Token(TokenKind Kind, string Text, int Line, ulong Number = 0, byte[]? Bytes = null);

/// <summary>Лексер YARA-подобного синтаксиса. Поддерживает комментарии // и /* */.</summary>
internal sealed class RuleLexer
{
    private readonly string _src;
    private int _pos;
    private Token? _peeked;

    public RuleLexer(string source)
    {
        _src = source;
        Line = 1;
    }

    public int Line { get; private set; }

    public Token Peek() => _peeked ??= Read();

    public Token Next()
    {
        if (_peeked is { } t)
        {
            _peeked = null;
            return t;
        }

        return Read();
    }

    public Token Expect(TokenKind kind, string what)
    {
        var t = Next();
        if (t.Kind != kind)
        {
            throw new RuleFormatException($"Ожидалось {what}, получено '{Describe(t)}'.", t.Line);
        }

        return t;
    }

    public bool TryConsume(TokenKind kind)
    {
        if (Peek().Kind == kind)
        {
            Next();
            return true;
        }

        return false;
    }

    public bool PeekIdentifier(string word) =>
        Peek() is { Kind: TokenKind.Identifier } t && string.Equals(t.Text, word, StringComparison.Ordinal);

    /// <summary>Читает сырое содержимое hex-строки после открывающей '{' (не включая '}').</summary>
    public string ReadHexBody()
    {
        if (_peeked is not null)
        {
            throw new InvalidOperationException("ReadHexBody нельзя вызывать после Peek.");
        }

        SkipTrivia();
        if (_pos >= _src.Length || _src[_pos] != '{')
        {
            throw new RuleFormatException("Ожидалась '{' в начале hex-строки.", Line);
        }

        _pos++;
        var start = _pos;
        while (_pos < _src.Length && _src[_pos] != '}')
        {
            if (_src[_pos] == '\n')
            {
                Line++;
            }

            _pos++;
        }

        if (_pos >= _src.Length)
        {
            throw new RuleFormatException("Незакрытая hex-строка.", Line);
        }

        var body = _src[start.._pos];
        _pos++;
        return body;
    }

    /// <summary>Следующий значимый символ (без чтения токена).</summary>
    public char PeekChar()
    {
        if (_peeked is not null)
        {
            throw new InvalidOperationException("PeekChar нельзя вызывать после Peek.");
        }

        SkipTrivia();
        return _pos < _src.Length ? _src[_pos] : '\0';
    }

    internal static string Describe(Token t) => t.Kind == TokenKind.Eof ? "конец текста" : t.Text;

    private Token Read()
    {
        SkipTrivia();
        if (_pos >= _src.Length)
        {
            return new Token(TokenKind.Eof, string.Empty, Line);
        }

        var line = Line;
        var c = _src[_pos];
        switch (c)
        {
            case '{': _pos++; return new Token(TokenKind.LBrace, "{", line);
            case '}': _pos++; return new Token(TokenKind.RBrace, "}", line);
            case '(': _pos++; return new Token(TokenKind.LParen, "(", line);
            case ')': _pos++; return new Token(TokenKind.RParen, ")", line);
            case ':': _pos++; return new Token(TokenKind.Colon, ":", line);
            case ',': _pos++; return new Token(TokenKind.Comma, ",", line);
            case '"': return ReadString(line);
            case '$':
            case '#':
                return ReadVariable(c, line);
            case '.' when At(1) == '.': _pos += 2; return new Token(TokenKind.Range, "..", line);
            case '=' when At(1) == '=': _pos += 2; return new Token(TokenKind.Eq, "==", line);
            case '=': _pos++; return new Token(TokenKind.Assign, "=", line);
            case '!' when At(1) == '=': _pos += 2; return new Token(TokenKind.Ne, "!=", line);
            case '<' when At(1) == '=': _pos += 2; return new Token(TokenKind.Le, "<=", line);
            case '<': _pos++; return new Token(TokenKind.Lt, "<", line);
            case '>' when At(1) == '=': _pos += 2; return new Token(TokenKind.Ge, ">=", line);
            case '>': _pos++; return new Token(TokenKind.Gt, ">", line);
        }

        if (char.IsAsciiDigit(c))
        {
            return ReadNumber(line);
        }

        if (char.IsAsciiLetter(c) || c == '_')
        {
            var start = _pos;
            while (_pos < _src.Length && (char.IsAsciiLetterOrDigit(_src[_pos]) || _src[_pos] == '_' || _src[_pos] == '.'))
            {
                _pos++;
            }

            return new Token(TokenKind.Identifier, _src[start.._pos], line);
        }

        throw new RuleFormatException($"Неожиданный символ '{c}'.", line);
    }

    private char At(int offset) => _pos + offset < _src.Length ? _src[_pos + offset] : '\0';

    private void SkipTrivia()
    {
        while (_pos < _src.Length)
        {
            var c = _src[_pos];
            if (c == '\n')
            {
                Line++;
                _pos++;
            }
            else if (char.IsWhiteSpace(c))
            {
                _pos++;
            }
            else if (c == '/' && At(1) == '/')
            {
                while (_pos < _src.Length && _src[_pos] != '\n')
                {
                    _pos++;
                }
            }
            else if (c == '/' && At(1) == '*')
            {
                var startLine = Line;
                _pos += 2;
                while (_pos < _src.Length && !(_src[_pos] == '*' && At(1) == '/'))
                {
                    if (_src[_pos] == '\n')
                    {
                        Line++;
                    }

                    _pos++;
                }

                if (_pos >= _src.Length)
                {
                    throw new RuleFormatException("Незакрытый комментарий /* */.", startLine);
                }

                _pos += 2;
            }
            else
            {
                break;
            }
        }
    }

    private Token ReadVariable(char sigil, int line)
    {
        var start = _pos;
        _pos++;
        while (_pos < _src.Length && (char.IsAsciiLetterOrDigit(_src[_pos]) || _src[_pos] == '_'))
        {
            _pos++;
        }

        if (sigil == '$' && _pos < _src.Length && _src[_pos] == '*')
        {
            _pos++;
        }

        var text = _src[start.._pos];
        if (sigil == '#' && text.Length == 1)
        {
            throw new RuleFormatException("Ожидалось имя строки после '#'.", line);
        }

        return new Token(sigil == '$' ? TokenKind.Variable : TokenKind.Count, text, line);
    }

    private Token ReadNumber(int line)
    {
        var start = _pos;
        ulong value;
        if (_src[_pos] == '0' && (At(1) == 'x' || At(1) == 'X'))
        {
            _pos += 2;
            var hexStart = _pos;
            while (_pos < _src.Length && char.IsAsciiHexDigit(_src[_pos]))
            {
                _pos++;
            }

            if (!ulong.TryParse(_src.AsSpan(hexStart, _pos - hexStart), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value))
            {
                throw new RuleFormatException("Некорректное шестнадцатеричное число.", line);
            }
        }
        else
        {
            while (_pos < _src.Length && char.IsAsciiDigit(_src[_pos]))
            {
                _pos++;
            }

            if (!ulong.TryParse(_src.AsSpan(start, _pos - start), NumberStyles.None, CultureInfo.InvariantCulture, out value))
            {
                throw new RuleFormatException("Слишком большое число.", line);
            }

            if (At(0) is 'K' or 'M' or 'G' && At(1) == 'B')
            {
                var mul = At(0) switch { 'K' => 1024UL, 'M' => 1024UL * 1024, _ => 1024UL * 1024 * 1024 };
                value = checked(value * mul);
                _pos += 2;
            }
        }

        if (_pos < _src.Length && (char.IsAsciiLetterOrDigit(_src[_pos]) || _src[_pos] == '_'))
        {
            throw new RuleFormatException($"Некорректный числовой литерал '{_src[start..(_pos + 1)]}'.", line);
        }

        return new Token(TokenKind.Integer, _src[start.._pos], line, value);
    }

    private Token ReadString(int line)
    {
        _pos++; // открывающая кавычка
        var bytes = new List<byte>();
        var text = new StringBuilder();
        Span<byte> utf8 = stackalloc byte[4];
        while (true)
        {
            if (_pos >= _src.Length || _src[_pos] == '\n')
            {
                throw new RuleFormatException("Незакрытая строка.", line);
            }

            var c = _src[_pos++];
            if (c == '"')
            {
                break;
            }

            if (c == '\\')
            {
                if (_pos >= _src.Length)
                {
                    throw new RuleFormatException("Незавершённая escape-последовательность.", line);
                }

                var e = _src[_pos++];
                switch (e)
                {
                    case '"': bytes.Add((byte)'"'); text.Append('"'); break;
                    case '\\': bytes.Add((byte)'\\'); text.Append('\\'); break;
                    case 'n': bytes.Add((byte)'\n'); text.Append('\n'); break;
                    case 'r': bytes.Add((byte)'\r'); text.Append('\r'); break;
                    case 't': bytes.Add((byte)'\t'); text.Append('\t'); break;
                    case '0': bytes.Add(0); text.Append('\0'); break;
                    case 'x':
                        if (_pos + 2 > _src.Length ||
                            !byte.TryParse(_src.AsSpan(_pos, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var hb))
                        {
                            throw new RuleFormatException("Некорректная последовательность \\xHH.", line);
                        }

                        _pos += 2;
                        bytes.Add(hb);
                        text.Append((char)hb);
                        break;
                    default:
                        throw new RuleFormatException($"Неизвестная escape-последовательность '\\{e}'.", line);
                }

                continue;
            }

            if (char.IsHighSurrogate(c) && _pos < _src.Length && char.IsLowSurrogate(_src[_pos]))
            {
                var n = Encoding.UTF8.GetBytes([c, _src[_pos++]], utf8);
                bytes.AddRange(utf8[..n].ToArray());
                text.Append(c).Append(_src[_pos - 1]);
                continue;
            }

            var count = Encoding.UTF8.GetBytes([c], utf8);
            bytes.AddRange(utf8[..count].ToArray());
            text.Append(c);
        }

        return new Token(TokenKind.String, text.ToString(), line, 0, bytes.ToArray());
    }
}
