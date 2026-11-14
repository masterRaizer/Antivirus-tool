namespace Sentinel.Core.Signatures;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum PatternKind
{
    Text,
    Hex,
}

/// <summary>
/// Байтовый шаблон с маской: для каждого байта <see cref="Mask"/> задаёт значимые биты
/// (0xFF — точное совпадение, 0x00 — "??", 0xF0/0x0F — полубайтовые маски "4?"/"?A").
/// </summary>
public sealed class BytePattern
{
    public BytePattern(string id, PatternKind kind, byte[] bytes, byte[] mask, bool noCase, string source)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(mask);
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Шаблон не может быть пустым.", nameof(bytes));
        }

        if (bytes.Length != mask.Length)
        {
            throw new ArgumentException("Длины шаблона и маски различаются.", nameof(mask));
        }

        if (noCase)
        {
            bytes = Array.ConvertAll(bytes, PatternMatcher.ToLowerAscii);
        }

        Id = id;
        Kind = kind;
        Bytes = bytes;
        Mask = mask;
        NoCase = noCase;
        Source = source;
        IsExact = !noCase && Array.TrueForAll(mask, m => m == 0xFF);
    }

    public string Id { get; }
    public PatternKind Kind { get; }
    public byte[] Bytes { get; }
    public byte[] Mask { get; }
    public bool NoCase { get; }
    public string Source { get; }
    public bool IsExact { get; }
    public int Length => Bytes.Length;
}

/// <summary>
/// Правило сигнатуры. Один идентификатор строки ($a) может иметь несколько байтовых
/// вариантов (например, ascii и wide) — строка считается найденной, если найден любой вариант.
/// </summary>
public sealed class SignatureRule
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string Description { get; init; } = string.Empty;
    public Severity Severity { get; init; } = Severity.Medium;
    public string Category { get; init; } = "generic";
    public IReadOnlyList<string> Tags { get; init; } = [];
    public IReadOnlyList<BytePattern> Patterns { get; init; } = [];
    public IReadOnlySet<string> Sha256 { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public Condition? Condition { get; init; }
    public required string SourceFile { get; init; }
}

public sealed record RuleLoadError(string File, int Line, string Message)
{
    public override string ToString() => Line > 0 ? $"{File}({Line}): {Message}" : $"{File}: {Message}";
}

public sealed record PatternHit(string PatternId, long Offset);

public sealed record SignatureMatch(
    string RuleId,
    string RuleName,
    Severity Severity,
    string Category,
    string Description,
    IReadOnlyList<PatternHit> Hits,
    bool MatchedByHash,
    string SourceFile);

public sealed class RuleSet
{
    public RuleSet(IReadOnlyList<SignatureRule> rules, IReadOnlyList<RuleLoadError> errors)
    {
        Rules = rules;
        Errors = errors;
    }

    public static RuleSet Empty { get; } = new([], []);

    public IReadOnlyList<SignatureRule> Rules { get; }
    public IReadOnlyList<RuleLoadError> Errors { get; }
}

public sealed class RuleFormatException : Exception
{
    public RuleFormatException(string message, int line = 0)
        : base(message)
    {
        Line = line;
    }

    public RuleFormatException()
    {
    }

    public RuleFormatException(string message)
        : base(message)
    {
    }

    public RuleFormatException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public int Line { get; }
}
