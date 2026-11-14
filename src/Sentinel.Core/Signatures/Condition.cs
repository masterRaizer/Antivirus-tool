namespace Sentinel.Core.Signatures;

/// <summary>Контекст вычисления условия правила для конкретных данных.</summary>
public interface IConditionContext
{
    long FileSize { get; }
    IReadOnlyCollection<string> PatternIds { get; }
    IReadOnlyList<long> Hits(string patternId);
    bool TryReadUInt(long offset, int size, bool bigEndian, out ulong value);
}

public enum CompareOp
{
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

public abstract record Condition
{
    public abstract bool Evaluate(IConditionContext ctx);

    /// <summary>Идентификаторы строк, на которые ссылается условие (для валидации при загрузке).</summary>
    public abstract IEnumerable<string> ReferencedPatterns();

    internal static bool Compare(ulong left, CompareOp op, ulong right) => op switch
    {
        CompareOp.Eq => left == right,
        CompareOp.Ne => left != right,
        CompareOp.Lt => left < right,
        CompareOp.Le => left <= right,
        CompareOp.Gt => left > right,
        CompareOp.Ge => left >= right,
        _ => false,
    };
}

public sealed record BoolCondition(bool Value) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => Value;
    public override IEnumerable<string> ReferencedPatterns() => [];
}

public sealed record AndCondition(Condition Left, Condition Right) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => Left.Evaluate(ctx) && Right.Evaluate(ctx);
    public override IEnumerable<string> ReferencedPatterns() => Left.ReferencedPatterns().Concat(Right.ReferencedPatterns());
}

public sealed record OrCondition(Condition Left, Condition Right) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => Left.Evaluate(ctx) || Right.Evaluate(ctx);
    public override IEnumerable<string> ReferencedPatterns() => Left.ReferencedPatterns().Concat(Right.ReferencedPatterns());
}

public sealed record NotCondition(Condition Inner) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => !Inner.Evaluate(ctx);
    public override IEnumerable<string> ReferencedPatterns() => Inner.ReferencedPatterns();
}

/// <summary><c>$a</c> — строка найдена хотя бы один раз.</summary>
public sealed record PatternCondition(string PatternId) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => ctx.Hits(PatternId).Count > 0;
    public override IEnumerable<string> ReferencedPatterns() => [PatternId];
}

/// <summary><c>$a at 0</c> — строка найдена по точному смещению.</summary>
public sealed record PatternAtCondition(string PatternId, long Offset) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => ctx.Hits(PatternId).Contains(Offset);
    public override IEnumerable<string> ReferencedPatterns() => [PatternId];
}

/// <summary><c>$a in (0..1024)</c> — строка найдена в диапазоне смещений (включительно).</summary>
public sealed record PatternInCondition(string PatternId, long From, long To) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => ctx.Hits(PatternId).Any(o => o >= From && o <= To);
    public override IEnumerable<string> ReferencedPatterns() => [PatternId];
}

/// <summary><c>#a &gt;= 3</c> — число вхождений строки.</summary>
public sealed record PatternCountCondition(string PatternId, CompareOp Op, ulong Value) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => Compare((ulong)ctx.Hits(PatternId).Count, Op, Value);
    public override IEnumerable<string> ReferencedPatterns() => [PatternId];
}

/// <summary>
/// <c>any of them</c>, <c>all of them</c>, <c>2 of ($a, $b*)</c>.
/// <see cref="Required"/> = null означает "all"; набор null означает "them".
/// </summary>
public sealed record OfCondition(int? Required, IReadOnlyList<string>? Selectors) : Condition
{
    public override bool Evaluate(IConditionContext ctx)
    {
        var ids = Resolve(ctx.PatternIds);
        if (ids.Count == 0)
        {
            return false;
        }

        var need = Required ?? ids.Count;
        var found = 0;
        foreach (var id in ids)
        {
            if (ctx.Hits(id).Count > 0 && ++found >= need)
            {
                return true;
            }
        }

        return false;
    }

    public IReadOnlyList<string> Resolve(IReadOnlyCollection<string> all)
    {
        if (Selectors is null)
        {
            return all.ToList();
        }

        var result = new List<string>();
        foreach (var sel in Selectors)
        {
            if (sel.EndsWith('*'))
            {
                var prefix = sel[..^1];
                result.AddRange(all.Where(id => id.StartsWith(prefix, StringComparison.Ordinal)));
            }
            else if (all.Contains(sel))
            {
                result.Add(sel);
            }
        }

        return result.Distinct(StringComparer.Ordinal).ToList();
    }

    public override IEnumerable<string> ReferencedPatterns() =>
        Selectors?.Where(s => !s.EndsWith('*')) ?? [];
}

/// <summary><c>filesize &lt; 1MB</c>.</summary>
public sealed record FileSizeCondition(CompareOp Op, ulong Value) : Condition
{
    public override bool Evaluate(IConditionContext ctx) => Compare((ulong)ctx.FileSize, Op, Value);
    public override IEnumerable<string> ReferencedPatterns() => [];
}

/// <summary><c>uint16(0) == 0x5A4D</c>, <c>uint32be(4) != 0</c>.</summary>
public sealed record IntReadCondition(int Size, bool BigEndian, long Offset, CompareOp Op, ulong Value) : Condition
{
    public override bool Evaluate(IConditionContext ctx) =>
        ctx.TryReadUInt(Offset, Size, BigEndian, out var v) && Compare(v, Op, Value);

    public override IEnumerable<string> ReferencedPatterns() => [];
}
