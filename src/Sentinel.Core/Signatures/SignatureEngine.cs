using System.Buffers.Binary;

namespace Sentinel.Core.Signatures;

/// <summary>Применяет набор правил к содержимому файла.</summary>
public sealed class SignatureEngine
{
    private readonly RuleSet _rules;

    public SignatureEngine(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _rules = rules;
    }

    public RuleSet Rules => _rules;

    /// <param name="data">Просканированные байты (может быть префиксом файла).</param>
    /// <param name="fileSize">Реальный размер файла (для условия filesize).</param>
    /// <param name="sha256">SHA-256 всего файла в нижнем регистре или null.</param>
    public IReadOnlyList<SignatureMatch> Scan(ReadOnlyMemory<byte> data, long fileSize, string? sha256) => Scan(data, fileSize, sha256, null);

    /// <param name="target">Файл (путь и признак PE): правила с <c>appliesTo</c>/<c>excludeFileNames</c> применяются только к подходящим файлам.</param>
    public IReadOnlyList<SignatureMatch> Scan(ReadOnlyMemory<byte> data, long fileSize, string? sha256, ScanTarget? target)
    {
        var matches = new List<SignatureMatch>();
        foreach (var rule in _rules.Rules)
        {
            if (!rule.Applies(target))
            {
                continue;
            }

            if (sha256 is not null && rule.Sha256.Contains(sha256))
            {
                matches.Add(new SignatureMatch(rule.Id, rule.Name, rule.Severity, rule.Category, rule.Description, [], true, rule.SourceFile));
                continue;
            }

            if (rule.Condition is null)
            {
                continue;
            }

            var ctx = new Context(rule, data, fileSize);
            if (rule.Condition.Evaluate(ctx))
            {
                matches.Add(new SignatureMatch(rule.Id, rule.Name, rule.Severity, rule.Category, rule.Description,
                    ctx.CollectedHits(), false, rule.SourceFile));
            }
        }

        return matches;
    }

    public IReadOnlyList<SignatureMatch> Scan(byte[] data, string? sha256 = null) =>
        Scan(data, data?.LongLength ?? 0, sha256);

    private sealed class Context : IConditionContext
    {
        private readonly ReadOnlyMemory<byte> _data;
        private readonly Dictionary<string, List<BytePattern>> _variants;
        private readonly Dictionary<string, IReadOnlyList<long>> _cache = new(StringComparer.Ordinal);

        public Context(SignatureRule rule, ReadOnlyMemory<byte> data, long fileSize)
        {
            _data = data;
            FileSize = fileSize;
            _variants = rule.Patterns
                .GroupBy(p => p.Id, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
            PatternIds = _variants.Keys.ToList();
        }

        public long FileSize { get; }

        public IReadOnlyCollection<string> PatternIds { get; }

        public IReadOnlyList<long> Hits(string patternId)
        {
            if (_cache.TryGetValue(patternId, out var cached))
            {
                return cached;
            }

            if (!_variants.TryGetValue(patternId, out var variants))
            {
                return _cache[patternId] = [];
            }

            var span = _data.Span;
            var all = new SortedSet<long>();
            foreach (var v in variants)
            {
                all.UnionWith(PatternMatcher.FindAll(span, v));
            }

            return _cache[patternId] = all.ToList();
        }

        public bool TryReadUInt(long offset, int size, bool bigEndian, out ulong value)
        {
            value = 0;
            if (offset < 0 || offset + size > _data.Length)
            {
                return false;
            }

            var s = _data.Span.Slice((int)offset, size);
            value = size switch
            {
                1 => s[0],
                2 => bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(s) : BinaryPrimitives.ReadUInt16LittleEndian(s),
                4 => bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(s) : BinaryPrimitives.ReadUInt32LittleEndian(s),
                _ => throw new ArgumentOutOfRangeException(nameof(size)),
            };
            return true;
        }

        public List<PatternHit> CollectedHits() =>
            _cache.Where(kv => kv.Value.Count > 0)
                .SelectMany(kv => kv.Value.Take(16).Select(o => new PatternHit(kv.Key, o)))
                .OrderBy(h => h.Offset)
                .ToList();
    }
}
