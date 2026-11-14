namespace Sentinel.Core.Signatures;

/// <summary>Поиск всех вхождений байтового шаблона с маской и/или без учёта регистра ASCII.</summary>
public static class PatternMatcher
{
    public const int DefaultMaxHits = 256;

    public static List<long> FindAll(ReadOnlySpan<byte> data, BytePattern pattern, int maxHits = DefaultMaxHits)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        var hits = new List<long>();
        if (pattern.Length > data.Length || maxHits <= 0)
        {
            return hits;
        }

        if (pattern.IsExact)
        {
            var needle = pattern.Bytes.AsSpan();
            var offset = 0;
            while (offset <= data.Length - needle.Length)
            {
                var idx = data[offset..].IndexOf(needle);
                if (idx < 0)
                {
                    break;
                }

                hits.Add(offset + idx);
                if (hits.Count >= maxHits)
                {
                    break;
                }

                offset += idx + 1;
            }

            return hits;
        }

        var last = data.Length - pattern.Length;
        for (var i = 0; i <= last; i++)
        {
            if (MatchAt(data, i, pattern))
            {
                hits.Add(i);
                if (hits.Count >= maxHits)
                {
                    break;
                }
            }
        }

        return hits;
    }

    public static bool MatchAt(ReadOnlySpan<byte> data, long offset, BytePattern pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        if (offset < 0 || offset + pattern.Length > data.Length)
        {
            return false;
        }

        var bytes = pattern.Bytes;
        var mask = pattern.Mask;
        var start = (int)offset;
        for (var j = 0; j < bytes.Length; j++)
        {
            var b = data[start + j];
            if (pattern.NoCase)
            {
                b = ToLowerAscii(b);
            }

            if ((b & mask[j]) != (bytes[j] & mask[j]))
            {
                return false;
            }
        }

        return true;
    }

    internal static byte ToLowerAscii(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
}
