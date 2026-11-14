namespace Sentinel.Core.Analysis;

/// <summary>
/// Энтропия Шеннона в битах на байт (0..8). Значения выше ~7.2 характерны для
/// сжатых/зашифрованных данных (упаковщики, шифрованные полезные нагрузки).
/// </summary>
public static class EntropyCalculator
{
    /// <summary>Порог, начиная с которого данные считаются упакованными/зашифрованными.</summary>
    public const double HighEntropyThreshold = 7.2;

    public static double Calculate(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<long> counts = stackalloc long[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        return FromCounts(counts, data.Length);
    }

    public static double Calculate(Stream stream) => Calculate(stream, long.MaxValue);

    /// <summary>Энтропия не более <paramref name="maxBytes"/> байт с текущей позиции потока.</summary>
    public static double Calculate(Stream stream, long maxBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var counts = new long[256];
        long total = 0;
        var buffer = new byte[1 << 16];
        while (total < maxBytes)
        {
            var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, maxBytes - total));
            if (read <= 0)
            {
                break;
            }

            for (var i = 0; i < read; i++)
            {
                counts[buffer[i]]++;
            }

            total += read;
        }

        return FromCounts(counts, total);
    }

    public static double CalculateFile(string path)
    {
        using var stream = Hashing.FileHasher.OpenShared(path);
        return Calculate(stream);
    }

    /// <summary>
    /// Энтропия по скользящим блокам фиксированного размера — позволяет найти
    /// зашифрованный фрагмент внутри в целом «обычного» файла.
    /// </summary>
    public static IReadOnlyList<double> CalculateBlocks(ReadOnlySpan<byte> data, int blockSize = 4096)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);
        var result = new List<double>((data.Length + blockSize - 1) / blockSize);
        for (var offset = 0; offset < data.Length; offset += blockSize)
        {
            var len = Math.Min(blockSize, data.Length - offset);
            result.Add(Calculate(data.Slice(offset, len)));
        }

        return result;
    }

    private static double FromCounts(ReadOnlySpan<long> counts, long total)
    {
        if (total == 0)
        {
            return 0.0;
        }

        double entropy = 0;
        double dTotal = total;
        foreach (var c in counts)
        {
            if (c == 0)
            {
                continue;
            }

            var p = c / dTotal;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
