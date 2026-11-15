using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Text;

namespace Sentinel.Core.ThreatIntel;

/// <summary>Запись базы угроз: SHA-256 (64 hex-символа) и имя семейства.</summary>
public readonly record struct ThreatHashEntry(string Sha256, string Family);

/// <summary>
/// Двоичный формат <c>threat_hashes.bin</c> (little-endian):
/// <code>
/// 0   magic "SNTLDB01" (8)         8   version u32 = 1        12  recordCount u32
/// 16  timestampUtc i64 (unix, с)   24  familyCount u32        28  reserved u32
/// 32  hashesOffset u64             40  idsOffset u64          48  familyOffsetsOffset u64    56  namesOffset u64
/// hashes:  recordCount × 32 байта SHA-256, отсортированы по возрастанию (побайтовое сравнение)
/// ids:     recordCount × u16 — номер семейства записи
/// familyOffsets: familyCount × u32 — смещение имени относительно namesOffset
/// names:   имена семейств: u16 длина + UTF-8
/// </code>
/// </summary>
public static class ThreatHashDatabaseFormat
{
    public const string Magic = "SNTLDB01";
    public const int HeaderSize = 64;
    public const int HashSize = 32;
    public const int MaxFamilies = ushort.MaxValue;
    public const string GenericFamily = "Malware.Generic";
}

/// <summary>Сборка <c>threat_hashes.bin</c>: дедупликация, сортировка, таблица семейств. Результат детерминирован.</summary>
public static class ThreatHashDatabaseBuilder
{
    public static int Build(IEnumerable<ThreatHashEntry> entries, DateTimeOffset timestamp, Stream output)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(output);

        // Один хеш — одно семейство; при расхождении выигрывает лексикографически меньшее имя (детерминизм).
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (!ThreatFeedParsers.TryNormalizeSha256(entry.Sha256, out var hash))
            {
                continue;
            }

            var family = string.IsNullOrWhiteSpace(entry.Family) ? ThreatHashDatabaseFormat.GenericFamily : Truncate(entry.Family.Trim(), 96);
            if (!map.TryGetValue(hash, out var existing) || string.CompareOrdinal(family, existing) < 0)
            {
                map[hash] = family;
            }
        }

        var hashes = map.Keys.OrderBy(h => h, StringComparer.Ordinal).ToArray();
        var familyIds = new Dictionary<string, ushort>(StringComparer.Ordinal);
        var families = new List<string>();
        ushort IdFor(string family)
        {
            if (!familyIds.TryGetValue(family, out var id))
            {
                if (families.Count >= ThreatHashDatabaseFormat.MaxFamilies)
                {
                    family = ThreatHashDatabaseFormat.GenericFamily;
                    if (familyIds.TryGetValue(family, out id))
                    {
                        return id;
                    }
                }

                id = (ushort)families.Count;
                families.Add(family);
                familyIds[family] = id;
            }

            return id;
        }

        var ids = new ushort[hashes.Length];
        for (var i = 0; i < hashes.Length; i++)
        {
            ids[i] = IdFor(map[hashes[i]]);
        }

        using var names = new MemoryStream();
        var offsets = new uint[families.Count];
        for (var i = 0; i < families.Count; i++)
        {
            offsets[i] = (uint)names.Length;
            var bytes = Encoding.UTF8.GetBytes(families[i]);
            var length = new byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(length, (ushort)bytes.Length);
            names.Write(length);
            names.Write(bytes);
        }

        var hashesOffset = (ulong)ThreatHashDatabaseFormat.HeaderSize;
        var idsOffset = hashesOffset + ((ulong)hashes.Length * ThreatHashDatabaseFormat.HashSize);
        var offsetsOffset = idsOffset + ((ulong)hashes.Length * 2);
        var namesOffset = offsetsOffset + ((ulong)families.Count * 4);

        var header = new byte[ThreatHashDatabaseFormat.HeaderSize];
        Encoding.ASCII.GetBytes(ThreatHashDatabaseFormat.Magic).CopyTo(header, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), (uint)hashes.Length);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(16), timestamp.ToUnixTimeSeconds());
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(24), (uint)families.Count);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(32), hashesOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(40), idsOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(48), offsetsOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(56), namesOffset);
        output.Write(header);

        Span<byte> raw = stackalloc byte[ThreatHashDatabaseFormat.HashSize];
        foreach (var hash in hashes)
        {
            HexInto(hash, raw);
            output.Write(raw);
        }

        Span<byte> two = stackalloc byte[2];
        foreach (var id in ids)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(two, id);
            output.Write(two);
        }

        Span<byte> four = stackalloc byte[4];
        foreach (var offset in offsets)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(four, offset);
            output.Write(four);
        }

        names.Position = 0;
        names.CopyTo(output);
        output.Flush();
        return hashes.Length;
    }

    /// <summary>Атомарная запись: временный файл рядом, затем переименование.</summary>
    public static int BuildToFile(IEnumerable<ThreatHashEntry> entries, DateTimeOffset timestamp, string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = path + ".tmp";
        int count;
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            count = Build(entries, timestamp, stream);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, path, overwrite: true);
        return count;
    }

    internal static void HexInto(string hex, Span<byte> destination) => Convert.FromHexString(hex).CopyTo(destination);

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}

/// <summary>
/// Чтение <c>threat_hashes.bin</c> через <see cref="MemoryMappedFile"/>: файл не загружается в кучу .NET,
/// поиск — бинарный (≈20 сравнений на миллион записей).
/// </summary>
public sealed class ThreatHashDatabase : IThreatHashLookup, IDisposable
{
    [ThreadStatic]
    private static byte[]? s_probe;

    private readonly MemoryMappedFile _file;
    private readonly MemoryMappedViewAccessor _view;
    private readonly string[] _families;
    private readonly long _hashesOffset;
    private readonly long _idsOffset;

    private ThreatHashDatabase(MemoryMappedFile file, MemoryMappedViewAccessor view, string path, int count, DateTimeOffset timestamp,
        string[] families, long hashesOffset, long idsOffset)
    {
        _file = file;
        _view = view;
        Path = path;
        Count = count;
        TimestampUtc = timestamp;
        _families = families;
        _hashesOffset = hashesOffset;
        _idsOffset = idsOffset;
    }

    public string Path { get; }

    public int Count { get; }

    public DateTimeOffset TimestampUtc { get; }

    public int FamilyCount => _families.Length;

    /// <summary>Открывает базу; повреждённый или чужой файл — <see cref="InvalidDataException"/>.</summary>
    public static ThreatHashDatabase Open(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var length = new FileInfo(path).Length;
        if (length < ThreatHashDatabaseFormat.HeaderSize)
        {
            throw new InvalidDataException("Файл базы угроз слишком мал.");
        }

        var file = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        MemoryMappedViewAccessor? view = null;
        try
        {
            view = file.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            var header = new byte[ThreatHashDatabaseFormat.HeaderSize];
            view.ReadArray(0, header, 0, header.Length);
            if (Encoding.ASCII.GetString(header, 0, 8) != ThreatHashDatabaseFormat.Magic)
            {
                throw new InvalidDataException("Неверная сигнатура файла базы угроз.");
            }

            var count = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12));
            var timestamp = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(16)));
            var familyCount = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(24));
            var hashesOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(32));
            var idsOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(40));
            var offsetsOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(48));
            var namesOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(56));
            var expectedIds = hashesOffset + ((ulong)count * ThreatHashDatabaseFormat.HashSize);
            if (hashesOffset != ThreatHashDatabaseFormat.HeaderSize || idsOffset != expectedIds
                || offsetsOffset != idsOffset + ((ulong)count * 2) || namesOffset != offsetsOffset + ((ulong)familyCount * 4)
                || namesOffset > (ulong)length)
            {
                throw new InvalidDataException("Структура файла базы угроз повреждена.");
            }

            var families = new string[familyCount];
            var offsets = new byte[familyCount * 4];
            if (familyCount > 0)
            {
                view.ReadArray((long)offsetsOffset, offsets, 0, offsets.Length);
            }

            for (var i = 0; i < familyCount; i++)
            {
                var position = (long)namesOffset + BinaryPrimitives.ReadUInt32LittleEndian(offsets.AsSpan(i * 4));
                if (position + 2 > length)
                {
                    throw new InvalidDataException("Таблица семейств повреждена.");
                }

                var nameLength = view.ReadUInt16(position);
                if (position + 2 + nameLength > length)
                {
                    throw new InvalidDataException("Таблица семейств повреждена.");
                }

                var name = new byte[nameLength];
                view.ReadArray(position + 2, name, 0, nameLength);
                families[i] = Encoding.UTF8.GetString(name);
            }

            return new ThreatHashDatabase(file, view, path, (int)count, timestamp, families, (long)hashesOffset, (long)idsOffset);
        }
        catch
        {
            view?.Dispose();
            file.Dispose();
            throw;
        }
    }

    public bool TryGetFamily(string sha256Hex, out string? family)
    {
        family = null;
        if (!ThreatFeedParsers.TryNormalizeSha256(sha256Hex, out var normalized))
        {
            return false;
        }

        Span<byte> key = stackalloc byte[ThreatHashDatabaseFormat.HashSize];
        ThreatHashDatabaseBuilder.HexInto(normalized, key);
        var index = IndexOf(key);
        if (index < 0)
        {
            return false;
        }

        var id = _view.ReadUInt16(_idsOffset + ((long)index * 2));
        family = id < _families.Length ? _families[id] : ThreatHashDatabaseFormat.GenericFamily;
        return true;
    }

    public bool Contains(string sha256Hex) => TryGetFamily(sha256Hex, out _);

    /// <summary>Бинарный поиск ключа среди отсортированных 32-байтных записей; -1 — не найден.</summary>
    private int IndexOf(ReadOnlySpan<byte> key)
    {
        var buffer = s_probe ??= new byte[ThreatHashDatabaseFormat.HashSize];
        int low = 0, high = Count - 1;
        while (low <= high)
        {
            var mid = low + ((high - low) / 2);
            _view.ReadArray(_hashesOffset + ((long)mid * ThreatHashDatabaseFormat.HashSize), buffer, 0, ThreatHashDatabaseFormat.HashSize);
            var cmp = buffer.AsSpan().SequenceCompareTo(key);
            if (cmp == 0)
            {
                return mid;
            }

            if (cmp < 0)
            {
                low = mid + 1;
            }
            else
            {
                high = mid - 1;
            }
        }

        return -1;
    }

    /// <summary>Все записи по порядку (для слияния с новыми данными при обновлении).</summary>
    public IEnumerable<ThreatHashEntry> Enumerate()
    {
        var buffer = new byte[ThreatHashDatabaseFormat.HashSize];
        for (var i = 0; i < Count; i++)
        {
            _view.ReadArray(_hashesOffset + ((long)i * ThreatHashDatabaseFormat.HashSize), buffer, 0, ThreatHashDatabaseFormat.HashSize);
            var id = _view.ReadUInt16(_idsOffset + ((long)i * 2));
            yield return new ThreatHashEntry(Convert.ToHexString(buffer).ToLowerInvariant(), id < _families.Length ? _families[id] : ThreatHashDatabaseFormat.GenericFamily);
        }
    }

    public void Dispose()
    {
        _view.Dispose();
        _file.Dispose();
    }
}
