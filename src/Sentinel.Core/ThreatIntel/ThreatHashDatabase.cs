using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Text;

namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Запись базы: хеш (hex нижнего регистра) и семейство. Поле называется <c>Sha256</c> исторически: в нём может лежать и MD5
/// (32 hex), и SHA-1 (40 hex) — вид хеша определяется длиной (<see cref="ThreatHashKinds.Of"/>).
/// </summary>
public readonly record struct ThreatHashEntry(string Sha256, string Family);

/// <summary>Вид хеша в базе угроз.</summary>
public enum ThreatHashKind
{
    Sha256,
    Sha1,
    Md5,
}

public static class ThreatHashKinds
{
    public static int ByteLength(ThreatHashKind kind) => kind switch
    {
        ThreatHashKind.Md5 => 16,
        ThreatHashKind.Sha1 => 20,
        _ => 32,
    };

    public static int HexLength(ThreatHashKind kind) => ByteLength(kind) * 2;

    /// <summary>Вид по длине hex-строки; <c>null</c> — не хеш.</summary>
    public static ThreatHashKind? Of(string? hex) => hex?.Trim().Length switch
    {
        64 => ThreatHashKind.Sha256,
        40 => ThreatHashKind.Sha1,
        32 => ThreatHashKind.Md5,
        _ => null,
    };

    /// <summary>Имя файла базы: <c>threat_hashes.bin</c>, <c>threat_hashes_sha1.bin</c>, <c>threat_hashes_md5.bin</c>.</summary>
    public static string FileName(ThreatHashKind kind) => kind switch
    {
        ThreatHashKind.Md5 => "threat_hashes_md5.bin",
        ThreatHashKind.Sha1 => "threat_hashes_sha1.bin",
        _ => "threat_hashes.bin",
    };

    public static string Label(ThreatHashKind kind) => kind switch
    {
        ThreatHashKind.Md5 => "MD5",
        ThreatHashKind.Sha1 => "SHA-1",
        _ => "SHA-256",
    };
}

/// <summary>
/// Формат <c>threat_hashes*.bin</c>: заголовок 64 байта (сигнатура, версия, число записей, метка времени, число семейств,
/// длина хеша, смещения разделов), затем отсортированные хеши фиксированной длины, 2-байтные номера семейств, смещения и
/// имена семейств. Версия 1 — только SHA-256 (32 байта); версия 2 — длина хеша в байте 28 (16 — MD5, 20 — SHA-1, 32 — SHA-256).
/// </summary>
public static class ThreatHashDatabaseFormat
{
    public const string Magic = "SNTLDB01";
    public const int HeaderSize = 64;
    public const int HashSize = 32;
    public const int MaxFamilies = ushort.MaxValue;
    public const string GenericFamily = "Malware.Generic";
}

public static class ThreatHashDatabaseBuilder
{
    public static int Build(IEnumerable<ThreatHashEntry> entries, DateTimeOffset timestamp, Stream output) =>
        Build(entries, timestamp, output, ThreatHashKind.Sha256);

    /// <summary>Сборка базы одного вида хешей; записи других видов пропускаются.</summary>
    public static int Build(IEnumerable<ThreatHashEntry> entries, DateTimeOffset timestamp, Stream output, ThreatHashKind kind)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(output);

        // Один хеш — одно семейство; при расхождении выигрывает лексикографически меньшее имя (детерминизм).
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (!ThreatFeedParsers.TryNormalizeHash(entry.Sha256, kind, out var hash))
            {
                continue;
            }

            var family = NormalizeFamily(entry.Family);
            if (!map.TryGetValue(hash, out var existing) || string.CompareOrdinal(family, existing) < 0)
            {
                map[hash] = family;
            }
        }

        var hashes = map.Keys.OrderBy(h => h, StringComparer.Ordinal).ToArray();
        var table = new FamilyTable([]);
        var size = ThreatHashKinds.ByteLength(kind);
        var raw = new byte[size];
        var ids = new MemoryStream(hashes.Length * 2);
        Span<byte> two = stackalloc byte[2];
        var start = output.Position;
        output.Write(new byte[ThreatHashDatabaseFormat.HeaderSize]);
        foreach (var hash in hashes)
        {
            HexInto(hash, raw);
            output.Write(raw);
            BinaryPrimitives.WriteUInt16LittleEndian(two, table.IdFor(map[hash]));
            ids.Write(two);
        }

        WriteTail(output, start, ids, table, hashes.Length, timestamp, kind);
        return hashes.Length;
    }

    /// <summary>Атомарная запись: временный файл рядом, затем переименование.</summary>
    public static int BuildToFile(IEnumerable<ThreatHashEntry> entries, DateTimeOffset timestamp, string path) =>
        BuildToFile(entries, timestamp, path, ThreatHashKind.Sha256);

    public static int BuildToFile(IEnumerable<ThreatHashEntry> entries, DateTimeOffset timestamp, string path, ThreatHashKind kind) =>
        WriteAtomically(path, stream => Build(entries, timestamp, stream, kind));

    /// <summary>
    /// Слияние уже собранной базы с новыми записями потоком: существующие хеши читаются по порядку из отображённого в память
    /// файла, новые (обычно десятки тысяч) сортируются отдельно. Вся база в память не загружается — на миллионах записей прежний
    /// способ (перечислить всё в список и пересобрать) занимал сотни мегабайт и заметно грузил процессор каждые 6 часов.
    /// Номера существующих семейств сохраняются; у совпавших хешей остаётся прежнее семейство.
    /// </summary>
    public static int MergeToFile(ThreatHashDatabase? existing, IEnumerable<ThreatHashEntry> additions, DateTimeOffset timestamp, string path,
        ThreatHashKind kind = ThreatHashKind.Sha256)
    {
        ArgumentNullException.ThrowIfNull(additions);
        if (existing is not null && existing.Kind != kind)
        {
            throw new ArgumentException("Вид хешей базы не совпадает с видом слияния.", nameof(existing));
        }

        var fresh = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in additions)
        {
            if (ThreatFeedParsers.TryNormalizeHash(entry.Sha256, kind, out var hash))
            {
                var family = NormalizeFamily(entry.Family);
                if (!fresh.TryGetValue(hash, out var other) || string.CompareOrdinal(family, other) < 0)
                {
                    fresh[hash] = family;
                }
            }
        }

        var added = fresh.OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => (Key: Convert.FromHexString(kv.Key), Family: kv.Value)).ToArray();
        return WriteAtomically(path, output =>
        {
            var size = ThreatHashKinds.ByteLength(kind);
            var table = new FamilyTable(existing?.Families ?? []);
            var ids = new MemoryStream(((existing?.Count ?? 0) + added.Length) * 2);
            Span<byte> two = stackalloc byte[2];
            var current = new byte[size];
            var start = output.Position;
            output.Write(new byte[ThreatHashDatabaseFormat.HeaderSize]);
            int i = 0, j = 0, count = 0;
            var total = existing?.Count ?? 0;
            while (i < total || j < added.Length)
            {
                ushort id;
                if (i < total)
                {
                    existing!.ReadHash(i, current);
                }

                var cmp = i >= total ? 1 : j >= added.Length ? -1 : current.AsSpan().SequenceCompareTo(added[j].Key);
                if (cmp < 0)
                {
                    output.Write(current);
                    id = existing!.ReadFamilyId(i);
                    i++;
                }
                else if (cmp > 0)
                {
                    output.Write(added[j].Key);
                    id = table.IdFor(added[j].Family);
                    j++;
                }
                else
                {
                    output.Write(current); // хеш уже известен — семейство прежнее
                    id = existing!.ReadFamilyId(i);
                    i++;
                    j++;
                }

                BinaryPrimitives.WriteUInt16LittleEndian(two, id);
                ids.Write(two);
                count++;
            }

            WriteTail(output, start, ids, table, count, timestamp, kind);
            return count;
        });
    }

    internal static void HexInto(string hex, Span<byte> destination) => Convert.FromHexString(hex).CopyTo(destination);

    private static string NormalizeFamily(string? family) =>
        string.IsNullOrWhiteSpace(family) ? ThreatHashDatabaseFormat.GenericFamily : Truncate(family.Trim(), 96);

    /// <summary>Номера семейств после хешей, таблица смещений и имён; заголовок записывается в начало последним.</summary>
    private static void WriteTail(Stream output, long start, MemoryStream ids, FamilyTable table, int count, DateTimeOffset timestamp, ThreatHashKind kind)
    {
        var size = ThreatHashKinds.ByteLength(kind);
        ids.Position = 0;
        ids.CopyTo(output);

        using var names = new MemoryStream();
        var offsets = new uint[table.Names.Count];
        for (var k = 0; k < table.Names.Count; k++)
        {
            offsets[k] = (uint)names.Length;
            var bytes = Encoding.UTF8.GetBytes(table.Names[k]);
            var length = new byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(length, (ushort)bytes.Length);
            names.Write(length);
            names.Write(bytes);
        }

        Span<byte> four = stackalloc byte[4];
        foreach (var offset in offsets)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(four, offset);
            output.Write(four);
        }

        names.Position = 0;
        names.CopyTo(output);

        var hashesOffset = (ulong)ThreatHashDatabaseFormat.HeaderSize;
        var idsOffset = hashesOffset + ((ulong)count * (ulong)size);
        var offsetsOffset = idsOffset + ((ulong)count * 2);
        var namesOffset = offsetsOffset + ((ulong)table.Names.Count * 4);
        var header = new byte[ThreatHashDatabaseFormat.HeaderSize];
        Encoding.ASCII.GetBytes(ThreatHashDatabaseFormat.Magic).CopyTo(header, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), kind == ThreatHashKind.Sha256 ? 1u : 2u);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), (uint)count);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(16), timestamp.ToUnixTimeSeconds());
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(24), (uint)table.Names.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(28), (uint)size);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(32), hashesOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(40), idsOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(48), offsetsOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(56), namesOffset);
        var end = output.Position;
        output.Position = start;
        output.Write(header);
        output.Position = end;
        output.Flush();
    }

    private static int WriteAtomically(string path, Func<Stream, int> write)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = path + ".tmp";
        int count;
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        {
            count = write(stream);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, path, overwrite: true);
        return count;
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    /// <summary>Таблица семейств: существующие имена сохраняют номера, новые дописываются; переполнение — в общее семейство.</summary>
    private sealed class FamilyTable
    {
        private readonly Dictionary<string, ushort> _ids = new(StringComparer.Ordinal);

        public FamilyTable(IReadOnlyList<string> existing)
        {
            foreach (var name in existing)
            {
                _ids.TryAdd(name, (ushort)Names.Count);
                Names.Add(name);
            }
        }

        public List<string> Names { get; } = [];

        public ushort IdFor(string family)
        {
            if (_ids.TryGetValue(family, out var id))
            {
                return id;
            }

            if (Names.Count >= ThreatHashDatabaseFormat.MaxFamilies)
            {
                family = ThreatHashDatabaseFormat.GenericFamily;
                if (_ids.TryGetValue(family, out id))
                {
                    return id;
                }

                return 0; // таблица полна, общего семейства нет — первая запись (не теряем хеш)
            }

            id = (ushort)Names.Count;
            Names.Add(family);
            _ids[family] = id;
            return id;
        }
    }
}

/// <summary>
/// Чтение <c>threat_hashes*.bin</c> через <see cref="MemoryMappedFile"/>: файл не загружается в кучу .NET,
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
    private readonly int _hashSize;

    private ThreatHashDatabase(MemoryMappedFile file, MemoryMappedViewAccessor view, string path, int count, DateTimeOffset timestamp,
        string[] families, long hashesOffset, long idsOffset, ThreatHashKind kind)
    {
        _file = file;
        _view = view;
        Path = path;
        Count = count;
        TimestampUtc = timestamp;
        _families = families;
        _hashesOffset = hashesOffset;
        _idsOffset = idsOffset;
        Kind = kind;
        _hashSize = ThreatHashKinds.ByteLength(kind);
    }

    public string Path { get; }

    public int Count { get; }

    public DateTimeOffset TimestampUtc { get; }

    public int FamilyCount => _families.Length;

    public ThreatHashKind Kind { get; }

    /// <summary>Имена семейств в порядке номеров (для слияния без перенумерации).</summary>
    public IReadOnlyList<string> Families => _families;

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

            var version = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8));
            var size = version >= 2 ? (int)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(28)) : ThreatHashDatabaseFormat.HashSize;
            ThreatHashKind kind = size switch
            {
                16 => ThreatHashKind.Md5,
                20 => ThreatHashKind.Sha1,
                32 => ThreatHashKind.Sha256,
                _ => throw new InvalidDataException($"Неизвестная длина хеша в базе угроз: {size}."),
            };
            var count = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12));
            var timestamp = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(16)));
            var familyCount = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(24));
            var hashesOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(32));
            var idsOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(40));
            var offsetsOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(48));
            var namesOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(56));
            var expectedIds = hashesOffset + ((ulong)count * (ulong)size);
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

            return new ThreatHashDatabase(file, view, path, (int)count, timestamp, families, (long)hashesOffset, (long)idsOffset, kind);
        }
        catch
        {
            view?.Dispose();
            file.Dispose();
            throw;
        }
    }

    /// <summary>Поиск хеша своего вида (для базы SHA-256 — SHA-256, для MD5 — MD5 и т.д.).</summary>
    public bool TryGetFamily(string sha256Hex, out string? family)
    {
        family = null;
        if (!ThreatFeedParsers.TryNormalizeHash(sha256Hex, Kind, out var normalized))
        {
            return false;
        }

        Span<byte> key = stackalloc byte[_hashSize];
        ThreatHashDatabaseBuilder.HexInto(normalized, key);
        var index = IndexOf(key);
        if (index < 0)
        {
            return false;
        }

        var id = ReadFamilyId(index);
        family = id < _families.Length ? _families[id] : ThreatHashDatabaseFormat.GenericFamily;
        return true;
    }

    public bool Contains(string sha256Hex) => TryGetFamily(sha256Hex, out _);

    internal void ReadHash(int index, byte[] destination) =>
        _view.ReadArray(_hashesOffset + ((long)index * _hashSize), destination, 0, _hashSize);

    internal ushort ReadFamilyId(int index) => _view.ReadUInt16(_idsOffset + ((long)index * 2));

    /// <summary>Бинарный поиск ключа среди отсортированных записей; -1 — не найден.</summary>
    private int IndexOf(ReadOnlySpan<byte> key)
    {
        var buffer = s_probe ??= new byte[ThreatHashDatabaseFormat.HashSize];
        var probe = buffer.AsSpan(0, _hashSize);
        int low = 0, high = Count - 1;
        while (low <= high)
        {
            var mid = low + ((high - low) / 2);
            _view.ReadArray(_hashesOffset + ((long)mid * _hashSize), buffer, 0, _hashSize);
            var cmp = probe.SequenceCompareTo(key);
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

    /// <summary>Все записи по порядку.</summary>
    public IEnumerable<ThreatHashEntry> Enumerate()
    {
        var buffer = new byte[_hashSize];
        for (var i = 0; i < Count; i++)
        {
            ReadHash(i, buffer);
            var id = ReadFamilyId(i);
            yield return new ThreatHashEntry(Convert.ToHexString(buffer).ToLowerInvariant(), id < _families.Length ? _families[id] : ThreatHashDatabaseFormat.GenericFamily);
        }
    }

    public void Dispose()
    {
        _view.Dispose();
        _file.Dispose();
    }
}
