using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core.Scanning;

/// <summary>
/// Персистентный кэш чистых файлов: <c>(путь, размер, время записи, отпечаток правил и баз) → Clean</c>.
/// Неизменённый чистый файл при повторной проверке пропускается без хеширования и проверки подписи.
/// Файл <c>scan_cache.bin</c> перезаписывается атомарно (временный файл → замена). Сменился отпечаток правил или баз —
/// весь кэш считается устаревшим.
/// </summary>
public sealed class ScanVerdictCache
{
    private const string Magic = "SNTLSC01";

    private readonly object _sync = new();
    private readonly Dictionary<string, (long Size, long WriteTicks)> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _path;
    private string _fingerprint;
    private int _dirty;

    public ScanVerdictCache(string path, string fingerprint)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(fingerprint);
        _path = path;
        _fingerprint = fingerprint;
        Load();
    }

    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Отпечаток правил и баз: имя, размер и время изменения каждого файла правил и базы угроз.</summary>
    public static string ComputeFingerprint(params string?[] filesOrDirectories)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var item in filesOrDirectories.Where(i => !string.IsNullOrEmpty(i)).OrderBy(i => i, StringComparer.OrdinalIgnoreCase))
        {
            IEnumerable<string> files = Directory.Exists(item)
                ? Directory.EnumerateFiles(item!, "*", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                : File.Exists(item) ? [item!] : [];
            foreach (var file in files)
            {
                var info = new FileInfo(file);
                sha.AppendData(Encoding.UTF8.GetBytes($"{Path.GetFileName(file)}|{info.Length}|{info.LastWriteTimeUtc.Ticks};"));
            }
        }

        return Convert.ToHexString(sha.GetHashAndReset());
    }

    /// <summary>Заменяет отпечаток (например, после обновления баз): прежние записи отбрасываются.</summary>
    public void SetFingerprint(string fingerprint)
    {
        lock (_sync)
        {
            if (!string.Equals(_fingerprint, fingerprint, StringComparison.Ordinal))
            {
                _fingerprint = fingerprint;
                _entries.Clear();
                _dirty = 1;
            }
        }
    }

    /// <summary>Файл не менялся с момента, когда был признан чистым.</summary>
    public bool IsKnownClean(string path)
    {
        var info = new FileInfo(path);
        lock (_sync)
        {
            return info.Exists && _entries.TryGetValue(Normalize(path), out var e) && e.Size == info.Length && e.WriteTicks == info.LastWriteTimeUtc.Ticks;
        }
    }

    public void MarkClean(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            return;
        }

        lock (_sync)
        {
            _entries[Normalize(path)] = (info.Length, info.LastWriteTimeUtc.Ticks);
            _dirty = 1;
        }
    }

    public void Invalidate(string path)
    {
        lock (_sync)
        {
            if (_entries.Remove(Normalize(path)))
            {
                _dirty = 1;
            }
        }
    }

    /// <summary>Записывает кэш атомарно; без изменений ничего не делает.</summary>
    public void Save()
    {
        byte[] data;
        lock (_sync)
        {
            if (_dirty == 0)
            {
                return;
            }

            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                w.Write(Encoding.ASCII.GetBytes(Magic));
                w.Write(_fingerprint);
                w.Write(_entries.Count);
                foreach (var (path, e) in _entries)
                {
                    w.Write(path);
                    w.Write(e.Size);
                    w.Write(e.WriteTicks);
                }
            }

            data = ms.ToArray();
            _dirty = 0;
        }

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = _path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(data);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, _path, overwrite: true);
    }

    private void Load()
    {
        if (!File.Exists(_path))
        {
            return;
        }

        try
        {
            using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var r = new BinaryReader(stream, Encoding.UTF8);
            if (Encoding.ASCII.GetString(r.ReadBytes(Magic.Length)) != Magic || r.ReadString() != _fingerprint)
            {
                return;
            }

            var count = r.ReadInt32();
            for (var i = 0; i < count; i++)
            {
                _entries[r.ReadString()] = (r.ReadInt64(), r.ReadInt64());
            }
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or ArgumentException or FormatException)
        {
            // Повреждённый кэш не критичен: проверка просто выполнится заново.
            _entries.Clear();
        }
    }

    private static string Normalize(string path) => Path.GetFullPath(path);

}
