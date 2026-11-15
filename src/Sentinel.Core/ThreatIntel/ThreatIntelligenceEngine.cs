namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Локальная база угроз. Открывает наиболее свежую из двух копий <c>threat_hashes.bin</c>: обновляемую в каталоге данных
/// и поставляемую с программой (<c>data\threat_hashes.bin</c> рядом с исполняемым файлом). Горячая замена файла при обновлении
/// не прерывает поиск: читатели ждут не дольше самой подмены.
/// </summary>
public sealed class ThreatIntelligenceEngine : IThreatHashLookup, IDisposable
{
    public const string FileName = "threat_hashes.bin";

    private readonly ReaderWriterLockSlim _lock = new();
    private readonly string _updatablePath;
    private readonly string? _bundledPath;
    private ThreatHashDatabase? _database;

    public ThreatIntelligenceEngine(string dataDirectory, string? bundledPath = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataDirectory);
        _updatablePath = Path.Combine(Path.GetFullPath(dataDirectory), FileName);
        _bundledPath = string.IsNullOrWhiteSpace(bundledPath) ? null : Path.GetFullPath(bundledPath);
        _database = OpenBest();
    }

    /// <summary>Поставляемая база рядом с исполняемым файлом: <c>&lt;каталог программы&gt;\data\threat_hashes.bin</c>.</summary>
    public static string DefaultBundledPath() => Path.Combine(AppContext.BaseDirectory, "data", FileName);

    public string UpdatablePath => _updatablePath;

    public int Count => With(d => d?.Count ?? 0);

    public DateTimeOffset? TimestampUtc => With(d => d?.TimestampUtc);

    public string? ActivePath => With(d => d?.Path);

    public bool TryGetFamily(string sha256Hex, out string? family)
    {
        _lock.EnterReadLock();
        try
        {
            if (_database is null)
            {
                family = null;
                return false;
            }

            return _database.TryGetFamily(sha256Hex, out family);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>Все записи активной базы (для слияния с новыми данными).</summary>
    public IReadOnlyList<ThreatHashEntry> Snapshot()
    {
        _lock.EnterReadLock();
        try
        {
            return _database is null ? [] : [.. _database.Enumerate()];
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>Повторно выбирает самую свежую базу (например, после ручной замены файла).</summary>
    public void Reload()
    {
        _lock.EnterWriteLock();
        try
        {
            var old = _database;
            _database = OpenBest();
            old?.Dispose();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <summary>Заменяет обновляемую базу готовым файлом: старое отображение закрывается, файл перемещается, база открывается заново.</summary>
    public void ReplaceWith(string newFile)
    {
        ArgumentException.ThrowIfNullOrEmpty(newFile);
        using (ThreatHashDatabase.Open(newFile))
        {
            // проверка целостности до замены: повреждённый файл не должен вытеснить рабочую базу
        }

        _lock.EnterWriteLock();
        try
        {
            _database?.Dispose();
            _database = null;
            Directory.CreateDirectory(Path.GetDirectoryName(_updatablePath)!);
            File.Move(newFile, _updatablePath, overwrite: true);
            _database = OpenBest();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public void Dispose()
    {
        _lock.EnterWriteLock();
        try
        {
            _database?.Dispose();
            _database = null;
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        _lock.Dispose();
    }

    private T With<T>(Func<ThreatHashDatabase?, T> read)
    {
        _lock.EnterReadLock();
        try
        {
            return read(_database);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    private ThreatHashDatabase? OpenBest()
    {
        ThreatHashDatabase? best = null;
        foreach (var path in new[] { _updatablePath, _bundledPath }.Where(p => p is not null && File.Exists(p)))
        {
            try
            {
                var candidate = ThreatHashDatabase.Open(path!);
                if (best is null || candidate.TimestampUtc > best.TimestampUtc)
                {
                    best?.Dispose();
                    best = candidate;
                }
                else
                {
                    candidate.Dispose();
                }
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
            {
                // Повреждённая копия пропускается; вторая (или её отсутствие) остаётся запасным вариантом.
            }
        }

        return best;
    }
}
