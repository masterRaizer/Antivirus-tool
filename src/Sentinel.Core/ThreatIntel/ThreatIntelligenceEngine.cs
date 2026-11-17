namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Локальная база угроз из трёх файлов: <c>threat_hashes.bin</c> (SHA-256), <c>threat_hashes_sha1.bin</c> и
/// <c>threat_hashes_md5.bin</c> (базы, где есть только эти хеши: VirusShare, ESET <c>*.md5</c>/<c>*.sha1</c>, signature-base).
/// Для каждого вида открывается наиболее свежая из двух копий: обновляемая в каталоге данных и поставляемая с программой
/// (<c>data\</c> рядом с исполняемым файлом). Горячая замена файла при обновлении не прерывает поиск.
/// </summary>
public sealed class ThreatIntelligenceEngine : IThreatHashLookup, IDisposable
{
    public const string FileName = "threat_hashes.bin";

    private static readonly ThreatHashKind[] Kinds = [ThreatHashKind.Sha256, ThreatHashKind.Sha1, ThreatHashKind.Md5];

    private readonly ReaderWriterLockSlim _lock = new();
    private readonly string _dataDirectory;
    private readonly string? _bundledDirectory;
    private readonly Dictionary<ThreatHashKind, ThreatHashDatabase?> _databases = [];

    public ThreatIntelligenceEngine(string dataDirectory, string? bundledPath = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataDirectory);
        _dataDirectory = Path.GetFullPath(dataDirectory);
        _bundledDirectory = string.IsNullOrWhiteSpace(bundledPath) ? null : Path.GetDirectoryName(Path.GetFullPath(bundledPath));
        foreach (var kind in Kinds)
        {
            _databases[kind] = OpenBest(kind);
        }
    }

    public static string DefaultBundledPath() => Path.Combine(AppContext.BaseDirectory, "data", FileName);

    /// <summary>Обновляемая копия базы SHA-256 в каталоге данных.</summary>
    public string UpdatablePath => UpdatablePathOf(ThreatHashKind.Sha256);

    public string UpdatablePathOf(ThreatHashKind kind) => Path.Combine(_dataDirectory, ThreatHashKinds.FileName(kind));

    /// <summary>Записей SHA-256.</summary>
    public int Count => CountOf(ThreatHashKind.Sha256);

    /// <summary>Записей всех видов (SHA-256 + SHA-1 + MD5).</summary>
    public long TotalCount => Kinds.Sum(k => (long)CountOf(k));

    public int CountOf(ThreatHashKind kind) => With(kind, d => d?.Count ?? 0);

    public DateTimeOffset? TimestampUtc => With(ThreatHashKind.Sha256, d => d?.TimestampUtc);

    public string? ActivePath => With(ThreatHashKind.Sha256, d => d?.Path);

    /// <summary>Есть ли базы MD5/SHA-1: только тогда анализатор считает эти хеши (лишняя работа без базы не нужна).</summary>
    public bool HasLegacyHashes => CountOf(ThreatHashKind.Md5) > 0 || CountOf(ThreatHashKind.Sha1) > 0;

    public bool TryGetFamily(string sha256Hex, out string? family) => TryGetFamily(ThreatHashKind.Sha256, sha256Hex, out family);

    public bool TryGetFamily(ThreatHashKind kind, string hex, out string? family)
    {
        _lock.EnterReadLock();
        try
        {
            if (_databases.GetValueOrDefault(kind) is not { } database)
            {
                family = null;
                return false;
            }

            return database.TryGetFamily(hex, out family);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>Все записи SHA-256 (для тестов и отладки; при обновлении используется потоковое слияние <see cref="Merge"/>).</summary>
    public IReadOnlyList<ThreatHashEntry> Snapshot() => With(ThreatHashKind.Sha256, d => d is null ? [] : (IReadOnlyList<ThreatHashEntry>)[.. d.Enumerate()]);

    public void Reload()
    {
        _lock.EnterWriteLock();
        try
        {
            foreach (var kind in Kinds)
            {
                var old = _databases.GetValueOrDefault(kind);
                _databases[kind] = OpenBest(kind);
                old?.Dispose();
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public void ReplaceWith(string newFile) => ReplaceWith(newFile, ThreatHashKind.Sha256);

    /// <summary>Подмена базы вида <paramref name="kind"/> новым файлом (проверяется до подмены).</summary>
    public void ReplaceWith(string newFile, ThreatHashKind kind)
    {
        ArgumentException.ThrowIfNullOrEmpty(newFile);
        using (var check = ThreatHashDatabase.Open(newFile))
        {
            // проверка целостности до замены: повреждённый файл не должен вытеснить рабочую базу
            if (check.Kind != kind)
            {
                throw new InvalidDataException($"Файл содержит хеши {ThreatHashKinds.Label(check.Kind)}, ожидались {ThreatHashKinds.Label(kind)}.");
            }
        }

        _lock.EnterWriteLock();
        try
        {
            _databases.GetValueOrDefault(kind)?.Dispose();
            _databases[kind] = null;
            Directory.CreateDirectory(_dataDirectory);
            File.Move(newFile, UpdatablePathOf(kind), overwrite: true);
            _databases[kind] = OpenBest(kind);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Добавить записи в базу их вида потоковым слиянием (вся база в память не загружается). Записи других видов пропускаются.
    /// Возвращает число новых хешей.
    /// </summary>
    public int Merge(IEnumerable<ThreatHashEntry> additions, DateTimeOffset timestamp, ThreatHashKind kind = ThreatHashKind.Sha256)
    {
        ArgumentNullException.ThrowIfNull(additions);
        var list = additions.Where(e => ThreatHashKinds.Of(e.Sha256) == kind).ToList();
        var before = CountOf(kind);
        if (list.Count == 0)
        {
            return 0;
        }

        Directory.CreateDirectory(_dataDirectory);
        var temp = UpdatablePathOf(kind) + ".new";
        _lock.EnterReadLock();
        try
        {
            ThreatHashDatabaseBuilder.MergeToFile(_databases.GetValueOrDefault(kind), list, timestamp, temp, kind);
        }
        finally
        {
            _lock.ExitReadLock();
        }

        ReplaceWith(temp, kind);
        return Math.Max(0, CountOf(kind) - before);
    }

    public void Dispose()
    {
        _lock.EnterWriteLock();
        try
        {
            foreach (var kind in Kinds)
            {
                _databases.GetValueOrDefault(kind)?.Dispose();
                _databases[kind] = null;
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        _lock.Dispose();
    }

    private T With<T>(ThreatHashKind kind, Func<ThreatHashDatabase?, T> read)
    {
        _lock.EnterReadLock();
        try
        {
            return read(_databases.GetValueOrDefault(kind));
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    private ThreatHashDatabase? OpenBest(ThreatHashKind kind)
    {
        ThreatHashDatabase? best = null;
        var bundled = _bundledDirectory is null ? null : Path.Combine(_bundledDirectory, ThreatHashKinds.FileName(kind));
        foreach (var path in new[] { UpdatablePathOf(kind), bundled }.Where(p => p is not null && File.Exists(p)))
        {
            try
            {
                var candidate = ThreatHashDatabase.Open(path!);
                if (candidate.Kind != kind)
                {
                    candidate.Dispose();
                    continue;
                }

                if (best is null || candidate.TimestampUtc > best.TimestampUtc
                    || (candidate.TimestampUtc == best.TimestampUtc && candidate.Count > best.Count))
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
