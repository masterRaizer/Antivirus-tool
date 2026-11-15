using System.Threading.Channels;

namespace Sentinel.Core.Realtime;

public sealed class FileMonitorOptions
{
    /// <summary>Наблюдаемые каталоги (с подкаталогами). Несуществующие и недоступные пропускаются.</summary>
    public IReadOnlyList<string> Directories { get; init; } = [];

    /// <summary>Пауза тишины по файлу, после которой он отдаётся на проверку (файл дописан).</summary>
    public TimeSpan Debounce { get; init; } = TimeSpan.FromMilliseconds(800);

    /// <summary>Фрагменты путей, изменения в которых — системный шум (сравнение без учёта регистра, разделитель <c>\</c>).</summary>
    public IReadOnlyList<string> IgnoredPathFragments { get; init; } = DefaultIgnoredFragments;

    /// <summary>Расширения служебных файлов, которые постоянно переписываются системой и приложениями.</summary>
    public IReadOnlyList<string> IgnoredExtensions { get; init; } = DefaultIgnoredExtensions;

    /// <summary>Сколько файлов может одновременно ожидать паузы тишины.</summary>
    public int MaxPending { get; init; } = 20_000;

    public static IReadOnlyList<string> DefaultIgnoredFragments { get; } =
    [
        @"\$recycle.bin\", @"\system volume information\", @"\windows\winsxs\", @"\windows\prefetch\",
        @"\windows\softwaredistribution\", @"\windows\logs\", @"\windows\servicing\", @"\windows\installer\",
        @"\windows\system32\winevt\", @"\windows\system32\config\", @"\windows\system32\logfiles\",
        @"\windows\system32\wbem\repository\", @"\windows\system32\catroot2\", @"\windows\system32\sru\",
        @"\cache\", @"\code cache\", @"\gpucache\", @"\cache_data\", @"\service worker\", @"\indexeddb\",
        @"\.git\", @"\node_modules\", @"\.vs\", @"\obj\", @"\microsoft\windows\webcache\",
        @"\microsoft\windows defender\", @"\microsoft\search\data\", @"\microsoft\diagnosis\", @"\usoshared\logs\",
        @"\packages\microsoft.windows.", @"\sentinel\quarantine\", @"\sentinel\reports\",
    ];

    public static IReadOnlyList<string> DefaultIgnoredExtensions { get; } =
    [
        ".log", ".etl", ".evtx", ".pf", ".lock", ".lck", ".db-wal", ".db-shm", ".db-journal", ".sqlite-wal", ".sqlite-shm",
        ".crdownload", ".part", ".partial", ".tmp~", ".swp", ".ldb", ".regtrans-ms", ".blf", ".pma", ".edb", ".jrs", ".chk",
    ];

    /// <summary>
    /// Каталоги по умолчанию для Windows: профили пользователей, ProgramData, временные каталоги,
    /// папки задач планировщика и файла hosts. На прочих ОС — домашний и временный каталоги.
    /// </summary>
    public static FileMonitorOptions CreateDefault(string? dataDirectory = null)
    {
        var dirs = new List<string>();
        if (OperatingSystem.IsWindows())
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var systemDrive = Path.GetPathRoot(windows);
            if (!string.IsNullOrEmpty(systemDrive))
            {
                dirs.Add(Path.Combine(systemDrive, "Users"));
            }

            dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            if (!string.IsNullOrEmpty(windows))
            {
                dirs.Add(Path.Combine(windows, "Temp"));
                dirs.Add(Path.Combine(windows, "System32", "Tasks"));
                dirs.Add(Path.Combine(windows, "System32", "drivers", "etc"));
            }
        }
        else
        {
            dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            dirs.Add(Path.GetTempPath());
        }

        var fragments = DefaultIgnoredFragments.ToList();
        if (!string.IsNullOrEmpty(dataDirectory))
        {
            // Собственные данные (карантин, отчёты, манифесты) никогда не проверяются повторно.
            fragments.Add(FileNoiseFilter.Normalize(dataDirectory).TrimEnd('\\') + "\\");
        }

        return new FileMonitorOptions
        {
            Directories = dirs.Where(d => !string.IsNullOrEmpty(d)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            IgnoredPathFragments = fragments,
        };
    }
}

/// <summary>Отсев системного шума: служебные каталоги, кэши и постоянно переписываемые файлы.</summary>
public static class FileNoiseFilter
{
    public static string Normalize(string path) => path.Replace('/', '\\').ToLowerInvariant();

    public static bool IsNoise(string? path, FileMonitorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        var normalized = Normalize(path);
        foreach (var ext in options.IgnoredExtensions)
        {
            if (normalized.EndsWith(ext, StringComparison.Ordinal))
            {
                return true;
            }
        }

        foreach (var fragment in options.IgnoredPathFragments)
        {
            if (normalized.Contains(fragment, StringComparison.Ordinal))
            {
                return true;
            }
        }

        // Временные файлы Office (~$…) и атомарной записи (….tmp рядом с целевым файлом) интереса не представляют,
        // а вот исполняемые файлы во временных каталогах — представляют, поэтому каталоги Temp не исключаются.
        var name = normalized[(normalized.LastIndexOf('\\') + 1)..];
        return name.StartsWith("~$", StringComparison.Ordinal);
    }
}

/// <summary>
/// Дебаунс изменений: файл отдаётся на проверку один раз, когда запись в него затихла.
/// Время инъектируется, поэтому логика проверяется без таймеров.
/// </summary>
public sealed class FileChangeDebouncer
{
    private readonly Dictionary<string, long> _due = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private readonly TimeSpan _quiet;
    private readonly int _capacity;

    public FileChangeDebouncer(TimeSpan quiet, int capacity = 20_000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _quiet = quiet;
        _capacity = capacity;
    }

    /// <summary>Изменений, отброшенных из-за переполнения (всплеск активности на диске).</summary>
    public long Dropped { get; private set; }

    public int PendingCount
    {
        get
        {
            lock (_sync)
            {
                return _due.Count;
            }
        }
    }

    /// <summary>Отмечает изменение файла и переносит срок его проверки.</summary>
    public bool Touch(string path, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        lock (_sync)
        {
            if (!_due.ContainsKey(path) && _due.Count >= _capacity)
            {
                Dropped++;
                return false;
            }

            _due[path] = (now + _quiet).UtcTicks;
            return true;
        }
    }

    /// <summary>Файлы, по которым пауза тишины истекла.</summary>
    public IReadOnlyList<string> Drain(DateTimeOffset now)
    {
        lock (_sync)
        {
            if (_due.Count == 0)
            {
                return [];
            }

            var ticks = now.UtcTicks;
            var ready = _due.Where(p => p.Value <= ticks).Select(p => p.Key).ToArray();
            foreach (var path in ready)
            {
                _due.Remove(path);
            }

            return ready;
        }
    }
}

/// <summary>
/// Мониторинг каталогов в реальном времени: <see cref="FileSystemWatcher"/> на каждый каталог,
/// отсев шума, дебаунс и очередь файлов на проверку (<see cref="Changes"/>).
/// </summary>
public sealed class FileActivityMonitor : IDisposable
{
    private readonly FileMonitorOptions _options;
    private readonly TimeProvider _time;
    private readonly FileChangeDebouncer _debouncer;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Channel<string> _changes = Channel.CreateBounded<string>(
        new BoundedChannelOptions(10_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

    private readonly object _sync = new();
    private ITimer? _timer;

    public FileActivityMonitor(FileMonitorOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _time = timeProvider ?? TimeProvider.System;
        _debouncer = new FileChangeDebouncer(options.Debounce, options.MaxPending);
    }

    /// <summary>Файлы, готовые к проверке (после дебаунса).</summary>
    public ChannelReader<string> Changes => _changes.Reader;

    /// <summary>Каталоги, за которыми фактически установлено наблюдение.</summary>
    public IReadOnlyList<string> WatchedDirectories
    {
        get
        {
            lock (_sync)
            {
                return _watchers.Select(w => w.Path).ToArray();
            }
        }
    }

    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                return _timer is not null;
            }
        }
    }

    /// <summary>Сбой наблюдения (переполнение буфера, удалён каталог): сообщение для журнала.</summary>
    public event Action<string>? Faulted;

    public void Start()
    {
        lock (_sync)
        {
            if (_timer is not null)
            {
                return;
            }

            foreach (var directory in _options.Directories)
            {
                TryWatch(directory);
            }

            var period = TimeSpan.FromMilliseconds(Math.Clamp(_options.Debounce.TotalMilliseconds / 4, 50, 500));
            _timer = _time.CreateTimer(_ => Flush(), null, period, period);
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _timer?.Dispose();
            _timer = null;
            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }

            _watchers.Clear();
        }
    }

    public void Dispose()
    {
        Stop();
        _changes.Writer.TryComplete();
    }

    /// <summary>Сообщает об изменении файла (обработчик событий наблюдателя; открыт для тестов).</summary>
    internal void Notify(string path)
    {
        if (!FileNoiseFilter.IsNoise(path, _options))
        {
            _debouncer.Touch(path, _time.GetUtcNow());
        }
    }

    /// <summary>Передаёт в очередь файлы с истёкшей паузой тишины.</summary>
    internal void Flush()
    {
        foreach (var path in _debouncer.Drain(_time.GetUtcNow()))
        {
            _changes.Writer.TryWrite(path);
        }
    }

    private void TryWatch(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        FileSystemWatcher? watcher = null;
        try
        {
            watcher = new FileSystemWatcher(directory)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
            };
            watcher.Created += (_, e) => Notify(e.FullPath);
            watcher.Changed += (_, e) => Notify(e.FullPath);
            watcher.Renamed += (_, e) => Notify(e.FullPath);
            watcher.Error += (_, e) => Faulted?.Invoke($"Наблюдение за '{directory}': {e.GetException().Message}");
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or PlatformNotSupportedException)
        {
            watcher?.Dispose();
            Faulted?.Invoke($"Не удалось начать наблюдение за '{directory}': {ex.Message}");
        }
    }
}
