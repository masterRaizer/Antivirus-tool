using Sentinel.Core.Analysis;

namespace Sentinel.Core.Behavioral;

/// <summary>Вид файлового события из монитора реального времени.</summary>
public enum FileEventKind
{
    Created,
    Modified,
    Renamed,
    Deleted,
}

/// <summary>Параметры поведенческого анти-шифровальщика.</summary>
public sealed record RansomwareShieldOptions
{
    /// <summary>Окно корреляции всплеска.</summary>
    public TimeSpan Window { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Окно подавления дублей событий <c>Modified</c> для одного пути.</summary>
    public TimeSpan Debounce { get; init; } = TimeSpan.FromMilliseconds(300);

    /// <summary>Порог уникальных затронутых файлов для «всплеска».</summary>
    public int BurstThreshold { get; init; } = 12;

    /// <summary>Порог средней энтропии перезаписанных файлов (бит/байт).</summary>
    public double EntropyThreshold { get; init; } = 7.65;

    /// <summary>Сколько высокоэнтропийных перезаписей считать признаком шифрования.</summary>
    public int HighEntropyCount { get; init; } = 5;

    /// <summary>Итоговый порог риска для срабатывания.</summary>
    public int AlertThreshold { get; init; } = 75;

    /// <summary>Пауза между оповещениями, чтобы не дублировать тревогу на одном всплеске.</summary>
    public TimeSpan AlertCooldown { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>Тревога анти-шифровальщика: итоговый балл, причина и затронутые файлы для корреляции и карантина источника.</summary>
public sealed record RansomwareAlert(int Score, string Reason, IReadOnlyList<string> AffectedFiles);

/// <summary>
/// Поведенческий детектор шифровальщиков в User-Mode поверх файлового монитора. Анализирует в скользящем окне 5 секунд
/// всплеск уникальных изменений в пользовательских профилях, появление «шифровальных» или единообразных новых расширений
/// и потоково измеренную (буфер 64 КБ) энтропию перезаписанных файлов. Технические каталоги разработки и кэши исключаются,
/// повторы <c>Modified</c> подавляются дебаунсом. Потокобезопасен.
/// </summary>
public sealed class RansomwareBehaviorShield
{
    private static readonly string[] ExcludedPathMarkers =
    [
        @"\node_modules\", @"\.git\", @"\bin\debug\", @"\bin\release\", @"\obj\", @"\.vs\",
        @"\appdata\local\microsoft\windows\inetcache\", @"\appdata\local\google\chrome\user data\",
        @"\appdata\local\mozilla\firefox\", @"\cache\", @"\code cache\", @"\gpucache\",
    ];

    private static readonly string[] ProfileMarkers =
        [@"\documents\", @"\desktop\", @"\pictures\", @"\downloads\", @"\users\", @"\videos\", @"\music\"];

    private static readonly HashSet<string> KnownRansomExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".enc", ".crypt", ".crypted", ".odin", ".zepto", ".cerber", ".locky", ".wncry", ".wcry", ".micro",
    };

    private readonly RansomwareShieldOptions _options;
    private readonly TimeProvider _time;
    private readonly Func<string, double> _entropyProbe;
    private readonly object _sync = new();
    private readonly LinkedList<Observation> _window = new();
    private readonly Dictionary<string, long> _lastModified = new(StringComparer.OrdinalIgnoreCase);
    private long _lastAlertTicks = long.MinValue;

    public RansomwareBehaviorShield(RansomwareShieldOptions? options = null, TimeProvider? timeProvider = null, Func<string, double>? entropyProbe = null)
    {
        _options = options ?? new RansomwareShieldOptions();
        _time = timeProvider ?? TimeProvider.System;
        _entropyProbe = entropyProbe ?? SafeFileEntropy;
    }

    /// <summary>Техническая/кэш-папка, исключаемая из анализа всплесков (защита от ложных срабатываний на сборках).</summary>
    public static bool IsExcludedPath(string path)
    {
        var normalized = path.Replace('/', '\\').ToLowerInvariant();
        return ExcludedPathMarkers.Any(m => normalized.Contains(m, StringComparison.Ordinal));
    }

    /// <summary>
    /// Регистрирует файловое событие и возвращает тревогу, если накоплено достаточно признаков шифрования.
    /// <paramref name="oldPath"/> — прежний путь для <see cref="FileEventKind.Renamed"/>.
    /// </summary>
    public RansomwareAlert? Observe(FileEventKind kind, string path, string? oldPath = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (IsExcludedPath(path) || !IsInUserProfile(path))
        {
            return null;
        }

        var now = _time.GetUtcNow();
        lock (_sync)
        {
            if (kind == FileEventKind.Modified && IsDebounced(path, now))
            {
                return null;
            }

            Prune(now);

            double entropy = -1;
            if (kind is FileEventKind.Created or FileEventKind.Modified or FileEventKind.Renamed)
            {
                entropy = _entropyProbe(path);
            }

            var extensionChanged = kind == FileEventKind.Renamed && oldPath is not null
                && !string.Equals(Path.GetExtension(oldPath), Path.GetExtension(path), StringComparison.OrdinalIgnoreCase);

            _window.AddLast(new Observation(now.Ticks, Path.GetFullPath(path), Path.GetExtension(path), kind, entropy, extensionChanged));

            return Evaluate(now);
        }
    }

    private RansomwareAlert? Evaluate(DateTimeOffset now)
    {
        if (_lastAlertTicks != long.MinValue && now.Ticks - _lastAlertTicks < _options.AlertCooldown.Ticks)
        {
            return null;
        }

        var affected = _window.Select(o => o.Path).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var uniqueCount = affected.Length;
        var score = 0;
        var reasons = new List<string>();

        if (uniqueCount >= _options.BurstThreshold)
        {
            score += 30;
            reasons.Add($"всплеск изменений: {uniqueCount} файлов за {_options.Window.TotalSeconds:0} с");
        }

        var newExtGroups = _window
            .Where(o => o.Kind is FileEventKind.Created or FileEventKind.Renamed && !string.IsNullOrEmpty(o.Extension))
            .GroupBy(o => o.Extension, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var ransomExt = newExtGroups.FirstOrDefault(g => KnownRansomExtensions.Contains(g.Key));
        var uniformNewExt = newExtGroups.FirstOrDefault(g =>
            g.Count() >= 5 && g.Key.Length is >= 5 and <= 9 && g.Key.TrimStart('.').All(char.IsLetterOrDigit));
        if (ransomExt is not null || uniformNewExt is not null)
        {
            score += 25;
            reasons.Add($"единообразное шифровальное расширение '{(ransomExt ?? uniformNewExt)!.Key}'");
        }

        var highEntropy = _window.Count(o => o.Entropy >= _options.EntropyThreshold);
        var hadRemovalOrExtChange = _window.Any(o => o.Kind == FileEventKind.Deleted || o.ExtensionChanged);
        if (highEntropy >= _options.HighEntropyCount && hadRemovalOrExtChange)
        {
            score += 75;
            reasons.Add($"{highEntropy} перезаписей с энтропией ≥ {_options.EntropyThreshold:0.00} при удалении/смене расширения исходных файлов");
        }

        if (score < _options.AlertThreshold)
        {
            return null;
        }

        _lastAlertTicks = now.Ticks;
        return new RansomwareAlert(Math.Min(score, 100), string.Join("; ", reasons), affected);
    }

    /// <summary>Регистрирует вмешательство в файл-приманку (всегда достигает порога тревоги).</summary>
    public RansomwareAlert RegisterCanaryTamper(CanaryTamperEvent tamper)
    {
        ArgumentNullException.ThrowIfNull(tamper);
        lock (_sync)
        {
            _lastAlertTicks = _time.GetUtcNow().Ticks;
        }

        return new RansomwareAlert(CanaryFileGuard.TamperScore, $"Вмешательство в файл-приманку: {tamper.Reason}", [tamper.Path]);
    }

    private bool IsDebounced(string path, DateTimeOffset now)
    {
        var full = Path.GetFullPath(path);
        if (_lastModified.TryGetValue(full, out var last) && now.Ticks - last < _options.Debounce.Ticks)
        {
            return true;
        }

        _lastModified[full] = now.Ticks;
        return false;
    }

    private void Prune(DateTimeOffset now)
    {
        var cutoff = now.Ticks - _options.Window.Ticks;
        while (_window.First is { } node && node.Value.Ticks < cutoff)
        {
            _window.RemoveFirst();
        }

        if (_lastModified.Count > 4096)
        {
            foreach (var key in _lastModified.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToArray())
            {
                _lastModified.Remove(key);
            }
        }
    }

    private static bool IsInUserProfile(string path)
    {
        var normalized = path.Replace('/', '\\').ToLowerInvariant();
        return ProfileMarkers.Any(m => normalized.Contains(m, StringComparison.Ordinal));
    }

    private static double SafeFileEntropy(string path)
    {
        try
        {
            return EntropyCalculator.CalculateFile(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return -1;
        }
    }

    private readonly record struct Observation(long Ticks, string Path, string Extension, FileEventKind Kind, double Entropy, bool ExtensionChanged);
}
