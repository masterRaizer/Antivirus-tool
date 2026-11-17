namespace Sentinel.Core.Signatures;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum PatternKind
{
    Text,
    Hex,
}

/// <summary>
/// Байтовый шаблон с маской: для каждого байта <see cref="Mask"/> задаёт значимые биты
/// (0xFF — точное совпадение, 0x00 — "??", 0xF0/0x0F — полубайтовые маски "4?"/"?A").
/// </summary>
public sealed class BytePattern
{
    public BytePattern(string id, PatternKind kind, byte[] bytes, byte[] mask, bool noCase, string source)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(mask);
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Шаблон не может быть пустым.", nameof(bytes));
        }

        if (bytes.Length != mask.Length)
        {
            throw new ArgumentException("Длины шаблона и маски различаются.", nameof(mask));
        }

        if (noCase)
        {
            bytes = Array.ConvertAll(bytes, PatternMatcher.ToLowerAscii);
        }

        Id = id;
        Kind = kind;
        Bytes = bytes;
        Mask = mask;
        NoCase = noCase;
        Source = source;
        IsExact = !noCase && Array.TrueForAll(mask, m => m == 0xFF);
    }

    public string Id { get; }
    public PatternKind Kind { get; }
    public byte[] Bytes { get; }
    public byte[] Mask { get; }
    public bool NoCase { get; }
    public string Source { get; }
    public bool IsExact { get; }
    public int Length => Bytes.Length;
}

/// <summary>
/// Правило сигнатуры. Один идентификатор строки ($a) может иметь несколько байтовых
/// вариантов (например, ascii и wide) — строка считается найденной, если найден любой вариант.
/// </summary>
public sealed class SignatureRule
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string Description { get; init; } = string.Empty;
    public Severity Severity { get; init; } = Severity.Medium;
    public string Category { get; init; } = "generic";
    public IReadOnlyList<string> Tags { get; init; } = [];
    public IReadOnlyList<BytePattern> Patterns { get; init; } = [];
    public IReadOnlySet<string> Sha256 { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public Condition? Condition { get; init; }
    public required string SourceFile { get; init; }

    /// <summary>
    /// Типы файлов, к которым применимо правило: <c>executable</c>, <c>script</c>, <c>config</c>. Пусто — к любым.
    /// PE-файл (по содержимому) считается исполняемым независимо от расширения.
    /// </summary>
    public IReadOnlyList<string> AppliesTo { get; init; } = [];

    /// <summary>Имена файлов, на которые правило не срабатывает (например, базы <c>geosite.dat</c> и <c>geoip.dat</c>).</summary>
    public IReadOnlyList<string> ExcludeFileNames { get; init; } = [];

    /// <summary>Подходит ли правило данному файлу.</summary>
    public bool Applies(ScanTarget? target)
    {
        if (target is null)
        {
            return true;
        }

        // Строковые индикаторы (адрес пула, кошелёк, URL загрузчика) в истории браузера, кэше мессенджера или журнале
        // ассистента — это упоминание угрозы, а не сама угроза: пользователь искал её в интернете или обсуждал.
        // Хеш-правила и PE-файлы проверяются везде.
        if (!target.IsPe && Patterns.Count > 0 && ScanTarget.IsUserDataStore(target.Path))
        {
            return false;
        }

        if (AppliesTo.Count == 0 && ExcludeFileNames.Count == 0)
        {
            return true;
        }

        var name = System.IO.Path.GetFileName(target.Path.Replace('\\', '/'));
        if (ExcludeFileNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        if (AppliesTo.Count == 0)
        {
            return true;
        }

        if (target.IsPe && AppliesTo.Contains("executable", StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        var extension = System.IO.Path.GetExtension(name);
        if (AppliesTo.Contains("config", StringComparer.OrdinalIgnoreCase) && ScanTarget.IsRandomDropName(name))
        {
            return true; // «cneicjnb.gkn»: случайное имя, которым сбрасывают конфигурации и полезную нагрузку
        }

        return AppliesTo.Any(kind => ScanTarget.ExtensionsFor(kind).Contains(extension));
    }
}

public sealed record RuleLoadError(string File, int Line, string Message)
{
    public override string ToString() => Line > 0 ? $"{File}({Line}): {Message}" : $"{File}: {Message}";
}

public sealed record PatternHit(string PatternId, long Offset);

public sealed record SignatureMatch(
    string RuleId,
    string RuleName,
    Severity Severity,
    string Category,
    string Description,
    IReadOnlyList<PatternHit> Hits,
    bool MatchedByHash,
    string SourceFile);

public sealed class RuleSet
{
    public RuleSet(IReadOnlyList<SignatureRule> rules, IReadOnlyList<RuleLoadError> errors)
    {
        Rules = rules;
        Errors = errors;
    }

    public static RuleSet Empty { get; } = new([], []);

    public IReadOnlyList<SignatureRule> Rules { get; }
    public IReadOnlyList<RuleLoadError> Errors { get; }
}

public sealed class RuleFormatException : Exception
{
    public RuleFormatException(string message, int line = 0)
        : base(message)
    {
        Line = line;
    }

    public RuleFormatException()
    {
    }

    public RuleFormatException(string message)
        : base(message)
    {
    }

    public RuleFormatException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public int Line { get; }
}

/// <summary>Файл, который проверяется правилами: путь и признак PE (по заголовку).</summary>
public sealed record ScanTarget(string Path, bool IsPe)
{
    private static readonly HashSet<string> Executable = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi", ".msix", ".jar", ".elf", ".so", ".bin",
    };

    private static readonly HashSet<string> Script = new(StringComparer.OrdinalIgnoreCase)
    {
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".pyw", ".sh", ".lnk",
    };

    private static readonly HashSet<string> Config = new(StringComparer.OrdinalIgnoreCase)
    {
        ".json", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".xml", ".txt", ".config", ".env", ".properties", "",
    };

    /// <summary>Каталоги хранилищ данных браузеров, мессенджеров и ассистентов (кэш, история, сессии, журналы диалогов).</summary>
    private static readonly string[] DataStoreDirectories =
    [
        @"\cache\cache_data\", @"\code cache\", @"\gpucache\", @"\dawncache\", @"\grshadercache\", @"\shadercache\",
        @"\service worker\cachestorage\", @"\service worker\scriptcache\", @"\indexeddb\", @"\local storage\leveldb\",
        @"\session storage\",
        @"\mozilla\firefox\profiles\", @"\cache2\entries\", @"\telegram desktop\tdata\",
        @"\.claude\projects\", @"\.claude\file-history\", @"\.claude\todos\", @"\.claude\shell-snapshots\",
    ];

    /// <summary>Базы профиля Chromium (Chrome, Edge, Яндекс, Opera, Brave): история, подсказки адресной строки, значки сайтов.</summary>
    private static readonly HashSet<string> ChromiumProfileStores = new(StringComparer.OrdinalIgnoreCase)
    {
        "History", "History-journal", "Favicons", "Favicons-journal", "Shortcuts", "Shortcuts-journal",
        "Network Action Predictor", "Network Action Predictor-journal", "Top Sites", "Top Sites-journal", "Visited Links",
        "Web Data", "Web Data-journal", "Login Data", "Login Data-journal", "Login Data For Account", "Cookies", "Cookies-journal",
        "Media History", "Media History-journal", "Current Session", "Current Tabs", "Last Session", "Last Tabs", "DIPS",
        "DIPS-journal", "Affiliation Database", "Preferences", "Secure Preferences", "Bookmarks", "Bookmarks.bak",
        "Network Persistent State", "TransportSecurity", "Reporting and NEL", "Trust Tokens", "History Provider Cache",
    };

    /// <summary>
    /// Файл — хранилище данных пользовательской программы (история и кэш браузера, кэш мессенджера, журнал диалогов
    /// ассистента), а не исполняемый код и не конфигурация. Строковые индикаторы угроз в таких файлах — упоминания.
    /// </summary>
    public static bool IsUserDataStore(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        var p = path.Replace('/', '\\');
        foreach (var dir in DataStoreDirectories)
        {
            if (p.Contains(dir, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return p.Contains(@"\User Data\", StringComparison.OrdinalIgnoreCase)
            && ChromiumProfileStores.Contains(System.IO.Path.GetFileName(p.Replace('\\', '/')));
    }

    /// <summary>
    /// Имя вида <c>cneicjnb.gkn</c> — ровно 8 строчных букв или цифр, точка и ещё 3: так выглядит результат
    /// <c>Path.GetRandomFileName()</c>, которым загрузчики и майнеры называют сброшенные конфигурации и копии.
    /// </summary>
    public static bool IsRandomDropName(string fileName)
    {
        if (fileName.Length != 12 || fileName[8] != '.')
        {
            return false;
        }

        for (var i = 0; i < fileName.Length; i++)
        {
            if (i != 8 && !(char.IsAsciiLetterLower(fileName[i]) || char.IsAsciiDigit(fileName[i])))
            {
                return false;
            }
        }

        return true;
    }

    internal static IReadOnlySet<string> ExtensionsFor(string kind) => kind.ToLowerInvariant() switch
    {
        "executable" => Executable,
        "script" => Script,
        "config" => Config,
        _ => new HashSet<string>(),
    };
}
