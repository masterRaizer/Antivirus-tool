namespace Sentinel.Core.ThreatFamilies;

/// <summary>
/// Описание семейства угроз: только индикаторы (хеши, имена, сетевые адреса) и метаданные — без образцов.
/// Подробный разбор — <c>docs/THREAT_FAMILIES.md</c>.
/// </summary>
public sealed record ThreatFamily
{
    public required string Id { get; init; }

    /// <summary>Имя для отчётов и сообщений пользователю.</summary>
    public required string Name { get; init; }

    /// <summary>Вектор заражения (пиратский софт, поддельный установщик) — сообщается пользователю прямо.</summary>
    public required string Vector { get; init; }

    /// <summary>Известные SHA-256 (нижний регистр) с ролью файла.</summary>
    public IReadOnlyDictionary<string, string> Hashes { get; init; } = new Dictionary<string, string>();

    /// <summary>Каталоги семейства под <c>%ProgramData%</c> (только имя папки).</summary>
    public IReadOnlyList<string> ProgramDataFolders { get; init; } = [];

    /// <summary>Имена значений Run, которые создаёт семейство.</summary>
    public IReadOnlyList<string> RunValueNames { get; init; } = [];

    /// <summary>Пути задач планировщика семейства.</summary>
    public IReadOnlyList<string> TaskPaths { get; init; } = [];

    public IReadOnlyList<string> Domains { get; init; } = [];

    public IReadOnlyList<string> IpAddresses { get; init; } = [];

    /// <summary>Порт, который слушает бэкдор загрузчика (0 — нет).</summary>
    public int BackdoorPort { get; init; }

    /// <summary>Детекты других антивирусов — для сообщения пользователю.</summary>
    public IReadOnlyList<string> KnownDetections { get; init; } = [];

    /// <summary>Ключи удаления поддельного установщика-носителя.</summary>
    public IReadOnlyList<string> UninstallKeys { get; init; } = [];
}

/// <summary>Сопоставление индикатора с семейством.</summary>
public sealed record FamilyIndicatorMatch(ThreatFamily Family, string Indicator, string Role);

/// <summary>
/// Встроенный каталог семейств, найденных на компьютерах пользователя (CAAService/Pearl и загрузчик techias),
/// и общие сетевые признаки майнинга (порты пулов). Хеши дублируют <c>rules/families.json</c>: правила ловят файлы
/// при сканировании, каталог — процессы, соединения и закрепление при аудите.
/// </summary>
public static class ThreatFamilyCatalog
{
    /// <summary>Типичные порты stratum-пулов (7048 — Kryptex/Pearl).</summary>
    public static IReadOnlySet<int> PoolPorts { get; } = new HashSet<int> { 3333, 4444, 5555, 7048, 14444 };

    public static ThreatFamily CaaService { get; } = new()
    {
        Id = "CAAService",
        Name = "Майнер CAAService (ботнет Pearl/pearlhash)",
        Vector = "поддельный установщик «Hiddify 2.5.7» (C:\\Program Files\\Hiddify) — программа скачана не с официального сайта",
        Hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["bfd086e44cfe11d63271f2e5959969d435750403a340c675688219db43b62376"] = "загрузчик CAAServices.exe",
            ["81fe4c33e7e899ca992b21f0aad310f29062df6a4221a5f9e6a07cd1f82b9477"] = "загрузчик CAAServices.exe (старый вариант)",
            ["1a58995232c96501a8c17139db5404527d9ec0b57863ae03605dd477e181ffdf"] = "GPU-майнер «Microsoft Network Realtime lnspection Service.exe»",
            ["4b9f7ae1213d93bc3de0330e84e42b8c29687e693d11de6d39da5c4c0ac4c495"] = "конфигурация CAAServices.vdr",
        },
        ProgramDataFolders = ["CAAService"],
        RunValueNames = ["CAA Service"],
        Domains = ["prl-ru.kryptex.network"],
        IpAddresses = ["155.212.215.227", "43.174.218.73", "95.37.216.178"],
        BackdoorPort = 24424,
        KnownDetections = ["Trojan.Win64.Miner.lvfp", "not-a-virus:RiskTool.Win32.BitCoinMiner.ozuc"],
        UninstallKeys = ["6L903538-42B1-4596-G479-BJ779F21A65D_is1"],
    };

    public static ThreatFamily Techias { get; } = new()
    {
        Id = "techias",
        Name = "Загрузчик из пиратского активатора Office (techias)",
        Vector = "пиратский активатор Microsoft Office (activate.techias.co.uk)",
        Hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["613dd576ff9f6b44e958e1f7df34123b1ded45aff7063577af83665d2483a32d"] = "загрузчик WinAIHService.exe (VersionInfo «WinNetService»)",
        },
        ProgramDataFolders = ["WinAIHService"],
        RunValueNames = ["Win AIH Service"],
        TaskPaths = [@"\Microsoft\Office\Office Persistent Activation"],
        Domains = ["activate.techias.co.uk"],
    };

    public static IReadOnlyList<ThreatFamily> All { get; } = [CaaService, Techias];

    /// <summary>Кошельки и строки конфигурации, однозначно указывающие на семейство.</summary>
    public static IReadOnlyList<(string Token, ThreatFamily Family)> ConfigTokens { get; } =
    [
        ("prl1p5hgdn92f0h2zt0qaemc6f8zdx5u28fvkpmvzhaehm6xwqgtez7dsqert43", CaaService),
        ("prl-ru.kryptex.network", CaaService),
        ("activate.techias.co.uk", Techias),
    ];

    public static FamilyIndicatorMatch? MatchHash(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256))
        {
            return null;
        }

        foreach (var family in All)
        {
            if (family.Hashes.TryGetValue(sha256.Trim(), out var role))
            {
                return new FamilyIndicatorMatch(family, sha256.Trim().ToLowerInvariant(), role);
            }
        }

        return null;
    }

    public static FamilyIndicatorMatch? MatchIp(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return null;
        }

        var normalized = NormalizeIp(address);
        foreach (var family in All)
        {
            if (family.IpAddresses.Contains(normalized, StringComparer.Ordinal))
            {
                return new FamilyIndicatorMatch(family, normalized, "сетевой узел семейства");
            }
        }

        return null;
    }

    /// <summary>Домен семейства в строке (командная строка, XML задачи, URL).</summary>
    public static FamilyIndicatorMatch? MatchText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        foreach (var (token, family) in ConfigTokens)
        {
            if (text.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return new FamilyIndicatorMatch(family, token, "строка конфигурации/загрузки семейства");
            }
        }

        return null;
    }

    public static FamilyIndicatorMatch? MatchRunValue(string? valueName) => MatchName(valueName, f => f.RunValueNames, "значение Run семейства");

    public static FamilyIndicatorMatch? MatchTaskPath(string? taskPath) => MatchName(
        taskPath is null ? null : "\\" + taskPath.TrimStart('\\'), f => f.TaskPaths, "задача планировщика семейства");

    /// <summary>Путь лежит в каталоге семейства под ProgramData (<c>…\ProgramData\CAAService\…</c>).</summary>
    public static FamilyIndicatorMatch? MatchPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var norm = path.Replace('/', '\\');
        foreach (var family in All)
        {
            foreach (var folder in family.ProgramDataFolders)
            {
                if (norm.Contains(@"\ProgramData\" + folder + @"\", StringComparison.OrdinalIgnoreCase)
                    || norm.EndsWith(@"\ProgramData\" + folder, StringComparison.OrdinalIgnoreCase))
                {
                    return new FamilyIndicatorMatch(family, folder, "каталог семейства в ProgramData");
                }
            }
        }

        return null;
    }

    /// <summary>IPv4-mapped IPv6 (<c>::ffff:1.2.3.4</c>) сводится к IPv4.</summary>
    internal static string NormalizeIp(string address)
    {
        var trimmed = address.Trim();
        return trimmed.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? trimmed[7..] : trimmed;
    }

    private static FamilyIndicatorMatch? MatchName(string? value, Func<ThreatFamily, IReadOnlyList<string>> selector, string role)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        foreach (var family in All)
        {
            var hit = selector(family).FirstOrDefault(n => string.Equals(n, value.Trim(), StringComparison.OrdinalIgnoreCase));
            if (hit is not null)
            {
                return new FamilyIndicatorMatch(family, hit, role);
            }
        }

        return null;
    }
}
