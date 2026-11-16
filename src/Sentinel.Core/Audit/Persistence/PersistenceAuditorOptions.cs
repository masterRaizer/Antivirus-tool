namespace Sentinel.Core.Audit.Persistence;

/// <summary>Параметры аудита персистентности. Каталоги инъектируются ради тестируемости на Linux.</summary>
public sealed record PersistenceAuditorOptions
{
    public string WindowsDirectory { get; init; } = DefaultWindows();

    /// <summary>Каталоги, где расположение бинарника считается штатным (System32, Program Files и т.п.).</summary>
    public IReadOnlyList<string> TrustedBinaryDirectories { get; init; } = [];

    /// <summary>Каталоги автозагрузки (Startup) для проверки.</summary>
    public IReadOnlyList<string> StartupDirectories { get; init; } = [];

    /// <summary>Путь к файлу hosts (или null, чтобы не проверять).</summary>
    public string? HostsFilePath { get; init; }

    /// <summary>Ожидаемое значение Winlogon\Shell.</summary>
    public string DefaultShell { get; init; } = "explorer.exe";

    /// <summary>
    /// Чувствительные домены (обновления, защита, антивирусные вендоры): их перенаправление
    /// в hosts особенно подозрительно (блокировка обновлений/защиты).
    /// </summary>
    public IReadOnlyList<string> SecuritySensitiveHosts { get; init; } =
    [
        "windowsupdate.com", "update.microsoft.com", "windowsdefender", "download.microsoft.com",
        "wdcp.microsoft.com", "wdcpalt.microsoft.com", "smartscreen.microsoft.com",
        "clamav", "avast", "avg", "kaspersky", "mcafee", "symantec", "norton",
        "bitdefender", "eset", "sophos", "malwarebytes", "virustotal.com", "drweb",
    ];

    /// <summary>Пользовательский список разрешённого (<c>allowed_exclusions.json</c>): цели из него не считаются подозрительными.</summary>
    public Func<string, bool>? IsUserAllowed { get; init; }

    /// <summary>Анализировать целевые файлы через FileAnalyzer (подпись, правила, энтропия).</summary>
    public bool AnalyzeTargets { get; init; } = true;

    /// <summary>Проверка существования файла при разборе команд без кавычек (в тестах — синтетическая файловая система).</summary>
    public Func<string, bool> FileExists { get; init; } = File.Exists;

    private static string DefaultWindows()
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return string.IsNullOrEmpty(win) ? @"C:\Windows" : win;
    }

    /// <summary>Значения по умолчанию для Windows (System32/SysWOW64, Program Files, папки Startup).</summary>
    public static PersistenceAuditorOptions CreateDefault()
    {
        var win = DefaultWindows();
        var system32 = Path.Combine(win, "System32");
        var sysWow64 = Path.Combine(win, "SysWOW64");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var trusted = new List<string> { system32, sysWow64, Path.Combine(win, "WinSxS") };
        if (!string.IsNullOrEmpty(programFiles))
        {
            trusted.Add(programFiles);
        }

        if (!string.IsNullOrEmpty(programFilesX86))
        {
            trusted.Add(programFilesX86);
        }

        // Платформа и обновления определений Защитника Windows: запись только для SYSTEM/TrustedInstaller, хотя это ProgramData.
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrEmpty(programData))
        {
            trusted.Add(Path.Combine(programData, "Microsoft", "Windows Defender", "Platform"));
            trusted.Add(Path.Combine(programData, "Microsoft", "Windows Defender", "Definition Updates"));
        }

        var startup = new List<string>();
        var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (!string.IsNullOrEmpty(userStartup))
        {
            startup.Add(userStartup);
        }

        if (!string.IsNullOrEmpty(commonStartup))
        {
            startup.Add(commonStartup);
        }

        return new PersistenceAuditorOptions
        {
            WindowsDirectory = win,
            TrustedBinaryDirectories = trusted,
            StartupDirectories = startup,
            HostsFilePath = Path.Combine(system32, "drivers", "etc", "hosts"),
        };
    }
}
