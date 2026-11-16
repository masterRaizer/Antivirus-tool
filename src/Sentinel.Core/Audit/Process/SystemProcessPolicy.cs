namespace Sentinel.Core.Audit.Process;

/// <summary>
/// Политика штатного расположения известных системных процессов Windows.
/// Для каждого имени задаётся множество допустимых каталогов; процесс с системным
/// именем, запущенный из другого каталога, — сильный индикатор маскировки.
/// Каталоги инъектируются, поэтому логика тестируется на Linux с произвольным «windows root».
/// </summary>
public sealed class SystemProcessPolicy
{
    private readonly Dictionary<string, string[]> _allowedByName;

    public SystemProcessPolicy(IReadOnlyDictionary<string, IReadOnlyList<string>> allowedByName)
    {
        ArgumentNullException.ThrowIfNull(allowedByName);
        _allowedByName = allowedByName.ToDictionary(
            kv => kv.Key.ToLowerInvariant(),
            kv => kv.Value.Select(NormalizeDir).ToArray(),
            StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyCollection<string> KnownNames => _allowedByName.Keys;

    /// <summary>Является ли имя (с расширением) именем известного системного процесса.</summary>
    public bool IsKnownSystemName(string name) =>
        !string.IsNullOrEmpty(name) && _allowedByName.ContainsKey(name.ToLowerInvariant());

    /// <summary>
    /// Находится ли исполняемый файл известного системного процесса в штатном каталоге.
    /// Возвращает <c>null</c>, если имя не системное либо путь неизвестен/непригоден для проверки.
    /// </summary>
    public bool? IsInAllowedLocation(string name, string? executablePath)
    {
        if (string.IsNullOrEmpty(name) || !_allowedByName.TryGetValue(name.ToLowerInvariant(), out var dirs))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return null;
        }

        // \SystemRoot\System32\conhost.exe и \??\C:\… из телеметрии ядра сравниваются как C:\Windows\System32.
        var dir = GetDirectory(Kernel.NtPath.ToWin32(executablePath));
        if (dir is null)
        {
            return null;
        }

        return dirs.Any(d => string.Equals(d, dir, StringComparison.OrdinalIgnoreCase));
    }

    public IReadOnlyList<string> AllowedDirectories(string name) =>
        _allowedByName.TryGetValue(name.ToLowerInvariant(), out var dirs) ? dirs : [];

    /// <summary>
    /// Нормализует каталог платформонезависимо: унифицирует разделители к '\' и убирает хвостовой.
    /// Не вызывает <see cref="Path.GetFullPath(string)"/>, чтобы Windows-пути корректно
    /// сравнивались и при прогоне тестов на Linux.
    /// </summary>
    private static string NormalizeDir(string dir) =>
        dir.Replace('/', '\\').TrimEnd('\\');

    /// <summary>Каталог Windows-пути: часть до последнего разделителя ('\' или '/'). null — разделителя нет.</summary>
    private static string? GetDirectory(string path)
    {
        var idx = path.LastIndexOfAny(['\\', '/']);
        return idx <= 0 ? null : NormalizeDir(path[..idx]);
    }

    /// <summary>
    /// Политика по умолчанию для Windows. Большинство ключевых процессов обязано
    /// находиться в System32/SysWOW64, а <c>explorer.exe</c> — в корне каталога Windows.
    /// </summary>
    public static SystemProcessPolicy CreateDefault(string? windowsDirectory = null)
    {
        var win = windowsDirectory
            ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(win))
        {
            win = @"C:\Windows";
        }

        var system32 = Path.Combine(win, "System32");
        var sysWow64 = Path.Combine(win, "SysWOW64");
        string[] sys = [system32, sysWow64];

        var map = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["smss.exe"] = sys,
            ["csrss.exe"] = sys,
            ["wininit.exe"] = sys,
            ["winlogon.exe"] = sys,
            ["services.exe"] = sys,
            ["lsass.exe"] = sys,
            ["lsaiso.exe"] = sys,
            ["svchost.exe"] = sys,
            ["dwm.exe"] = sys,
            ["taskhostw.exe"] = sys,
            ["spoolsv.exe"] = sys,
            ["conhost.exe"] = sys,
            ["fontdrvhost.exe"] = sys,
            ["sihost.exe"] = sys,
            ["ctfmon.exe"] = sys,
            ["runtimebroker.exe"] = sys,
            ["searchindexer.exe"] = sys,
            ["dllhost.exe"] = sys,
            ["explorer.exe"] = [win],
        };

        return new SystemProcessPolicy(map);
    }
}
