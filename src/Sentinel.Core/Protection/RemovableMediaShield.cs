using Sentinel.Core.Signatures;

namespace Sentinel.Core.Protection;

/// <summary>Находка USB-щита на съёмном носителе.</summary>
public sealed record UsbFinding(string Kind, Severity Severity, string Path, string Description);

/// <summary>Подключённый съёмный том.</summary>
public sealed record RemovableVolume(string RootPath, string? Label, string? FileSystem, long? TotalBytes);

/// <summary>Наблюдатель за подключением съёмных носителей.</summary>
public interface IRemovableDriveWatcher
{
    /// <summary>Текущие готовые съёмные тома.</summary>
    IReadOnlyList<RemovableVolume> GetRemovableVolumes();
}

/// <summary>
/// USB-щит: детекторы угроз съёмных носителей, работающие без WMI (пригодны в Безопасном режиме и WinRE).
/// Обходит корень и подкаталоги до глубины 2 с обязательным пропуском <see cref="FileAttributes.ReparsePoint"/>.
/// Четыре детектора: <c>autorun.inf</c>, классический USB-червь (скрытая папка + одноимённый исполняемый/ярлык),
/// вредоносные <c>.lnk</c> ([MS-SHLLINK]) и потоковая проверка бинарников инъектируемым анализатором.
/// </summary>
public sealed class RemovableMediaShield
{
    private const int MaxDepth = 2;

    private static readonly string[] ExecutableExtensions =
        [".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".dll", ".sys", ".vbs", ".js", ".hta", ".ps1", ".jar"];

    private static readonly string[] MasqueradeInnerExtensions =
        [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".txt", ".rtf"];

    private static readonly string[] MaliciousLnkTargets =
        ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"];

    private static readonly string[] SpoofedIconLibraries = ["shell32.dll", "imageres.dll"];

    private readonly Func<string, Severity?>? _binaryScan;

    /// <param name="binaryScan">Проверка бинарника по пути (через <c>FileAnalyzer</c>), возвращает уровень угрозы или <c>null</c>.</param>
    public RemovableMediaShield(Func<string, Severity?>? binaryScan = null) => _binaryScan = binaryScan;

    /// <summary>Сканирует съёмный том или произвольную папку и возвращает находки.</summary>
    public IReadOnlyList<UsbFinding> ScanDirectory(string root)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);
        var findings = new List<UsbFinding>();
        if (!Directory.Exists(root))
        {
            return findings;
        }

        ScanAutorun(root, findings);

        foreach (var directory in EnumerateDirectories(root))
        {
            DirectoryInfo[] subdirs;
            FileInfo[] files;
            try
            {
                var info = new DirectoryInfo(directory);
                subdirs = info.GetDirectories();
                files = info.GetFiles();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            DetectHiddenFolderWorm(subdirs, files, findings);

            foreach (var file in files)
            {
                if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                InspectFile(file, findings);
            }
        }

        return findings;
    }

    private void InspectFile(FileInfo file, List<UsbFinding> findings)
    {
        var ext = file.Extension.ToLowerInvariant();

        if (IsDoubleExtension(file.Name))
        {
            findings.Add(new UsbFinding("DoubleExtension", Severity.High, file.FullName,
                $"Двойное расширение маскирует исполняемый файл под документ: {file.Name}."));
        }

        if (ext == ".lnk")
        {
            InspectShortcut(file, findings);
        }

        if (_binaryScan is not null && ExecutableExtensions.Contains(ext))
        {
            try
            {
                if (_binaryScan(file.FullName) is { } severity && severity >= Severity.Medium)
                {
                    findings.Add(new UsbFinding("MaliciousBinary", severity, file.FullName,
                        $"Исполняемый файл на носителе определён как угроза ({severity})."));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // файл недоступен — пропускаем
            }
        }
    }

    private static void InspectShortcut(FileInfo file, List<UsbFinding> findings)
    {
        ShellLinkDetails? link;
        try
        {
            link = ShellLinkBinaryParser.ParseFile(file.FullName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        if (link is null)
        {
            return;
        }

        var target = (link.TargetPath ?? link.RelativePath ?? string.Empty).ToLowerInvariant();
        var targetName = target.Replace('/', '\\');
        targetName = targetName[(targetName.LastIndexOf('\\') + 1)..];
        var args = link.Arguments ?? string.Empty;
        var hitsInterpreter = MaliciousLnkTargets.Contains(targetName);
        var iconSpoof = link.IconLocation is { } icon && SpoofedIconLibraries.Any(l => icon.Contains(l, StringComparison.OrdinalIgnoreCase));

        if (hitsInterpreter)
        {
            var severity = iconSpoof ? Severity.Critical : Severity.High;
            findings.Add(new UsbFinding("WeaponizedShortcut", severity, file.FullName,
                $"Ярлык '{file.Name}' запускает интерпретатор {targetName} {args}".Trim()
                + (iconSpoof ? " и маскируется под папку/документ (подмена значка)." : ".")));
        }
        else if (link.Arguments is { Length: > 0 } && ContainsFilelessMarker(args))
        {
            findings.Add(new UsbFinding("WeaponizedShortcut", Severity.High, file.FullName,
                $"Ярлык '{file.Name}' содержит обфусцированную команду: {args}"));
        }
    }

    private static void DetectHiddenFolderWorm(DirectoryInfo[] subdirs, FileInfo[] files, List<UsbFinding> findings)
    {
        var hidden = subdirs
            .Where(d => (d.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0
                        && (d.Attributes & FileAttributes.ReparsePoint) == 0)
            .Select(d => d.Name)
            .ToArray();
        var lures = files
            .Where(f => (f.Attributes & FileAttributes.ReparsePoint) == 0)
            .Select(f => f.Name)
            .ToArray();
        foreach (var lure in DetectWorm(hidden, lures))
        {
            var full = files.First(f => string.Equals(f.Name, lure, StringComparison.OrdinalIgnoreCase)).FullName;
            findings.Add(new UsbFinding("UsbWorm", Severity.Critical, full,
                $"Классический USB-червь: исполняемый файл '{lure}' дублирует имя скрытой папки — пользователь запускает вирус вместо своей папки."));
        }
    }

    /// <summary>
    /// Чистая логика детекта USB-червя: исполняемый файл/ярлык, чьё имя совпадает с именем скрытой папки
    /// (в том числе через двойное расширение <c>&lt;Папка&gt;.pdf.exe</c>). Выделена для тестирования без атрибутов ОС.
    /// </summary>
    internal static IReadOnlyList<string> DetectWorm(IReadOnlyList<string> hiddenFolderNames, IReadOnlyList<string> fileNames)
    {
        var hidden = hiddenFolderNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var matches = new List<string>();
        if (hidden.Count == 0)
        {
            return matches;
        }

        foreach (var name in fileNames)
        {
            var ext = Path.GetExtension(name).ToLowerInvariant();
            var isLureExtension = ext is ".exe" or ".scr" or ".com" or ".pif" or ".lnk";
            var baseName = Path.GetFileNameWithoutExtension(name);
            var matchesHidden = hidden.Contains(baseName) || hidden.Any(h => name.StartsWith(h + ".", StringComparison.OrdinalIgnoreCase));
            if (isLureExtension && matchesHidden)
            {
                matches.Add(name);
            }
        }

        return matches;
    }

    private void ScanAutorun(string root, List<UsbFinding> findings)
    {
        var autorun = Path.Combine(root, "autorun.inf");
        if (!File.Exists(autorun))
        {
            return;
        }

        AutorunInfo info;
        try
        {
            info = AutorunInfParser.ParseFile(autorun);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        if (info.HasExecutableDirective)
        {
            findings.Add(new UsbFinding("Autorun", Severity.High, autorun,
                $"autorun.inf задаёт автозапуск: {string.Join(", ", info.Targets)}."));

            foreach (var target in info.Targets)
            {
                var full = Path.Combine(root, target.Replace('/', '\\').TrimStart('\\'));
                if (File.Exists(full) && _binaryScan is not null)
                {
                    try
                    {
                        if (_binaryScan(full) is { } severity && severity >= Severity.Medium)
                        {
                            findings.Add(new UsbFinding("AutorunTarget", severity, full,
                                $"Цель автозапуска autorun.inf определена как угроза ({severity})."));
                        }
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // недоступно
                    }
                }
            }
        }
    }

    internal static bool IsDoubleExtension(string fileName)
    {
        var name = fileName.ToLowerInvariant();
        var lastDot = name.LastIndexOf('.');
        if (lastDot <= 0 || !ExecutableExtensions.Contains(name[lastDot..]))
        {
            return false;
        }

        var inner = name[..lastDot];
        var innerDot = inner.LastIndexOf('.');
        if (innerDot <= 0)
        {
            return false;
        }

        var innerExt = inner[innerDot..];
        // Либо известное документарное расширение, либо маскировка пробелами (document.pdf      .exe).
        return MasqueradeInnerExtensions.Contains(innerExt) || fileName.Contains("  ", StringComparison.Ordinal);
    }

    private static bool ContainsFilelessMarker(string value)
    {
        var lower = value.ToLowerInvariant();
        return lower.Contains("-enc", StringComparison.Ordinal) || lower.Contains("frombase64string", StringComparison.Ordinal)
            || lower.Contains("downloadstring", StringComparison.Ordinal) || lower.Contains("iex", StringComparison.Ordinal)
            || lower.Contains("http://", StringComparison.Ordinal) || lower.Contains("https://", StringComparison.Ordinal);
    }

    /// <summary>Каталоги корня и его подкаталоги до глубины 2, без пересечения точек повторного разбора.</summary>
    private static IEnumerable<string> EnumerateDirectories(string root)
    {
        yield return root;
        var stack = new Stack<(string Path, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            var (current, depth) = stack.Pop();
            if (depth >= MaxDepth)
            {
                continue;
            }

            DirectoryInfo[] subdirs;
            try
            {
                subdirs = new DirectoryInfo(current).GetDirectories();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var sub in subdirs)
            {
                if ((sub.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                yield return sub.FullName;
                stack.Push((sub.FullName, depth + 1));
            }
        }
    }
}

/// <summary>
/// Наблюдатель съёмных носителей через периодический опрос <see cref="DriveInfo.GetDrives"/> (без WMI — работает в Safe Mode/WinRE).
/// Перечисление дисков инъектируется, что позволяет тестировать логику появления новых томов на Linux.
/// </summary>
public sealed class PollingRemovableDriveWatcher : IRemovableDriveWatcher
{
    private readonly Func<IReadOnlyList<RemovableVolume>> _enumerate;

    public PollingRemovableDriveWatcher(Func<IReadOnlyList<RemovableVolume>>? enumerate = null) =>
        _enumerate = enumerate ?? EnumerateSystemRemovableVolumes;

    public IReadOnlyList<RemovableVolume> GetRemovableVolumes() => _enumerate();

    /// <summary>Новые тома по сравнению с предыдущим снимком (для фонового цикла опроса раз в 2 секунды).</summary>
    public IReadOnlyList<RemovableVolume> DiffNew(ISet<string> knownRoots)
    {
        ArgumentNullException.ThrowIfNull(knownRoots);
        var current = GetRemovableVolumes();
        var fresh = current.Where(v => knownRoots.Add(v.RootPath)).ToArray();
        return fresh;
    }

    private static RemovableVolume[] EnumerateSystemRemovableVolumes()
    {
        try
        {
            return DriveInfo.GetDrives()
                .Where(d => d is { DriveType: DriveType.Removable, IsReady: true })
                .Select(d => new RemovableVolume(d.RootDirectory.FullName, SafeLabel(d), SafeFileSystem(d), SafeSize(d)))
                .ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static string? SafeLabel(DriveInfo d)
    {
        try { return d.VolumeLabel; } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static string? SafeFileSystem(DriveInfo d)
    {
        try { return d.DriveFormat; } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static long? SafeSize(DriveInfo d)
    {
        try { return d.TotalSize; } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }
}
