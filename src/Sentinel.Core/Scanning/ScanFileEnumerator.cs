using Sentinel.Core.Runtime;

namespace Sentinel.Core.Scanning;

/// <summary>Режим отбора файлов при обходе.</summary>
public enum EnumerationMode
{
    /// <summary>Только исполняемые, скриптовые, библиотечные и пакетные форматы; кэши браузеров и Electron пропускаются.</summary>
    Quick,

    /// <summary>Все файлы локальных дисков.</summary>
    Full,

    /// <summary>Все файлы выбранного каталога или съёмного диска.</summary>
    Custom,
}

/// <summary>
/// Обход каталогов для проверки. Точки повторного разбора NTFS (junction и символические ссылки: <c>All Users</c>,
/// <c>Application Data</c>, <c>Local Settings</c>) не пересекаются — это исключает бесконечную рекурсию и дубли путей.
/// Каталоги Sentinel и недоступные каталоги пропускаются.
/// </summary>
public static class ScanFileEnumerator
{
    /// <summary>Расширения быстрой проверки (в нижнем регистре, с точкой).</summary>
    public static readonly IReadOnlySet<string> QuickExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi", ".msix", ".bat", ".cmd", ".ps1", ".psm1",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".pyw",
    };

    /// <summary>Каталоги кэшей браузеров и Electron-приложений: огромное число мелких файлов, исполняемого кода там нет.</summary>
    public static readonly IReadOnlySet<string> SkippedDirectoryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Cache", "Code Cache", "GPUCache", "DawnCache", "ShaderCache", "GrShaderCache", "IndexedDB", "Service Worker", "Crashpad",
    };

    public static bool IsQuickCandidate(string path) => QuickExtensions.Contains(Path.GetExtension(path));

    public static IEnumerable<string> Enumerate(IEnumerable<ScanRoot> roots, EnumerationMode mode, IEnumerable<string>? excludedDirectories = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(roots);
        var excluded = (excludedDirectories ?? []).Select(NormalizeDirectory).ToArray();
        var seenRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(root.Path))
            {
                if (Accepts(root.Path, mode) || mode == EnumerationMode.Custom)
                {
                    yield return root.Path;
                }

                continue;
            }

            if (!Directory.Exists(root.Path) || !seenRoots.Add(NormalizeDirectory(root.Path)))
            {
                continue;
            }

            // Корень, сам являющийся точкой повторного разбора, пользователь выбрал явно — его обходим, но внутрь не заходим по ссылкам.
            foreach (var file in Walk(new DirectoryInfo(root.Path), root.MaxDepth, mode, excluded, cancellationToken))
            {
                yield return file;
            }
        }
    }

    private static IEnumerable<string> Walk(DirectoryInfo start, int maxDepth, EnumerationMode mode, string[] excluded, CancellationToken token)
    {
        var stack = new Stack<(DirectoryInfo Dir, int Depth)>();
        stack.Push((start, 0));
        while (stack.Count > 0)
        {
            token.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();
            FileInfo[] files;
            DirectoryInfo[] subdirectories;
            try
            {
                files = dir.GetFiles();
                subdirectories = depth < maxDepth ? dir.GetDirectories() : [];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                continue;
            }

            foreach (var file in files)
            {
                // Файловые ссылки не разыменовываются: проверяется содержимое самого пути, а не произвольной цели.
                if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                if (Accepts(file.FullName, mode))
                {
                    yield return file.FullName;
                }
            }

            foreach (var sub in subdirectories)
            {
                if ((sub.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                if (mode == EnumerationMode.Quick && SkippedDirectoryNames.Contains(sub.Name))
                {
                    continue;
                }

                if (IsExcluded(sub.FullName, excluded))
                {
                    continue;
                }

                stack.Push((sub, depth + 1));
            }
        }
    }

    private static bool Accepts(string path, EnumerationMode mode) => mode != EnumerationMode.Quick || IsQuickCandidate(path);

    private static bool IsExcluded(string directory, string[] excluded)
    {
        var full = NormalizeDirectory(directory);
        return excluded.Any(e => string.Equals(full, e, StringComparison.OrdinalIgnoreCase)
            || full.StartsWith(e + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
}
