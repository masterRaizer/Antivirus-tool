namespace Sentinel.Core.Scanning;

/// <summary>
/// Самозащита и неприкосновенность ядра ОС: критические процессы и файлы Windows, а также каталоги самого
/// антивируса не изолируются и не завершаются ни при каких вердиктах.
/// </summary>
public static class SelfProtection
{
    private static readonly string[] ProtectedImageNames =
    [
        "csrss.exe", "smss.exe", "lsass.exe", "wininit.exe", "services.exe", "explorer.exe", "ntoskrnl.exe", "winload.efi",
        "winlogon.exe", "system", "registry", "memory compression",
    ];

    private static readonly string[] OwnImageNames = ["sentinel.app.exe", "sentinel.service.exe", "sentinel.cli.exe", "sentinel.exe"];

    // Сравнение строковое, в стиле Windows (без обращения к файловой системе): одинаково работает на любой ОС
    // и в сомнительных случаях защищает больше (регистр не различается).
    private const StringComparison PathComparison = StringComparison.OrdinalIgnoreCase;

    /// <summary>Каталоги Sentinel (программа и данные) плюс явно добавленные (например, каталог данных рантайма).</summary>
    public static IReadOnlyList<string> OwnDirectories(params string[] extra)
    {
        var list = new List<string>();
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrEmpty(programFiles))
        {
            list.Add(Path.Combine(programFiles, "Sentinel"));
        }

        if (!string.IsNullOrEmpty(programData))
        {
            list.Add(Path.Combine(programData, "Sentinel"));
        }

        list.Add(@"C:\Program Files\Sentinel");
        list.Add(@"C:\ProgramData\Sentinel");
        list.AddRange(extra.Where(e => !string.IsNullOrWhiteSpace(e)));
        return list.Select(Normalize).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>Образ процесса, который нельзя завершать (критический для ОС).</summary>
    public static bool IsProtectedImageName(string? imageName) =>
        !string.IsNullOrWhiteSpace(imageName)
        && ProtectedImageNames.Contains(FileNameOf(imageName), StringComparer.OrdinalIgnoreCase);

    /// <summary>Образ самого Sentinel.</summary>
    public static bool IsOwnImageName(string? imageName) =>
        !string.IsNullOrWhiteSpace(imageName)
        && OwnImageNames.Contains(FileNameOf(imageName), StringComparer.OrdinalIgnoreCase);

    /// <summary>Файл лежит в каталоге Sentinel или это критический файл Windows — изоляция и удаление запрещены.</summary>
    public static bool IsProtectedFile(string? path, params string[] extraOwnDirectories)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var name = FileNameOf(path);
        if (ProtectedImageNames.Contains(name, StringComparer.OrdinalIgnoreCase) && IsInSystemDirectory(path))
        {
            return true;
        }

        return IsInOwnDirectory(path, extraOwnDirectories);
    }

    public static bool IsInOwnDirectory(string path, params string[] extraOwnDirectories)
    {
        var full = Normalize(path);
        return OwnDirectories(extraOwnDirectories).Any(d => full.StartsWith(d + '\\', PathComparison)
            || string.Equals(full, d, PathComparison));
    }

    private static bool IsInSystemDirectory(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var full = Normalize(path);
        if (!string.IsNullOrEmpty(windows) && full.StartsWith(Normalize(windows) + '\\', PathComparison))
        {
            return true;
        }

        return full.Contains(@"\windows\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Имя файла с учётом обоих разделителей (на Linux <c>\</c> не разделитель, а пути Windows встречаются в данных).</summary>
    private static string FileNameOf(string path)
    {
        var normalized = path.Trim().Replace('/', '\\');
        return normalized[(normalized.LastIndexOf('\\') + 1)..];
    }

    private static string Normalize(string path) => path.Trim().Replace('/', '\\').TrimEnd('\\');
}
