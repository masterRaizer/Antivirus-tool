namespace Sentinel.Core.Auditors.Persistence;

/// <summary>Разбор командной строки: отделение исполняемого файла от аргументов и нормализация путей служб.</summary>
public static class CommandLineSplitter
{
    private static readonly string[] ExecutableExtensions =
        [".exe", ".sys", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".msc", ".scr", ".com"];

    /// <summary>
    /// Детерминированно делит командную строку на путь к бинарнику и аргументы.
    /// В кавычках — весь путь до закрывающей кавычки. Без кавычек — до первого известного
    /// исполняемого расширения включительно (воспроизводит разбор <c>CreateProcess</c>), иначе до первого пробела.
    /// </summary>
    public static (string Executable, string? Arguments) Split(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        var text = commandLine.Trim();
        if (text.Length == 0)
        {
            return (string.Empty, null);
        }

        if (text[0] == '"')
        {
            var end = text.IndexOf('"', 1);
            if (end < 0)
            {
                return (text[1..], null);
            }

            var exe = text[1..end];
            var rest = text[(end + 1)..].Trim();
            return (exe, rest.Length == 0 ? null : rest);
        }

        foreach (var ext in ExecutableExtensions)
        {
            var idx = text.IndexOf(ext + " ", StringComparison.OrdinalIgnoreCase);
            if (idx > 0)
            {
                var cut = idx + ext.Length;
                return (text[..cut], text[(cut + 1)..].Trim());
            }

            if (text.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
            {
                return (text, null);
            }
        }

        var space = text.IndexOf(' ', StringComparison.Ordinal);
        return space < 0 ? (text, null) : (text[..space], text[(space + 1)..].Trim());
    }

    /// <summary>
    /// Нормализует путь образа службы из реестра: раскрывает <c>\SystemRoot\</c>, снимает префикс <c>\??\</c>,
    /// достраивает <c>system32\</c> до полного пути. Возвращает путь к файлу без аргументов (через <see cref="Split"/>).
    /// </summary>
    public static string NormalizeServiceImagePath(string imagePath, string windowsRoot)
    {
        ArgumentNullException.ThrowIfNull(imagePath);
        ArgumentNullException.ThrowIfNull(windowsRoot);
        var (exe, _) = Split(imagePath);
        var path = exe.Trim();
        var root = windowsRoot.TrimEnd('\\', '/');

        if (path.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            path = path[4..];
        }

        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            path = root + "\\" + path[@"\SystemRoot\".Length..];
        }
        else if (path.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase))
        {
            path = root + path["%SystemRoot%".Length..];
        }
        else if (path.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)
                 || path.StartsWith(@"System32\", StringComparison.Ordinal))
        {
            path = root + "\\" + path;
        }
        else if (path.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase))
        {
            var drive = root.Length >= 2 && root[1] == ':' ? root[..2] : "C:";
            path = drive + path;
        }

        return path;
    }
}
