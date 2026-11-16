using System.Text;

namespace Sentinel.Core.Audit.Process;

/// <summary>
/// Разбор командной строки Windows на аргументы по правилам CommandLineToArgvW
/// (кавычки, экранирование обратными слэшами перед кавычкой). Нужен, чтобы отделить
/// путь к исполняемому файлу от аргументов и анализировать флаги интерпретаторов.
/// </summary>
public static class CommandLineParser
{
    /// <summary>Разбивает командную строку на аргументы. Пустая строка даёт пустой список.</summary>
    public static IReadOnlyList<string> Split(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return [];
        }

        var args = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        var hasToken = false;
        var i = 0;
        var s = commandLine;

        while (i < s.Length)
        {
            var c = s[i];

            if (c == '\\')
            {
                // Подсчёт серии обратных слэшей: они экранируют кавычку только непосредственно перед ней.
                var backslashes = 0;
                while (i < s.Length && s[i] == '\\')
                {
                    backslashes++;
                    i++;
                }

                if (i < s.Length && s[i] == '"')
                {
                    current.Append('\\', backslashes / 2);
                    hasToken = true;
                    if (backslashes % 2 == 0)
                    {
                        inQuotes = !inQuotes;
                    }
                    else
                    {
                        current.Append('"');
                    }

                    i++;
                }
                else
                {
                    current.Append('\\', backslashes);
                    hasToken = true;
                }

                continue;
            }

            if (c == '"')
            {
                hasToken = true;
                // Двойная кавычка внутри кавычек означает литеральную кавычку.
                if (inQuotes && i + 1 < s.Length && s[i + 1] == '"')
                {
                    current.Append('"');
                    i += 2;
                    continue;
                }

                inQuotes = !inQuotes;
                i++;
                continue;
            }

            if (!inQuotes && (c == ' ' || c == '\t'))
            {
                if (hasToken)
                {
                    args.Add(current.ToString());
                    current.Clear();
                    hasToken = false;
                }

                i++;
                continue;
            }

            current.Append(c);
            hasToken = true;
            i++;
        }

        if (hasToken)
        {
            args.Add(current.ToString());
        }

        return args;
    }

    /// <summary>
    /// Извлекает путь к исполняемому файлу из командной строки (первый аргумент).
    /// Возвращает <c>null</c>, если строка пуста.
    /// </summary>
    public static string? ExtractExecutable(string? commandLine)
    {
        var args = Split(commandLine);
        return args.Count > 0 ? args[0] : null;
    }

    /// <summary>
    /// Исполняемый файл команды по правилам <c>CreateProcess</c>: путь в кавычках берётся как есть; путь без кавычек с пробелами
    /// проверяется слева направо по каждому пробелу (<c>C:\ProgramData\Microsoft\Windows</c> → нет файла,
    /// <c>C:\ProgramData\Microsoft\Windows Defender\Platform\…\MpCmdRun.exe</c> → есть), с подстановкой <c>.exe</c> без расширения.
    /// Если ни один вариант не существует (файл удалён, путь чужой машины) — прежнее поведение: первый токен.
    /// </summary>
    public static string? ResolveExecutable(string? commandLine, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        var text = commandLine?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        if (text[0] == '"')
        {
            return ExtractExecutable(text);
        }

        string? Existing(string candidate)
        {
            candidate = candidate.TrimEnd();
            if (candidate.Length == 0)
            {
                return null;
            }

            if (fileExists(candidate))
            {
                return candidate;
            }

            return !Path.HasExtension(candidate.Replace('\\', '/')) && fileExists(candidate + ".exe") ? candidate + ".exe" : null;
        }

        for (var space = text.IndexOf(' '); space > 0; space = text.IndexOf(' ', space + 1))
        {
            if (Existing(text[..space]) is { } found)
            {
                return found;
            }
        }

        return Existing(text) ?? FirstExecutablePrefix(text) ?? ExtractExecutable(text);
    }

    private static readonly string[] ExecutableExtensions = [".exe", ".sys", ".dll", ".com", ".scr", ".bat", ".cmd", ".ps1"];

    /// <summary>
    /// Файла нет (временный драйвер Защитника <c>MpKslDrv.sys</c> в удалённой папке <c>Definition Updates\{GUID}</c>, удалённая
    /// программа): путь без кавычек берётся до первого слова с расширением исполняемого файла, а не до первого пробела —
    /// иначе «C:\ProgramData\Microsoft\Windows Defender\…» превращался в «C:\ProgramData\Microsoft\Windows».
    /// </summary>
    private static string? FirstExecutablePrefix(string text)
    {
        for (var space = text.IndexOf(' '); ; space = text.IndexOf(' ', space + 1))
        {
            var candidate = (space < 0 ? text : text[..space]).TrimEnd();
            if (candidate.IndexOfAny(['\\', '/']) >= 0
                && ExecutableExtensions.Any(e => candidate.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
            {
                return candidate;
            }

            if (space < 0)
            {
                return null;
            }
        }
    }

    /// <summary>Аргументы без первого (исполняемого файла).</summary>
    public static IReadOnlyList<string> Arguments(string? commandLine)
    {
        var args = Split(commandLine);
        return args.Count <= 1 ? [] : args.Skip(1).ToArray();
    }
}
