namespace Sentinel.Core.Auditors.Persistence;

/// <summary>Результат проверки на уязвимость Unquoted Service Path.</summary>
public sealed record UnquotedServicePathResult(string ImagePath, IReadOnlyList<string> HijackPaths)
{
    /// <summary>Рекомендация пользователю: заключить путь службы в кавычки.</summary>
    public string Recommendation =>
        $"Путь службы не заключён в кавычки и содержит пробелы. Злоумышленник с правом записи может подложить "
        + $"{string.Join(" или ", HijackPaths)} и перехватить запуск. Заключите ImagePath в кавычки.";
}

/// <summary>
/// Детектор уязвимости Unquoted Service Path. Если путь автозапускаемой службы не в кавычках, не лежит в
/// <c>System32</c> и содержит пробел, Windows при старте пробует запускать усечённые варианты пути —
/// например, для <c>C:\Program Files\Sub Dir\svc.exe</c> сначала <c>C:\Program.exe</c>, затем <c>C:\Program Files\Sub.exe</c>.
/// </summary>
public static class UnquotedServicePathDetector
{
    public static UnquotedServicePathResult? Detect(RawServiceRecord service, string windowsRoot)
    {
        ArgumentNullException.ThrowIfNull(service);
        if (!service.IsAutoStart || string.IsNullOrWhiteSpace(service.ImagePath))
        {
            return null;
        }

        var raw = service.ImagePath.Trim();
        if (raw.StartsWith('"') || raw.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            return null; // путь в кавычках или драйверный \??\ — не подвержен
        }

        var (executable, _) = CommandLineSplitter.Split(raw);
        executable = executable.Trim();

        // Относительные/системные пути (system32\...) Windows ищет в известных каталогах — не уязвимы.
        if (executable.Length < 3 || executable[1] != ':')
        {
            return null;
        }

        var normalized = CommandLineSplitter.NormalizeServiceImagePath(raw, windowsRoot);
        var system32 = (windowsRoot.TrimEnd('\\', '/') + @"\system32\").ToLowerInvariant();
        if (normalized.ToLowerInvariant().StartsWith(system32, StringComparison.Ordinal))
        {
            return null;
        }

        if (!executable.Contains(' ', StringComparison.Ordinal))
        {
            return null;
        }

        var hijacks = new List<string>();
        var builder = new System.Text.StringBuilder();
        for (var i = 0; i < executable.Length; i++)
        {
            if (executable[i] == ' ')
            {
                var prefix = builder.ToString();
                if (prefix.Length > 3)
                {
                    hijacks.Add(prefix + ".exe");
                }
            }

            builder.Append(executable[i]);
        }

        return hijacks.Count == 0 ? null : new UnquotedServicePathResult(raw, hijacks);
    }
}
