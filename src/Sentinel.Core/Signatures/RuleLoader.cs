namespace Sentinel.Core.Signatures;

/// <summary>
/// Загрузка правил из каталога (по умолчанию rules/). Поддерживаемые расширения:
/// .json — JSON-правила; .yar, .yara, .rule — YARA-подобные текстовые правила.
/// Ошибочный файл не прерывает загрузку остальных: ошибки собираются в <see cref="RuleSet.Errors"/>.
/// </summary>
public static class RuleLoader
{
    public const long MaxRuleFileSize = 4L * 1024 * 1024;

    private static readonly string[] YaraExtensions = [".yar", ".yara", ".rule"];

    public static RuleSet LoadDirectory(string directory, bool recursive = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        if (!Directory.Exists(directory))
        {
            return new RuleSet([], [new RuleLoadError(directory, 0, "Каталог правил не найден.")]);
        }

        var files = Directory
            .EnumerateFiles(directory, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Where(IsRuleFile)
            .OrderBy(f => f, StringComparer.Ordinal);

        return LoadFiles(files);
    }

    public static RuleSet LoadFiles(IEnumerable<string> files)
    {
        ArgumentNullException.ThrowIfNull(files);
        var rules = new List<SignatureRule>();
        var errors = new List<RuleLoadError>();
        var seenIds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            IReadOnlyList<SignatureRule> parsed;
            try
            {
                var info = new FileInfo(file);
                if (info.Length > MaxRuleFileSize)
                {
                    errors.Add(new RuleLoadError(file, 0, $"Файл правил больше {MaxRuleFileSize} байт."));
                    continue;
                }

                parsed = ParseText(File.ReadAllText(file), file);
            }
            catch (RuleFormatException ex)
            {
                errors.Add(new RuleLoadError(file, ex.Line, ex.Message));
                continue;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add(new RuleLoadError(file, 0, $"Ошибка чтения: {ex.Message}"));
                continue;
            }

            foreach (var rule in parsed)
            {
                if (seenIds.TryGetValue(rule.Id, out var other))
                {
                    errors.Add(new RuleLoadError(file, 0, $"Дублирующийся id правила '{rule.Id}' (уже определён в {other})."));
                    continue;
                }

                seenIds[rule.Id] = file;
                rules.Add(rule);
            }
        }

        return new RuleSet(rules, errors);
    }

    public static IReadOnlyList<SignatureRule> ParseText(string text, string sourceFile)
    {
        var ext = Path.GetExtension(sourceFile);
        if (string.Equals(ext, ".json", StringComparison.OrdinalIgnoreCase))
        {
            return JsonRuleParser.Parse(text, sourceFile);
        }

        if (YaraExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
        {
            return YaraLikeRuleParser.Parse(text, sourceFile);
        }

        throw new RuleFormatException($"Неподдерживаемое расширение файла правил '{ext}'.");
    }

    private static bool IsRuleFile(string path)
    {
        var ext = Path.GetExtension(path);
        return string.Equals(ext, ".json", StringComparison.OrdinalIgnoreCase)
            || YaraExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
    }
}
