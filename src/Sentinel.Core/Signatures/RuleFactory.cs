using System.Text.RegularExpressions;

namespace Sentinel.Core.Signatures;

internal static partial class RuleFactory
{
    [GeneratedRegex("^[0-9a-fA-F]{64}$")]
    private static partial Regex Sha256Regex();

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex NameRegex();

    public static Severity ParseSeverity(string value, int line) =>
        Enum.TryParse<Severity>(value, ignoreCase: true, out var s) && Enum.IsDefined(s)
            ? s
            : throw new RuleFormatException($"Неизвестный уровень severity: '{value}'.", line);

    public static string NormalizeSha256(string value, int line)
    {
        var v = value.Trim();
        return Sha256Regex().IsMatch(v)
            ? v.ToLowerInvariant()
            : throw new RuleFormatException($"Некорректный SHA-256: '{value}'.", line);
    }

    public static void ValidateName(string name, int line)
    {
        if (!NameRegex().IsMatch(name))
        {
            throw new RuleFormatException($"Некорректное имя правила: '{name}'.", line);
        }
    }

    public static SignatureRule Build(
        string id,
        string name,
        string description,
        Severity severity,
        string category,
        IReadOnlyList<string> tags,
        IReadOnlyList<BytePattern> patterns,
        IReadOnlySet<string> sha256,
        Condition? condition,
        string sourceFile,
        int line,
        IReadOnlyList<string>? appliesTo = null,
        IReadOnlyList<string>? excludeFileNames = null)
    {
        ValidateName(name, line);
        if (string.IsNullOrWhiteSpace(id))
        {
            throw new RuleFormatException($"Правило {name}: пустой id.", line);
        }

        var defined = patterns.Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
        if (condition is not null)
        {
            foreach (var reference in condition.ReferencedPatterns())
            {
                if (!defined.Contains(reference))
                {
                    throw new RuleFormatException($"Правило {name}: условие ссылается на неопределённую строку {reference}.", line);
                }
            }
        }

        if (condition is null && sha256.Count == 0)
        {
            throw new RuleFormatException($"Правило {name}: нет ни условия, ни хешей SHA-256.", line);
        }

        return new SignatureRule
        {
            Id = id,
            Name = name,
            Description = description,
            Severity = severity,
            Category = string.IsNullOrWhiteSpace(category) ? "generic" : category,
            Tags = tags,
            Patterns = patterns,
            Sha256 = sha256,
            Condition = condition,
            SourceFile = sourceFile,
            AppliesTo = appliesTo ?? [],
            ExcludeFileNames = excludeFileNames ?? [],
        };
    }
}
