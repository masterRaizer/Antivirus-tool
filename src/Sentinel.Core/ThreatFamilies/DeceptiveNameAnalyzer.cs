using System.Globalization;
using System.Text;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Trust;

namespace Sentinel.Core.ThreatFamilies;

/// <summary>Вид обмана в имени.</summary>
public enum DeceptiveNameKind
{
    /// <summary>Подмена похожих символов: «lnspection» (l вместо I), «Micr0soft» (0 вместо O), «HeIper» (I вместо l).</summary>
    Homoglyph,

    /// <summary>В одном слове смешаны латиница и кириллица/греческий («Windоws» с кириллической «о»).</summary>
    MixedScript,
}

/// <summary>Результат проверки имени: что подделано и под какое слово.</summary>
public sealed record DeceptiveNameResult(DeceptiveNameKind Kind, string Word, string Imitates)
{
    public string Describe() => Kind == DeceptiveNameKind.MixedScript
        ? $"в слове «{Word}» смешаны латиница и кириллица/греческий (имитирует «{Imitates}»)"
        : $"слово «{Word}» имитирует «{Imitates}» за счёт похожих символов (l/I, 0/O, 1/l)";
}

/// <summary>
/// Детектор обманчивых имён файлов, процессов, задач и правил брандмауэра. Работает по словарю слов, из которых
/// составляют имена компонентов Windows («Microsoft», «Network», «Inspection», «Service»…): слово подозрительно,
/// если само в словаре не встречается, а после замены похожих символов (l↔I, 0→O, 1→l, кириллица → латиница)
/// совпадает со словарным. Обычные имена программ и слова, которых нет в словаре, не помечаются.
/// </summary>
public static class DeceptiveNameAnalyzer
{
    private const int MinWordLength = 4;
    private const int MaxAmbiguousPositions = 6;

    private static readonly HashSet<string> Dictionary = new(StringComparer.Ordinal)
    {
        "microsoft", "windows", "service", "services", "svchost", "host", "update", "updater", "updates", "defender",
        "security", "network", "networking", "realtime", "inspection", "runtime", "broker", "system", "explorer",
        "office", "edge", "telemetry", "helper", "manager", "driver", "intel", "nvidia", "google", "chrome", "firefox",
        "lsass", "csrss", "winlogon", "wininit", "discovery", "router", "solicitation", "core", "antimalware",
        "protection", "platform", "framework", "installer", "kernel", "monitor", "health", "client", "agent",
        "scheduler", "application", "desktop", "display", "audio", "graphics", "search", "indexer", "shell",
        "experience", "identity", "licensing", "activation", "policy", "firewall", "remote", "management",
        "instrumentation", "diagnostics", "diagnostic", "realtek", "launcher", "local", "console", "process",
        "spooler", "print", "defrag", "cleanup", "assistant", "persistent", "click", "telemetryagent",
    };

    /// <summary>Проверяет имя (файла, процесса, задачи, правила). <c>null</c> — признаков подмены нет.</summary>
    public static DeceptiveNameResult? Analyze(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        foreach (var word in SplitWords(StripExtension(name)))
        {
            if (word.Length < MinWordLength)
            {
                continue;
            }

            var hasLatin = word.Any(IsLatinLetter);
            var hasOtherScript = word.Any(c => char.IsLetter(c) && c > 0x7F && !IsLatinLetter(c));
            if (hasLatin && hasOtherScript)
            {
                return new DeceptiveNameResult(DeceptiveNameKind.MixedScript, word, ConfusableFolder.Fold(word).Skeleton);
            }

            var lowered = word.ToLowerInvariant();
            if (Dictionary.Contains(lowered))
            {
                continue;
            }

            if (Imitation(word) is { } imitated)
            {
                return new DeceptiveNameResult(DeceptiveNameKind.Homoglyph, word, imitated);
            }
        }

        return null;
    }

    /// <summary>Имя выдаёт себя за компонент Microsoft/Windows («Microsoft …», «Windows …», в том числе с подменой символов).</summary>
    public static bool ClaimsMicrosoftName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        foreach (var word in SplitWords(StripExtension(name)))
        {
            var lowered = word.ToLowerInvariant();
            var skeleton = ConfusableFolder.Fold(word).Skeleton;
            if (lowered is "microsoft" or "windows" || skeleton is "microsoft" or "windows" || Imitation(word) is "microsoft" or "windows")
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Действительная подпись Microsoft (O=Microsoft Corporation или CN=Microsoft Windows…).</summary>
    public static bool IsMicrosoftSigned(SignatureVerificationResult? signature) =>
        signature is { IsValid: true, SignerSubject: { } subject }
        && (subject.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
            || subject.Contains("CN=Microsoft", StringComparison.OrdinalIgnoreCase));

    /// <summary>Словарное слово, которое имитирует <paramref name="word"/>, или <c>null</c>.</summary>
    private static string? Imitation(string word)
    {
        // Кириллица, греческий, полноширинные буквы и цифры-двойники → латинский скелет.
        var skeleton = ConfusableFolder.Fold(word).Skeleton;
        if (!string.Equals(skeleton, word.ToLowerInvariant(), StringComparison.Ordinal) && Dictionary.Contains(skeleton))
        {
            return skeleton;
        }

        // l ↔ I: в нижнем регистре это l ↔ i. Перебираются все сочетания неоднозначных позиций.
        var lowered = word.ToLowerInvariant();
        var positions = new List<int>();
        for (var i = 0; i < lowered.Length; i++)
        {
            if (lowered[i] is 'l' or 'i' or '1')
            {
                positions.Add(i);
            }
        }

        if (positions.Count == 0 || positions.Count > MaxAmbiguousPositions)
        {
            return null;
        }

        var buffer = lowered.Replace('0', 'o').ToCharArray();
        for (var mask = 0; mask < 1 << positions.Count; mask++)
        {
            for (var p = 0; p < positions.Count; p++)
            {
                buffer[positions[p]] = (mask & (1 << p)) != 0 ? 'i' : 'l';
            }

            var candidate = new string(buffer);
            if (!string.Equals(candidate, lowered, StringComparison.Ordinal) && Dictionary.Contains(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string StripExtension(string name)
    {
        var trimmed = name.Trim().Trim('"');
        var slash = trimmed.LastIndexOfAny(['\\', '/']);
        if (slash >= 0)
        {
            trimmed = trimmed[(slash + 1)..];
        }

        var dot = trimmed.LastIndexOf('.');
        return dot > 0 && trimmed.Length - dot <= 5 ? trimmed[..dot] : trimmed;
    }

    /// <summary>Слова имени: разделители — всё, кроме букв и цифр.</summary>
    private static IEnumerable<string> SplitWords(string value)
    {
        var sb = new StringBuilder();
        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch))
            {
                sb.Append(ch);
            }
            else if (sb.Length > 0)
            {
                yield return sb.ToString();
                sb.Clear();
            }
        }

        if (sb.Length > 0)
        {
            yield return sb.ToString();
        }
    }

    private static bool IsLatinLetter(char c) =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z'
        || (c is >= 'À' and <= 'ɏ' && CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.LowercaseLetter or UnicodeCategory.UppercaseLetter);
}
