using System.Globalization;
using System.Text;

namespace Sentinel.Core.Audit.Process;

/// <summary>
/// Свёртка «обманчивых» символов (homoglyphs) к латинскому ASCII-скелету.
/// Используется для выявления подмены имён системных процессов визуально похожими
/// символами (кириллица, греческий, похожие цифры), например <c>lsаss.exe</c> с
/// кириллической «а» или <c>explorer</c> → <c>exp1orer</c>.
/// </summary>
public static class ConfusableFolder
{
    // Сопоставление «похожий символ → канонический латинский». Регистр приводится заранее.
    // Покрыты наиболее частые кириллические и греческие омоглифы плюс цифры-двойники.
    private static readonly Dictionary<char, char> Map = new()
    {
        // Кириллица (строчная), визуально совпадающая с латиницей
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['с'] = 'c', ['р'] = 'p', ['х'] = 'x',
        ['у'] = 'y', ['к'] = 'k', ['м'] = 'm', ['н'] = 'h', ['т'] = 't', ['в'] = 'b',
        ['і'] = 'i', ['ј'] = 'j', ['ѕ'] = 's', ['ԁ'] = 'd', ['ԛ'] = 'q', ['ԝ'] = 'w',
        ['ё'] = 'e', ['ѐ'] = 'e',
        // Греческие
        ['α'] = 'a', ['ο'] = 'o', ['ρ'] = 'p', ['ϲ'] = 'c', ['υ'] = 'u', ['ν'] = 'v',
        ['κ'] = 'k', ['τ'] = 't', ['ι'] = 'i', ['β'] = 'b',
        // Цифры-двойники букв (типичные подмены в именах процессов)
        ['0'] = 'o', ['1'] = 'l', ['3'] = 'e', ['5'] = 's',
        // Полноширинные латинские буквы (U+FF21..)
        ['ｅ'] = 'e', ['ｏ'] = 'o', ['ａ'] = 'a',
    };

    /// <summary>
    /// Приводит строку к нижнему регистру и сворачивает обманчивые символы к латинскому скелету.
    /// Возвращает также признак того, что при свёртке были заменены не-ASCII или цифровые символы.
    /// </summary>
    public static FoldResult Fold(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var lower = value.ToLowerInvariant();
        var sb = new StringBuilder(lower.Length);
        var substituted = false;
        var hasNonAscii = false;

        foreach (var ch in lower)
        {
            if (ch > 0x7F)
            {
                hasNonAscii = true;
            }

            if (Map.TryGetValue(ch, out var mapped))
            {
                sb.Append(mapped);
                if (mapped != ch)
                {
                    substituted = true;
                }
            }
            else
            {
                sb.Append(ch);
            }
        }

        return new FoldResult(lower, sb.ToString(), substituted, hasNonAscii);
    }

    /// <summary>
    /// Содержит ли строка символы вне базового латинского диапазона (кириллица, греческий и т.п.).
    /// Для имён штатных системных процессов такие символы недопустимы.
    /// </summary>
    public static bool ContainsNonLatinLetters(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        foreach (var ch in value)
        {
            if (!char.IsLetter(ch))
            {
                continue;
            }

            if (ch > 0x7F)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Является ли символ «обманчивым» (есть в таблице свёртки и отличается от своей проекции).</summary>
    internal static bool IsConfusable(char ch)
    {
        var lower = char.ToLowerInvariant(ch);
        return Map.TryGetValue(lower, out var mapped) && mapped != lower;
    }
}

/// <summary>Результат свёртки обманчивых символов.</summary>
public sealed record FoldResult(string Lowered, string Skeleton, bool Substituted, bool HasNonAscii)
{
    /// <summary>Свёрнутая форма отличается от исходной нижне-регистровой — были подмены.</summary>
    public bool Changed => Substituted || !string.Equals(Lowered, Skeleton, StringComparison.Ordinal);
}
