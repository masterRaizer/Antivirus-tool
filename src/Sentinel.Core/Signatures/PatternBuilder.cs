using System.Globalization;

namespace Sentinel.Core.Signatures;

/// <summary>Построение байтовых шаблонов из текстовых и hex-строк правил.</summary>
public static class PatternBuilder
{
    /// <summary>
    /// Hex-строка: пары символов из [0-9A-Fa-f?], разделённые пробелами или нет:
    /// "4D 5A ?? 00 4?". Переходы [n-m] и альтернативы (A|B) не поддерживаются и вызывают ошибку.
    /// </summary>
    public static BytePattern FromHex(string id, string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var digits = new List<char>(hex.Length);
        foreach (var c in hex)
        {
            if (char.IsWhiteSpace(c))
            {
                continue;
            }

            if (char.IsAsciiHexDigit(c) || c == '?')
            {
                digits.Add(c);
                continue;
            }

            throw new RuleFormatException(c is '[' or '(' or '|' or '~'
                ? $"Конструкция '{c}' в hex-строке {id} не поддерживается."
                : $"Недопустимый символ '{c}' в hex-строке {id}.");
        }

        if (digits.Count == 0 || digits.Count % 2 != 0)
        {
            throw new RuleFormatException($"Hex-строка {id} должна содержать целое число байт.");
        }

        var bytes = new byte[digits.Count / 2];
        var mask = new byte[bytes.Length];
        for (var i = 0; i < bytes.Length; i++)
        {
            var hi = digits[i * 2];
            var lo = digits[(i * 2) + 1];
            byte value = 0;
            byte m = 0;
            if (hi != '?')
            {
                value |= (byte)(HexValue(hi) << 4);
                m |= 0xF0;
            }

            if (lo != '?')
            {
                value |= HexValue(lo);
                m |= 0x0F;
            }

            bytes[i] = value;
            mask[i] = m;
        }

        if (Array.TrueForAll(mask, x => x == 0))
        {
            throw new RuleFormatException($"Hex-строка {id} состоит только из масок '??'.");
        }

        return new BytePattern(id, PatternKind.Hex, bytes, mask, noCase: false, source: hex.Trim());
    }

    /// <summary>
    /// Текстовая строка. Возвращает 1–2 варианта: ascii (по умолчанию) и/или wide (UTF-16LE).
    /// </summary>
    public static IReadOnlyList<BytePattern> FromText(string id, byte[] utf8, string display, bool noCase, bool ascii, bool wide)
    {
        ArgumentNullException.ThrowIfNull(utf8);
        if (utf8.Length == 0)
        {
            throw new RuleFormatException($"Строка {id} пуста.");
        }

        if (!ascii && !wide)
        {
            ascii = true;
        }

        var result = new List<BytePattern>(2);
        if (ascii)
        {
            result.Add(new BytePattern(id, PatternKind.Text, utf8, Full(utf8.Length), noCase, display));
        }

        if (wide)
        {
            // Семантика YARA: каждый байт строки дополняется нулевым байтом.
            var w = new byte[utf8.Length * 2];
            for (var i = 0; i < utf8.Length; i++)
            {
                w[i * 2] = utf8[i];
            }

            result.Add(new BytePattern(id, PatternKind.Text, w, Full(w.Length), noCase, display));
        }

        return result;
    }

    private static byte[] Full(int n)
    {
        var m = new byte[n];
        Array.Fill(m, (byte)0xFF);
        return m;
    }

    private static byte HexValue(char c) => byte.Parse(c.ToString(), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
}
