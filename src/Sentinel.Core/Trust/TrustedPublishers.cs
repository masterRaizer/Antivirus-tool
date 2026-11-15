namespace Sentinel.Core.Trust;

/// <summary>
/// Издатели ПО, подпись которых (действительная, проверенная WinVerifyTrust) снижает уровень предупреждений
/// «файл в пользовательском каталоге»: обычные программы вроде Chrome, Discord, Spotify или Ollama ставятся в профиль пользователя.
/// Значение сопоставляется с полями <c>O=</c> и <c>CN=</c> подписанта целиком, а не по подстроке.
/// Подпись неизвестного издателя (например, подписанные драйверы случайных поставщиков в Temp) доверия не даёт.
/// </summary>
public static class TrustedPublishers
{
    private static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Windows Hardware Compatibility Publisher",
        "Microsoft Code Signing PCA", "Google LLC", "Google Inc", "Discord Inc.", "Spotify AB", "Opera Norway AS", "Opera Software AS",
        "Ollama Inc.", "Mozilla Corporation", "Brave Software, Inc.", "NVIDIA Corporation", "Intel Corporation", "Advanced Micro Devices, Inc.",
        "Logitech Inc", "Valve Corp.", "Dropbox, Inc.", "Zoom Video Communications, Inc.", "Slack Technologies, Inc.", "JetBrains s.r.o.",
        "GitHub, Inc.", "Adobe Inc.", "Apple Inc.", "Oracle America, Inc.", "Telegram FZ-LLC", "Mojang AB", "Notepad++",
    };

    /// <summary>Подписант (<c>CN=…, O=…</c>) входит в список доверенных издателей.</summary>
    public static bool IsTrusted(string? signerSubject)
    {
        if (string.IsNullOrWhiteSpace(signerSubject))
        {
            return false;
        }

        foreach (var part in SplitSubject(signerSubject))
        {
            var eq = part.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                continue;
            }

            var key = part[..eq].Trim();
            if ((key.Equals("O", StringComparison.OrdinalIgnoreCase) || key.Equals("CN", StringComparison.OrdinalIgnoreCase))
                && Names.Contains(part[(eq + 1)..].Trim().Trim('"')))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Подпись файла действительна и принадлежит доверенному издателю.</summary>
    public static bool IsTrusted(SignatureVerificationResult? signature) => signature is { IsValid: true } && IsTrusted(signature.SignerSubject);

    /// <summary>Делит субъект по запятым вне кавычек (<c>O="DigiCert, Inc."</c>).</summary>
    private static IEnumerable<string> SplitSubject(string subject)
    {
        var start = 0;
        var quoted = false;
        for (var i = 0; i < subject.Length; i++)
        {
            if (subject[i] == '"')
            {
                quoted = !quoted;
            }
            else if (subject[i] == ',' && !quoted)
            {
                yield return subject[start..i];
                start = i + 1;
            }
        }

        yield return subject[start..];
    }
}
