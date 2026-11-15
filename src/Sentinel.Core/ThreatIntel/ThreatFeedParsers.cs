using System.Text.RegularExpressions;

namespace Sentinel.Core.ThreatIntel;

/// <summary>Разбор публичных фидов индикаторов: только валидные SHA-256, без MD5/SHA-1, нулевых и «пустых» хешей.</summary>
public static partial class ThreatFeedParsers
{
    public const string EmptyFileSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    [GeneratedRegex("(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")]
    private static partial Regex Sha256Regex();

    [GeneratedRegex(@"^\s*hash\d*\s*=\s*""([0-9a-fA-F]{64})""", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex YaraMetaHashRegex();

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$")]
    private static partial Regex Ipv4Regex();

    /// <summary>Нормализует строку до 64 hex-символов нижнего регистра; нулевой и пустой хеши отбрасываются.</summary>
    public static bool TryNormalizeSha256(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (value is null)
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.Length != 64 || !trimmed.All(Uri.IsHexDigit))
        {
            return false;
        }

        var lower = trimmed.ToLowerInvariant();
        if (lower.All(c => c == '0') || lower == EmptyFileSha256)
        {
            return false;
        }

        normalized = lower;
        return true;
    }

    /// <summary>Все SHA-256 в произвольном тексте (README, IOC, JSON, CSV).</summary>
    public static IEnumerable<string> ExtractSha256(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        foreach (Match m in Sha256Regex().Matches(text))
        {
            if (TryNormalizeSha256(m.Value, out var hash))
            {
                yield return hash;
            }
        }
    }

    /// <summary>Файл <c>hash-iocs.txt</c> Neo23x0/signature-base: строки <c>хеш;описание</c>, комментарии <c>#</c>.</summary>
    public static IEnumerable<ThreatHashEntry> ParseSignatureBaseHashIocs(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            var separator = line.IndexOf(';', StringComparison.Ordinal);
            var hash = separator < 0 ? line : line[..separator];
            if (!TryNormalizeSha256(hash, out var normalized))
            {
                continue;
            }

            var description = separator < 0 ? string.Empty : line[(separator + 1)..].Trim();
            yield return new ThreatHashEntry(normalized, FamilyFromDescription(description));
        }
    }

    /// <summary>Хеши из мета-полей <c>hash = "…"</c> правил YARA (ссылки на реальные образцы); условия правил не затрагиваются.</summary>
    public static IEnumerable<ThreatHashEntry> ParseYaraMetaHashes(string yaraText, string family)
    {
        ArgumentNullException.ThrowIfNull(yaraText);
        foreach (Match m in YaraMetaHashRegex().Matches(yaraText))
        {
            if (TryNormalizeSha256(m.Groups[1].Value, out var hash))
            {
                yield return new ThreatHashEntry(hash, family);
            }
        }
    }

    /// <summary>Любой текст со списком хешей (например, <c>samples.sha256</c> ESET): семейство задаётся вызывающей стороной.</summary>
    public static IEnumerable<ThreatHashEntry> ParseHashList(string text, string family) =>
        ExtractSha256(text).Select(h => new ThreatHashEntry(h, family));

    /// <summary>Ответ MalwareBazaar <c>mb-api</c>: <c>{"query_status":"ok","data":[{"sha256_hash":"…","signature":"…"}]}</c>.</summary>
    public static IEnumerable<ThreatHashEntry> ParseMalwareBazaarJson(string json)
    {
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != System.Text.Json.JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var item in data.EnumerateArray())
        {
            var hash = item.TryGetProperty("sha256_hash", out var h) ? h.GetString() : null;
            if (!TryNormalizeSha256(hash, out var normalized))
            {
                continue;
            }

            var signature = item.TryGetProperty("signature", out var s) && s.ValueKind == System.Text.Json.JsonValueKind.String ? s.GetString() : null;
            yield return new ThreatHashEntry(normalized, string.IsNullOrWhiteSpace(signature) ? "MalwareBazaar" : $"MalwareBazaar.{signature}");
        }
    }

    /// <summary>Ответ ThreatFox <c>threatfox-api</c>: записи с <c>ioc_type</c> <c>sha256_hash</c>.</summary>
    public static IEnumerable<ThreatHashEntry> ParseThreatFoxJson(string json)
    {
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != System.Text.Json.JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var item in data.EnumerateArray())
        {
            var type = item.TryGetProperty("ioc_type", out var t) ? t.GetString() : null;
            if (!string.Equals(type, "sha256_hash", StringComparison.Ordinal))
            {
                continue;
            }

            var ioc = item.TryGetProperty("ioc", out var i) ? i.GetString() : null;
            if (!TryNormalizeSha256(ioc, out var normalized))
            {
                continue;
            }

            var malware = item.TryGetProperty("malware_printable", out var m) && m.ValueKind == System.Text.Json.JsonValueKind.String ? m.GetString() : null;
            yield return new ThreatHashEntry(normalized, string.IsNullOrWhiteSpace(malware) ? "ThreatFox" : $"ThreatFox.{malware}");
        }
    }

    /// <summary>Feodo Tracker <c>ipblocklist.txt</c>: IPv4-адреса C2, по одному в строке; комментарии <c>#</c>.</summary>
    public static IReadOnlyList<string> ParseIpBlocklist(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            var candidate = line.Split(',', ' ', '\t')[0].Trim();
            if (Ipv4Regex().IsMatch(candidate) && System.Net.IPAddress.TryParse(candidate, out _))
            {
                result.Add(candidate);
            }
        }

        return [.. result];
    }

    /// <summary>URLhaus <c>text</c>: URL распространения, по одному в строке; комментарии <c>#</c>.</summary>
    public static IReadOnlyList<string> ParseUrlList(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length > 0 && line[0] != '#' && Uri.TryCreate(line, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
            {
                result.Add(line);
            }
        }

        return [.. result];
    }

    private static string FamilyFromDescription(string description)
    {
        if (string.IsNullOrWhiteSpace(description))
        {
            return ThreatHashDatabaseFormat.GenericFamily;
        }

        var cut = description.IndexOf(" - ", StringComparison.Ordinal);
        var name = (cut > 0 ? description[..cut] : description).Trim();
        return name.Length == 0 ? ThreatHashDatabaseFormat.GenericFamily : "SigBase." + name;
    }
}
