using System.Text.RegularExpressions;

namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Разбор публичных фидов индикаторов. Прежние методы (<see cref="ParseHashList"/> и др.) возвращают только SHA-256; методы
/// <c>…AllKinds</c> — ещё MD5 и SHA-1 (для баз VirusShare, ESET <c>*.md5/*.sha1</c>, signature-base). Нулевые и «пустые»
/// хеши отбрасываются всегда.
/// </summary>
public static partial class ThreatFeedParsers
{
    public const string EmptyFileSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    [GeneratedRegex("(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")]
    private static partial Regex Sha256Regex();

    [GeneratedRegex("(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")]
    private static partial Regex Sha1Regex();

    [GeneratedRegex("(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")]
    private static partial Regex Md5Regex();

    public const string EmptyFileSha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    public const string EmptyFileMd5 = "d41d8cd98f00b204e9800998ecf8427e";

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

    /// <summary>Нормализация хеша заданного вида до hex нижнего регистра; нулевой и «пустой» хеши отбрасываются.</summary>
    public static bool TryNormalizeHash(string? value, ThreatHashKind kind, out string normalized)
    {
        if (kind == ThreatHashKind.Sha256)
        {
            return TryNormalizeSha256(value, out normalized);
        }

        normalized = string.Empty;
        var trimmed = value?.Trim();
        if (trimmed is null || trimmed.Length != ThreatHashKinds.HexLength(kind) || !trimmed.All(Uri.IsHexDigit))
        {
            return false;
        }

        var lower = trimmed.ToLowerInvariant();
        if (lower.All(c => c == '0') || lower == EmptyFileSha1 || lower == EmptyFileMd5)
        {
            return false;
        }

        normalized = lower;
        return true;
    }

    /// <summary>Все хеши заданного вида в произвольном тексте.</summary>
    public static IEnumerable<string> ExtractHashes(string text, ThreatHashKind kind)
    {
        ArgumentNullException.ThrowIfNull(text);
        var regex = kind switch
        {
            ThreatHashKind.Md5 => Md5Regex(),
            ThreatHashKind.Sha1 => Sha1Regex(),
            _ => Sha256Regex(),
        };
        foreach (Match m in regex.Matches(text))
        {
            if (TryNormalizeHash(m.Value, kind, out var hash))
            {
                yield return hash;
            }
        }
    }

    /// <summary>Список хешей всех видов (SHA-256, SHA-1, MD5) с одним семейством.</summary>
    public static IEnumerable<ThreatHashEntry> ParseHashListAllKinds(string text, string family) =>
        new[] { ThreatHashKind.Sha256, ThreatHashKind.Sha1, ThreatHashKind.Md5 }
            .SelectMany(kind => ExtractHashes(text, kind))
            .Select(h => new ThreatHashEntry(h, family));

    /// <summary><c>hash-iocs.txt</c> signature-base со всеми видами хешей (<c>хеш;описание</c>).</summary>
    public static IEnumerable<ThreatHashEntry> ParseSignatureBaseHashIocsAllKinds(string text)
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
            var hash = (separator < 0 ? line : line[..separator]).Trim();
            if (ThreatHashKinds.Of(hash) is not { } kind || !TryNormalizeHash(hash, kind, out var normalized))
            {
                continue;
            }

            var description = separator < 0 ? string.Empty : line[(separator + 1)..].Trim();
            yield return new ThreatHashEntry(normalized, FamilyFromDescription(description));
        }
    }

    /// <summary>
    /// Полная выгрузка MalwareBazaar в CSV (<c>bazaar.abuse.ch/export/csv/full/</c>): строки
    /// <c>"first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature",…</c>,
    /// комментарии <c>#</c>. Семейство — <c>MalwareBazaar.&lt;signature&gt;</c> или <c>MalwareBazaar.&lt;тип файла&gt;</c>. Читается потоком.
    /// </summary>
    public static IEnumerable<ThreatHashEntry> ParseMalwareBazaarCsv(TextReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            var fields = SplitCsv(line);
            if (fields.Count < 9 || !TryNormalizeSha256(fields[1], out var sha256))
            {
                continue;
            }

            var signature = fields[8].Trim();
            var type = fields[6].Trim();
            var family = signature.Length > 0 && !signature.Equals("n/a", StringComparison.OrdinalIgnoreCase) && !signature.Equals("null", StringComparison.OrdinalIgnoreCase)
                ? "MalwareBazaar." + signature
                : type.Length > 0 && !type.Equals("unknown", StringComparison.OrdinalIgnoreCase) ? "MalwareBazaar." + type : "MalwareBazaar";
            yield return new ThreatHashEntry(sha256, family);
        }
    }

    /// <summary>Список VirusShare (<c>VirusShare_NNNNN.md5</c>): по MD5 в строке, комментарии <c>#</c>. Семейство не указано.</summary>
    public static IEnumerable<ThreatHashEntry> ParseVirusShareList(TextReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length > 0 && line[0] != '#' && TryNormalizeHash(line, ThreatHashKind.Md5, out var md5))
            {
                yield return new ThreatHashEntry(md5, "VirusShare");
            }
        }
    }

    /// <summary>Разбор строки CSV с полями в кавычках (<c>""</c> внутри поля — кавычка).</summary>
    internal static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var sb = new System.Text.StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                }
                else if (c == '"')
                {
                    quoted = false;
                }
                else
                {
                    sb.Append(c);
                }
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c == ',')
            {
                fields.Add(sb.ToString().Trim());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }

        fields.Add(sb.ToString().Trim());
        return fields;
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
