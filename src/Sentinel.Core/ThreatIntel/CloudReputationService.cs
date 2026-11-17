using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;

namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Облачная репутация по SHA-256 (сам файл не отправляется): Kaspersky OpenTIP и VirusTotal v3 — каждый только при заданном ключе;
/// CIRCL hashlookup (открытая база известных программ NSRL и дистрибутивов, аналог «белого облака» KSN) — только при включённом
/// <see cref="SentinelConfig.EnableKnownGoodLookup"/>. Ответы кэшируются на 7 дней (отсутствие данных — на сутки);
/// <c>HTTP 429</c> включает паузу сервиса, проверка продолжается без него.
/// </summary>
public sealed class CloudReputationService : ICloudReputationProvider
{
    public static readonly TimeSpan CacheLifetime = TimeSpan.FromDays(7);
    public static readonly TimeSpan UnknownLifetime = TimeSpan.FromDays(1);
    public const int VirusTotalMaliciousThreshold = 3;

    /// <summary>Минимальное доверие CIRCL (<c>hashlookup:trust</c>, 0–100), с которого файл считается известной программой.</summary>
    public const int CirclTrustThreshold = 50;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly SentinelConfigStore _config;
    private readonly string? _cachePath;
    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _pausedUntil = new(StringComparer.Ordinal);
    private readonly object _saveLock = new();

    public CloudReputationService(SentinelConfigStore config, HttpClient http, string? cachePath = null, TimeProvider? time = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _cachePath = cachePath;
        _time = time ?? TimeProvider.System;
        LoadCache();
    }

    public CloudLookupResult Lookup(string sha256Hex)
    {
        if (!ThreatFeedParsers.TryNormalizeSha256(sha256Hex, out var hash))
        {
            return CloudLookupResult.Unknown;
        }

        var now = _time.GetUtcNow();
        if (_cache.TryGetValue(hash, out var cached) && cached.ExpiresUtc > now)
        {
            return new CloudLookupResult(cached.Reputation, cached.Source, cached.Detail) { KnownGood = cached.KnownGood, Disputed = cached.Disputed };
        }

        var config = _config.Load();
        var results = new List<CloudLookupResult>(3);
        if (!string.IsNullOrWhiteSpace(config.KasperskyOpenTipApiKey) && !IsPaused("kaspersky", now)
            && QueryKaspersky(hash, config.KasperskyOpenTipApiKey!, now) is { } kaspersky)
        {
            results.Add(kaspersky);
        }

        if (!results.Any(r => r.Reputation == CloudReputation.Malicious) && !string.IsNullOrWhiteSpace(config.VirusTotalApiKey)
            && !IsPaused("virustotal", now) && QueryVirusTotal(hash, config.VirusTotalApiKey!, now) is { } vt)
        {
            results.Add(vt);
        }

        // Белое облако спрашиваем, только если остальные сервисы не дали ни вердикта, ни «известной чистоты».
        if (config.EnableKnownGoodLookup && !results.Any(r => r.Reputation == CloudReputation.Malicious || r.KnownGood)
            && !IsPaused("circl", now) && QueryCircl(hash, now) is { } circl)
        {
            results.Add(circl);
        }

        if (results.Count == 0)
        {
            // Нет ключей, пауза из-за 429 или сбой сети: ничего не кэшируем, чтобы повторить позже.
            return CloudLookupResult.Unknown;
        }

        var answer = Combine(results);
        var lifetime = answer.Reputation == CloudReputation.Unknown ? UnknownLifetime : CacheLifetime;
        _cache[hash] = new CacheEntry(answer.Reputation, answer.Source, answer.Detail, now + lifetime, answer.KnownGood, answer.Disputed);
        SaveCache();
        return answer;
    }

    /// <summary>
    /// Сведение ответов: вредоносный вердикт любого сервиса побеждает; «известная чистота» действует, только если ни один
    /// сервис не сомневается; иначе — ответ первого сервиса (порядок: OpenTIP, VirusTotal, CIRCL).
    /// </summary>
    internal static CloudLookupResult Combine(IReadOnlyList<CloudLookupResult> results)
    {
        if (results.FirstOrDefault(r => r.Reputation == CloudReputation.Malicious) is { } malicious)
        {
            return malicious;
        }

        var disputed = results.Any(r => r.Disputed);
        if (!disputed && results.FirstOrDefault(r => r.KnownGood) is { } good)
        {
            return good;
        }

        return disputed ? results[0] with { KnownGood = false, Disputed = true } : results[0];
    }

    private CloudLookupResult? QueryKaspersky(string hash, string key, DateTimeOffset now)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://opentip.kaspersky.com/api/v1/search/hash?request={hash}");
        request.Headers.TryAddWithoutValidation("x-apikey", key);
        var body = Send(request, "kaspersky", now, out var status);
        if (status == HttpStatusCode.NotFound)
        {
            return new CloudLookupResult(CloudReputation.Unknown, "Kaspersky OpenTIP");
        }

        if (body is null)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var zone = doc.RootElement.TryGetProperty("Zone", out var z) ? z.GetString() : null;
            return zone switch
            {
                "Red" => new CloudLookupResult(CloudReputation.Malicious, "Kaspersky OpenTIP", "зона Red"),
                "Green" => new CloudLookupResult(CloudReputation.Clean, "Kaspersky OpenTIP", "зона Green") { KnownGood = true },
                "Yellow" or "Orange" => new CloudLookupResult(CloudReputation.Unknown, "Kaspersky OpenTIP", $"зона {zone}") { Disputed = true },
                _ => new CloudLookupResult(CloudReputation.Unknown, "Kaspersky OpenTIP", zone is null ? null : $"зона {zone}"),
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private CloudLookupResult? QueryVirusTotal(string hash, string key, DateTimeOffset now)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{hash}");
        request.Headers.TryAddWithoutValidation("x-apikey", key);
        var body = Send(request, "virustotal", now, out var status);
        if (status == HttpStatusCode.NotFound)
        {
            return new CloudLookupResult(CloudReputation.Unknown, "VirusTotal");
        }

        if (body is null)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
            var malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
            return malicious >= VirusTotalMaliciousThreshold
                ? new CloudLookupResult(CloudReputation.Malicious, "VirusTotal", $"{malicious} движков признали файл вредоносным")
                : new CloudLookupResult(malicious == 0 ? CloudReputation.Clean : CloudReputation.Unknown, "VirusTotal", $"malicious={malicious}")
                {
                    Disputed = malicious > 0,
                };
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// CIRCL hashlookup: <c>404</c> — хеша нет в базе; <c>200</c> с <c>KnownMalicious</c> — хеш отмечен источниками вредоносов;
    /// иначе файл известен (NSRL, пакеты дистрибутивов) с доверием <c>hashlookup:trust</c>.
    /// </summary>
    private CloudLookupResult? QueryCircl(string hash, DateTimeOffset now)
    {
        const string source = "CIRCL hashlookup";
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://hashlookup.circl.lu/lookup/sha256/{hash}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        var body = Send(request, "circl", now, out var status);
        if (status == HttpStatusCode.NotFound)
        {
            return new CloudLookupResult(CloudReputation.Unknown, source);
        }

        if (body is null)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (root.TryGetProperty("KnownMalicious", out var known) && TextOf(known) is { Length: > 0 } sources)
            {
                return new CloudLookupResult(CloudReputation.Malicious, source, $"хеш отмечен как вредоносный ({sources})");
            }

            var trust = root.TryGetProperty("hashlookup:trust", out var t) ? NumberOf(t) : 0;
            var name = root.TryGetProperty("FileName", out var f) ? TextOf(f) : null;
            var detail = string.IsNullOrEmpty(name) ? $"доверие {trust}" : $"доверие {trust}, {Path.GetFileName(name.Replace('\\', '/'))}";
            return trust >= CirclTrustThreshold
                ? new CloudLookupResult(CloudReputation.Clean, source, detail) { KnownGood = true }
                : new CloudLookupResult(CloudReputation.Unknown, source, detail);
        }
        catch (JsonException)
        {
            return null;
        }

        static string? TextOf(JsonElement e) => e.ValueKind switch
        {
            JsonValueKind.String => e.GetString()?.Trim(),
            JsonValueKind.Array => string.Join(", ", e.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : x.ToString())
                .Where(x => !string.IsNullOrWhiteSpace(x))),
            JsonValueKind.True => "да",
            _ => null,
        };

        static int NumberOf(JsonElement e) => e.ValueKind switch
        {
            JsonValueKind.Number when e.TryGetInt32(out var n) => n,
            JsonValueKind.String when int.TryParse(e.GetString(), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var n) => n,
            _ => 0,
        };
    }

    private string? Send(HttpRequestMessage request, string provider, DateTimeOffset now, out HttpStatusCode status)
    {
        status = 0;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var response = _http.Send(request, cts.Token);
            status = response.StatusCode;
            if (status == HttpStatusCode.TooManyRequests)
            {
                var wait = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(60);
                _pausedUntil[provider] = now + (wait < TimeSpan.FromSeconds(5) ? TimeSpan.FromSeconds(60) : wait);
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var reader = new StreamReader(response.Content.ReadAsStream(cts.Token));
            return reader.ReadToEnd();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or IOException)
        {
            return null;
        }
    }

    private bool IsPaused(string provider, DateTimeOffset now) => _pausedUntil.TryGetValue(provider, out var until) && until > now;

    private void LoadCache()
    {
        if (_cachePath is null || !File.Exists(_cachePath))
        {
            return;
        }

        try
        {
            var items = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(File.ReadAllText(_cachePath), Json);
            foreach (var (hash, entry) in items ?? [])
            {
                _cache[hash] = entry;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Повреждённый кэш не критичен.
        }
    }

    private void SaveCache()
    {
        if (_cachePath is null)
        {
            return;
        }

        lock (_saveLock)
        {
            try
            {
                var directory = Path.GetDirectoryName(_cachePath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var now = _time.GetUtcNow();
                var live = _cache.Where(kv => kv.Value.ExpiresUtc > now).ToDictionary(kv => kv.Key, kv => kv.Value);
                var temp = _cachePath + ".tmp";
                File.WriteAllText(temp, JsonSerializer.Serialize(live, Json));
                File.Move(temp, _cachePath, overwrite: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Кэш на диске — оптимизация; ошибка записи не мешает проверке.
            }
        }
    }

    private sealed record CacheEntry(CloudReputation Reputation, string Source, string? Detail, DateTimeOffset ExpiresUtc, bool KnownGood = false, bool Disputed = false);
}
