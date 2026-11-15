using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;

namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Облачная репутация по SHA-256 (сам файл не отправляется): Kaspersky OpenTIP и VirusTotal v3 — каждый только при заданном ключе.
/// Ответы кэшируются на 7 дней (отсутствие данных — на сутки); <c>HTTP 429</c> включает паузу сервиса, проверка продолжается без него.
/// </summary>
public sealed class CloudReputationService : ICloudReputationProvider
{
    public static readonly TimeSpan CacheLifetime = TimeSpan.FromDays(7);
    public static readonly TimeSpan UnknownLifetime = TimeSpan.FromDays(1);
    public const int VirusTotalMaliciousThreshold = 3;

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
            return new CloudLookupResult(cached.Reputation, cached.Source, cached.Detail);
        }

        var config = _config.Load();
        CloudLookupResult? answer = null;
        if (!string.IsNullOrWhiteSpace(config.KasperskyOpenTipApiKey) && !IsPaused("kaspersky", now))
        {
            answer = QueryKaspersky(hash, config.KasperskyOpenTipApiKey!, now);
        }

        if (answer is not { Reputation: CloudReputation.Malicious } && !string.IsNullOrWhiteSpace(config.VirusTotalApiKey) && !IsPaused("virustotal", now))
        {
            var vt = QueryVirusTotal(hash, config.VirusTotalApiKey!, now);
            if (vt is not null && (answer is null || vt.Reputation == CloudReputation.Malicious))
            {
                answer = vt;
            }
        }

        if (answer is null)
        {
            // Нет ключей, пауза из-за 429 или сбой сети: ничего не кэшируем, чтобы повторить позже.
            return CloudLookupResult.Unknown;
        }

        var lifetime = answer.Reputation == CloudReputation.Unknown ? UnknownLifetime : CacheLifetime;
        _cache[hash] = new CacheEntry(answer.Reputation, answer.Source, answer.Detail, now + lifetime);
        SaveCache();
        return answer;
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
                "Green" => new CloudLookupResult(CloudReputation.Clean, "Kaspersky OpenTIP", "зона Green"),
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
                : new CloudLookupResult(malicious == 0 ? CloudReputation.Clean : CloudReputation.Unknown, "VirusTotal", $"malicious={malicious}");
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return null;
        }
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

    private sealed record CacheEntry(CloudReputation Reputation, string Source, string? Detail, DateTimeOffset ExpiresUtc);
}
