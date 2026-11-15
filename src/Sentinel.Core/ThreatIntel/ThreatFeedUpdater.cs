using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.ThreatIntel;

/// <summary>Итог обновления одного источника (для <c>db_status.json</c> и Дашборда).</summary>
public sealed record FeedSourceStatus(string Name, string Url, string Status, int Hashes, int NetworkIndicators, string? Message);

/// <summary>Состояние баз угроз: показывается на Дашборде и в настройках.</summary>
public sealed record DatabaseStatus
{
    public DateTimeOffset? LastAttemptUtc { get; init; }

    public DateTimeOffset? LastSuccessUtc { get; init; }

    public DateTimeOffset? DatabaseTimestampUtc { get; init; }

    public int HashCount { get; init; }

    public int NetworkIndicatorCount { get; init; }

    public string LastStatus { get; init; } = "Обновление не выполнялось";

    public IReadOnlyList<FeedSourceStatus> Sources { get; init; } = [];
}

/// <summary>
/// Автообновление баз из открытых фидов. Источники независимы: недоступный фид, ответ <c>403/404/410</c> или сбой разбора
/// фиксируются в статусе и пропускаются, остальные сливаются в <c>threat_hashes.bin</c> (запись накопительная).
/// Файлы GitHub-репозиториев IOC загружаются по дереву (<c>git/trees</c>) и только при изменении blob SHA.
/// </summary>
public sealed class ThreatFeedUpdater : IDisposable
{
    public const string StatusFileName = "db_status.json";
    public const string NetworkFileName = "threat_network.txt";
    public const string StateFileName = "threat_feed_state.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _dataDirectory;
    private readonly SentinelConfigStore _config;
    private readonly ThreatIntelligenceEngine _engine;
    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly IReadOnlyList<ThreatFeedSource> _sources;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public ThreatFeedUpdater(string dataDirectory, SentinelConfigStore config, ThreatIntelligenceEngine engine, HttpClient http,
        TimeProvider? time = null, IReadOnlyList<ThreatFeedSource>? sources = null)
    {
        _dataDirectory = Path.GetFullPath(dataDirectory);
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _time = time ?? TimeProvider.System;
        _sources = sources ?? ThreatFeedSource.CreateDefaults();
    }

    public void Dispose() => _gate.Dispose();

    public string StatusPath => Path.Combine(_dataDirectory, StatusFileName);

    public string NetworkIndicatorsPath => Path.Combine(_dataDirectory, NetworkFileName);

    /// <summary>Текущий статус баз: из <c>db_status.json</c> с актуальными сведениями о загруженной базе.</summary>
    public DatabaseStatus ReadStatus()
    {
        DatabaseStatus status = new();
        try
        {
            if (File.Exists(StatusPath))
            {
                status = JsonSerializer.Deserialize<DatabaseStatus>(File.ReadAllText(StatusPath), Json) ?? status;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Повреждённый статус заменяется данными активной базы.
        }

        return status with { DatabaseTimestampUtc = _engine.TimestampUtc, HashCount = _engine.Count };
    }

    public async Task<DatabaseStatus> UpdateAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = _time.GetUtcNow();
            var config = _config.Load();
            var state = LoadState();
            var hashes = new List<ThreatHashEntry>();
            var ips = new SortedSet<string>(StringComparer.Ordinal);
            var urls = new SortedSet<string>(StringComparer.Ordinal);
            var results = new ConcurrentBag<(int Order, FeedSourceStatus Status)>();

            var order = 0;
            foreach (var source in _sources)
            {
                var index = order++;
                FeedResult feed;
                try
                {
                    feed = await source.FetchAsync(new FeedContext(_http, config, state), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or JsonException or InvalidOperationException
                    or System.Net.Sockets.SocketException or FormatException)
                {
                    // Изоляция сбоев: один фид не должен остановить остальные.
                    feed = FeedResult.Failed("ошибка", ex.Message);
                }

                hashes.AddRange(feed.Hashes);
                foreach (var ip in feed.Ips)
                {
                    ips.Add(ip);
                }

                foreach (var url in feed.Urls)
                {
                    urls.Add(url);
                }

                results.Add((index, new FeedSourceStatus(source.Name, source.Url, feed.Status, feed.Hashes.Count, feed.Ips.Count + feed.Urls.Count, feed.Message)));
            }

            var statuses = results.OrderBy(r => r.Order).Select(r => r.Status).ToArray();
            var okSources = statuses.Count(s => s.Status == "ok");
            var added = 0;
            if (hashes.Count > 0)
            {
                // Накопительное слияние: прежние записи сохраняются, новые добавляются.
                var merged = _engine.Snapshot().Concat(hashes).ToArray();
                var temp = Path.Combine(_dataDirectory, ThreatIntelligenceEngine.FileName + ".new");
                Directory.CreateDirectory(_dataDirectory);
                var before = _engine.Count;
                var count = ThreatHashDatabaseBuilder.BuildToFile(merged, now, temp);
                _engine.ReplaceWith(temp);
                added = count - before;
            }

            var networkCount = SaveNetworkIndicators(ips, urls);
            SaveState(state);
            var previous = ReadStatus();
            var success = okSources > 0;
            var status = new DatabaseStatus
            {
                LastAttemptUtc = now,
                LastSuccessUtc = success ? now : previous.LastSuccessUtc,
                DatabaseTimestampUtc = _engine.TimestampUtc,
                HashCount = _engine.Count,
                NetworkIndicatorCount = networkCount,
                LastStatus = success
                    ? $"Обновлено: источников {okSources} из {statuses.Length}, новых хешей {Math.Max(0, added)}"
                    : $"Не удалось обновить: ни один из {statuses.Length} источников не ответил",
                Sources = statuses,
            };
            WriteStatus(status);
            return status;
        }
        finally
        {
            _gate.Release();
        }
    }

    private int SaveNetworkIndicators(SortedSet<string> ips, SortedSet<string> urls)
    {
        if (ips.Count == 0 && urls.Count == 0)
        {
            return File.Exists(NetworkIndicatorsPath) ? File.ReadLines(NetworkIndicatorsPath).Count(l => l.Length > 0) : 0;
        }

        // Накопительно: новые индикаторы добавляются к прежним, список ограничен (самые свежие вытесняют старые не ведутся — только дедупликация).
        var existing = NetworkIndicatorSet.Load(NetworkIndicatorsPath);
        var all = new SortedSet<string>(existing.Lines, StringComparer.Ordinal);
        foreach (var ip in ips)
        {
            all.Add("ip:" + ip);
        }

        foreach (var url in urls)
        {
            all.Add("url:" + url);
        }

        var temp = NetworkIndicatorsPath + ".tmp";
        File.WriteAllLines(temp, all, new UTF8Encoding(false));
        File.Move(temp, NetworkIndicatorsPath, overwrite: true);
        return all.Count;
    }

    private FeedState LoadState()
    {
        var path = Path.Combine(_dataDirectory, StateFileName);
        try
        {
            if (File.Exists(path))
            {
                return JsonSerializer.Deserialize<FeedState>(File.ReadAllText(path), Json) ?? new FeedState();
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Без состояния источники просто загрузятся заново.
        }

        return new FeedState();
    }

    private void SaveState(FeedState state)
    {
        Directory.CreateDirectory(_dataDirectory);
        var path = Path.Combine(_dataDirectory, StateFileName);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, Json));
        File.Move(temp, path, overwrite: true);
    }

    private void WriteStatus(DatabaseStatus status)
    {
        Directory.CreateDirectory(_dataDirectory);
        var temp = StatusPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(status, Json));
        File.Move(temp, StatusPath, overwrite: true);
    }
}

/// <summary>Накопленное состояние источников: blob SHA уже обработанных файлов GitHub-репозиториев.</summary>
public sealed class FeedState
{
    public Dictionary<string, string> Blobs { get; set; } = new(StringComparer.Ordinal);
}

public sealed record FeedContext(HttpClient Http, SentinelConfig Config, FeedState State);

public sealed record FeedResult(string Status, string? Message, IReadOnlyList<ThreatHashEntry> Hashes, IReadOnlyList<string> Ips, IReadOnlyList<string> Urls)
{
    public static FeedResult Failed(string status, string message) => new(status, message, [], [], []);

    public static FeedResult Ok(IReadOnlyList<ThreatHashEntry> hashes, IReadOnlyList<string>? ips = null, IReadOnlyList<string>? urls = null, string? message = null) =>
        new("ok", message, hashes, ips ?? [], urls ?? []);
}

/// <summary>Один источник индикаторов.</summary>
public abstract class ThreatFeedSource
{
    public abstract string Name { get; }

    public abstract string Url { get; }

    public abstract Task<FeedResult> FetchAsync(FeedContext context, CancellationToken cancellationToken);

    /// <summary>Источники по умолчанию: GitHub-зеркала IOC, устаревшие публичные списки abuse.ch и актуальные API abuse.ch (нужен Auth-Key).</summary>
    public static IReadOnlyList<ThreatFeedSource> CreateDefaults() =>
    [
        new GitHubIocSource("Neo23x0/signature-base (IOC)", "Neo23x0", "signature-base", "master",
            path => path.StartsWith("iocs/", StringComparison.Ordinal) && path.EndsWith(".txt", StringComparison.Ordinal),
            (path, text) => path.EndsWith("hash-iocs.txt", StringComparison.Ordinal)
                ? ThreatFeedParsers.ParseSignatureBaseHashIocs(text)
                : ThreatFeedParsers.ParseHashList(text, "SigBase." + Path.GetFileNameWithoutExtension(path))),
        new GitHubIocSource("Neo23x0/signature-base (YARA, мета-хеши)", "Neo23x0", "signature-base", "master",
            path => path.StartsWith("yara/", StringComparison.Ordinal) && path.EndsWith(".yar", StringComparison.Ordinal),
            (path, text) => ThreatFeedParsers.ParseYaraMetaHashes(text, "SigBase." + Path.GetFileNameWithoutExtension(path))),
        new GitHubIocSource("eset/malware-ioc", "eset", "malware-ioc", "master",
            path => path.Contains('/', StringComparison.Ordinal) && !path.EndsWith(".yar", StringComparison.Ordinal) && !path.EndsWith(".png", StringComparison.Ordinal)
                && !path.EndsWith(".md5", StringComparison.Ordinal) && !path.EndsWith(".sha1", StringComparison.Ordinal)
                && (path.EndsWith(".sha256", StringComparison.Ordinal) || path.EndsWith(".txt", StringComparison.Ordinal) || path.EndsWith(".csv", StringComparison.Ordinal)
                    || path.EndsWith(".ioc", StringComparison.Ordinal) || path.EndsWith(".adoc", StringComparison.Ordinal) || path.EndsWith(".json", StringComparison.Ordinal)),
            (path, text) => ThreatFeedParsers.ParseHashList(text, "ESET." + path[..path.IndexOf('/', StringComparison.Ordinal)])),
        new TextListSource("abuse.ch MalwareBazaar (публичный список)", "https://bazaar.abuse.ch/export/txt/sha256/recent/",
            text => (ThreatFeedParsers.ParseHashList(text, "MalwareBazaar").ToArray(), [], [])),
        new TextListSource("abuse.ch URLhaus (публичный список)", "https://urlhaus.abuse.ch/downloads/text/",
            text => ([], [], ThreatFeedParsers.ParseUrlList(text))),
        new TextListSource("abuse.ch Feodo Tracker (C2 IP)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            text => ([], ThreatFeedParsers.ParseIpBlocklist(text), [])),
        new AbuseChApiSource("abuse.ch MalwareBazaar API", "https://mb-api.abuse.ch/api/v1/", "query=get_recent&selector=time",
            "application/x-www-form-urlencoded", json => (ThreatFeedParsers.ParseMalwareBazaarJson(json).ToArray(), [], [])),
        new AbuseChApiSource("abuse.ch ThreatFox API", "https://threatfox-api.abuse.ch/api/v1/", "{\"query\":\"get_iocs\",\"days\":7}",
            "application/json", json => (ThreatFeedParsers.ParseThreatFoxJson(json).ToArray(), [], [])),
        new AbuseChApiSource("abuse.ch URLhaus API", "https://urlhaus-api.abuse.ch/v1/urls/recent/", null, null, ParseUrlhausApi),
    ];

    internal static (IReadOnlyList<ThreatHashEntry>, IReadOnlyList<string>, IReadOnlyList<string>) ParseUrlhausApi(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var urls = new List<string>();
        if (doc.RootElement.TryGetProperty("urls", out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                if (item.TryGetProperty("url", out var u) && u.GetString() is { Length: > 0 } url && Uri.TryCreate(url, UriKind.Absolute, out _))
                {
                    urls.Add(url);
                }
            }
        }

        return ([], [], urls);
    }

    protected static string Describe(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Gone => "410: источник закрыт его владельцем",
        HttpStatusCode.Forbidden => "403: доступ запрещён или превышен лимит",
        HttpStatusCode.Unauthorized => "401: нужен ключ (Auth-Key)",
        HttpStatusCode.NotFound => "404: не найдено",
        HttpStatusCode.TooManyRequests => "429: лимит запросов",
        _ => $"HTTP {(int)status}",
    };
}

/// <summary>Простой текстовый список по одному URL.</summary>
public sealed class TextListSource(string name, string url, Func<string, (IReadOnlyList<ThreatHashEntry> Hashes, IReadOnlyList<string> Ips, IReadOnlyList<string> Urls)> parse)
    : ThreatFeedSource
{
    public override string Name => name;

    public override string Url => url;

    public override async Task<FeedResult> FetchAsync(FeedContext context, CancellationToken cancellationToken)
    {
        using var response = await context.Http.GetAsync(url, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return FeedResult.Failed("пропущен", Describe(response.StatusCode));
        }

        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var (hashes, ips, urls) = parse(text);
        return FeedResult.Ok(hashes, ips, urls);
    }
}

/// <summary>Актуальные API abuse.ch: работают только с Auth-Key из <c>sentinel_config.json</c>; без ключа источник пропускается.</summary>
public sealed class AbuseChApiSource(string name, string url, string? postBody, string? contentType,
    Func<string, (IReadOnlyList<ThreatHashEntry> Hashes, IReadOnlyList<string> Ips, IReadOnlyList<string> Urls)> parse) : ThreatFeedSource
{
    public override string Name => name;

    public override string Url => url;

    public override async Task<FeedResult> FetchAsync(FeedContext context, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(context.Config.AbuseChAuthKey))
        {
            return FeedResult.Failed("пропущен", "не задан AbuseChAuthKey в sentinel_config.json");
        }

        using var request = new HttpRequestMessage(postBody is null ? HttpMethod.Get : HttpMethod.Post, url);
        request.Headers.TryAddWithoutValidation("Auth-Key", context.Config.AbuseChAuthKey);
        if (postBody is not null)
        {
            request.Content = new StringContent(postBody, Encoding.UTF8, contentType!);
        }

        using var response = await context.Http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return FeedResult.Failed("пропущен", Describe(response.StatusCode));
        }

        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var (hashes, ips, urls) = parse(text);
        return FeedResult.Ok(hashes, ips, urls);
    }
}

/// <summary>
/// Репозиторий IOC на GitHub: дерево файлов запрашивается через <c>api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1</c>,
/// файлы — через <c>raw.githubusercontent.com</c>; неизменившиеся (по blob SHA) файлы повторно не загружаются.
/// </summary>
public sealed class GitHubIocSource(string name, string owner, string repo, string branch, Func<string, bool> pathFilter,
    Func<string, string, IEnumerable<ThreatHashEntry>> parse) : ThreatFeedSource
{
    private const int MaxParallelDownloads = 8;
    private const long MaxFileBytes = 8 * 1024 * 1024;

    public override string Name => name;

    public override string Url => $"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1";

    public override async Task<FeedResult> FetchAsync(FeedContext context, CancellationToken cancellationToken)
    {
        using var treeRequest = new HttpRequestMessage(HttpMethod.Get, Url);
        treeRequest.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        using var treeResponse = await context.Http.SendAsync(treeRequest, cancellationToken).ConfigureAwait(false);
        if (!treeResponse.IsSuccessStatusCode)
        {
            return FeedResult.Failed("пропущен", Describe(treeResponse.StatusCode));
        }

        using var doc = JsonDocument.Parse(await treeResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        var files = new List<(string Path, string Sha)>();
        if (doc.RootElement.TryGetProperty("tree", out var tree) && tree.ValueKind == JsonValueKind.Array)
        {
            foreach (var node in tree.EnumerateArray())
            {
                if (node.TryGetProperty("type", out var type) && type.GetString() == "blob"
                    && node.TryGetProperty("path", out var path) && path.GetString() is { } p && pathFilter(p)
                    && node.TryGetProperty("sha", out var sha) && sha.GetString() is { } s
                    && (!node.TryGetProperty("size", out var size) || size.GetInt64() <= MaxFileBytes))
                {
                    files.Add((p, s));
                }
            }
        }

        var changed = files.Where(f => !context.State.Blobs.TryGetValue($"{owner}/{repo}:{f.Path}", out var known) || known != f.Sha).ToArray();
        var hashes = new ConcurrentBag<ThreatHashEntry>();
        var downloaded = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        var failures = 0;
        await Parallel.ForEachAsync(changed, new ParallelOptions { MaxDegreeOfParallelism = MaxParallelDownloads, CancellationToken = cancellationToken },
            async (file, token) =>
            {
                try
                {
                    var text = await context.Http.GetStringAsync($"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file.Path}", token).ConfigureAwait(false);
                    foreach (var entry in parse(file.Path, text))
                    {
                        hashes.Add(entry);
                    }

                    downloaded[$"{owner}/{repo}:{file.Path}"] = file.Sha;
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !token.IsCancellationRequested)
                {
                    Interlocked.Increment(ref failures);
                }
            }).ConfigureAwait(false);

        foreach (var (key, sha) in downloaded)
        {
            context.State.Blobs[key] = sha;
        }

        var message = $"файлов в дереве: {files.Count}, загружено: {downloaded.Count}{(failures > 0 ? $", ошибок: {failures}" : string.Empty)}";
        return FeedResult.Ok([.. hashes], message: message);
    }
}

/// <summary>Сетевые индикаторы (IP командных серверов и URL распространения) из <c>threat_network.txt</c>.</summary>
public sealed class NetworkIndicatorSet
{
    private readonly HashSet<string> _ips;
    private readonly HashSet<string> _urls;

    private NetworkIndicatorSet(IReadOnlyList<string> lines)
    {
        Lines = lines;
        _ips = new HashSet<string>(lines.Where(l => l.StartsWith("ip:", StringComparison.Ordinal)).Select(l => l[3..]), StringComparer.Ordinal);
        _urls = new HashSet<string>(lines.Where(l => l.StartsWith("url:", StringComparison.Ordinal)).Select(l => l[4..]), StringComparer.OrdinalIgnoreCase);
    }

    public static NetworkIndicatorSet Empty { get; } = new([]);

    public IReadOnlyList<string> Lines { get; }

    public int Count => Lines.Count;

    public static NetworkIndicatorSet Load(string path)
    {
        try
        {
            return File.Exists(path) ? new NetworkIndicatorSet([.. File.ReadAllLines(path).Where(l => l.Length > 0)]) : Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Empty;
        }
    }

    /// <summary>Возвращает совпавший индикатор, если командная строка содержит известный IP командного сервера или URL распространения.</summary>
    public string? FindIn(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine) || Count == 0)
        {
            return null;
        }

        foreach (var url in _urls)
        {
            if (commandLine.Contains(url, StringComparison.OrdinalIgnoreCase))
            {
                return url;
            }
        }

        foreach (var ip in _ips)
        {
            var index = commandLine.IndexOf(ip, StringComparison.Ordinal);
            while (index >= 0)
            {
                var end = index + ip.Length;
                var before = index == 0 || !(char.IsAsciiDigit(commandLine[index - 1]) || commandLine[index - 1] == '.');
                var after = end >= commandLine.Length || !(char.IsAsciiDigit(commandLine[end]) || commandLine[end] == '.');
                if (before && after)
                {
                    return ip;
                }

                index = commandLine.IndexOf(ip, end, StringComparison.Ordinal);
            }
        }

        return null;
    }
}
