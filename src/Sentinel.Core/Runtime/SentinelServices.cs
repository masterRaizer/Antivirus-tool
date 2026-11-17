using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;
using Sentinel.Core.ThreatIntel;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Runtime;

/// <summary>
/// Общий набор сервисов проверки файлов: правила, проверка подписей, белый список, база угроз, облачная репутация и список разрешённого.
/// Служба, приложение, консольный сканер и рабочие процессы пула строят анализатор одинаково — результаты совпадают.
/// </summary>
public sealed class SentinelServices : IDisposable
{
    private static readonly Lazy<HttpClient> SharedHttp = new(() =>
    {
        var client = new HttpClient(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) }) { Timeout = TimeSpan.FromSeconds(60) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel-Antivirus/1.1");
        return client;
    });

    private SentinelServices(string dataDirectory, RuleSet rules, ISignatureVerifier verifier, SystemWhitelist whitelist,
        ThreatIntelligenceEngine threatIntel, SentinelConfigStore config, AllowedExclusionStore allowed, CloudReputationService cloud, FileAnalyzer analyzer)
    {
        DataDirectory = dataDirectory;
        Rules = rules;
        Verifier = verifier;
        Whitelist = whitelist;
        ThreatIntel = threatIntel;
        Config = config;
        Allowed = allowed;
        Cloud = cloud;
        Analyzer = analyzer;
    }

    public string DataDirectory { get; }

    public RuleSet Rules { get; }

    public ISignatureVerifier Verifier { get; }

    public SystemWhitelist Whitelist { get; }

    public ThreatIntelligenceEngine ThreatIntel { get; }

    public SentinelConfigStore Config { get; }

    public AllowedExclusionStore Allowed { get; }

    public CloudReputationService Cloud { get; }

    public FileAnalyzer Analyzer { get; }

    public static HttpClient Http => SharedHttp.Value;

    /// <summary>Пользователь разрешил этот путь (повреждённый файл списка не должен ронять проверку).</summary>
    public bool IsUserAllowed(string path)
    {
        try
        {
            return Allowed.Load().IsPathAllowed(path);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public bool IsHashAllowed(string sha256)
    {
        try
        {
            return Allowed.Load().IsHashAllowed(sha256);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static SentinelServices Create(string dataDirectory, string rulesDirectory, string? allowedExclusionsFile = null, long? maxScanBytes = null)
    {
        var data = Path.GetFullPath(dataDirectory);
        Directory.CreateDirectory(data);
        var rules = RuleLoader.LoadDirectory(rulesDirectory);
        var verifier = SignatureVerifierFactory.CreateDefault();
        var whitelist = new SystemWhitelist(verifier, WhitelistOptions.CreateDefault());
        var intel = new ThreatIntelligenceEngine(data, ThreatIntelligenceEngine.DefaultBundledPath());
        var config = SentinelConfigStore.ForDataDirectory(data);
        var allowed = allowedExclusionsFile is null ? AllowedExclusionStore.ForDataDirectory(data) : new AllowedExclusionStore(allowedExclusionsFile);
        var cloud = new CloudReputationService(config, Http, Path.Combine(data, "cloud_cache.json"));
        SentinelServices? services = null;
        var options = new FileAnalyzerOptions
        {
            MaxScanBytes = maxScanBytes ?? new FileAnalyzerOptions().MaxScanBytes,
            IsUserAllowed = path => services!.IsUserAllowed(path),
            IsHashAllowed = hash => services!.IsHashAllowed(hash),
            ResultCacheDuration = TimeSpan.FromMinutes(30),
            CacheGeneration = () => (File.Exists(allowed.Path) ? File.GetLastWriteTimeUtc(allowed.Path).Ticks : 0)
                ^ (intel.TimestampUtc?.UtcTicks ?? 0),
        };
        var analyzer = new FileAnalyzer(new SignatureEngine(rules), verifier, whitelist, options, intel, cloud);
        services = new SentinelServices(data, rules, verifier, whitelist, intel, config, allowed, cloud, analyzer);
        return services;
    }

    public void Dispose() => ThreatIntel.Dispose();
}
