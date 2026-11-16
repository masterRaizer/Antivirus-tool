using System.Runtime.Versioning;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;

namespace Sentinel.Core.ThreatFamilies;

/// <summary>Итог поиска семейств: отчёты аудиторов и коррелированные находки.</summary>
public sealed record FamilyScanResult(
    PersistenceAuditReport? Persistence,
    ConfigAuditReport? Config,
    ProcessAuditReport? Processes,
    IReadOnlyList<DefenderExclusionChange> DefenderEvents,
    IReadOnlyList<FamilyDetection> Detections);

/// <summary>
/// Поиск семейств майнеров/загрузчиков: аудит закрепления, конфигурации и процессов (с таблицей TCP), события 5007 Защитника
/// за последние дни и корреляция. Источники — делегаты, поэтому сценарий целиком проверяется на Linux на заглушках.
/// </summary>
public sealed class ThreatFamilyScanner
{
    public Func<PersistenceAuditReport>? Persistence { get; init; }
    public Func<ConfigAuditReport>? Config { get; init; }
    public Func<IReadOnlyList<DefenderExclusion>, ProcessAuditReport>? Processes { get; init; }
    public IDefenderEventSource? DefenderEvents { get; init; }
    public Func<string, DateTime?> FileCreationTimeUtc { get; init; } = _ => null;
    public TimeSpan EventLookback { get; init; } = TimeSpan.FromDays(30);

    public FamilyScanResult Scan()
    {
        var persistence = Persistence?.Invoke();
        var config = Config?.Invoke();
        var processes = Processes?.Invoke(config?.DefenderExclusions ?? []);
        IReadOnlyList<DefenderExclusionChange> events;
        try
        {
            events = DefenderEvents?.GetExclusionChanges(EventLookback) ?? [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            events = []; // журнал недоступен (Безопасный режим, отключённый Защитник) — корреляция по составу
        }

        var detections = ThreatFamilyCorrelator.Correlate(new FamilyCorrelationInput
        {
            Persistence = persistence,
            Config = config,
            Processes = processes,
            DefenderEvents = events,
            FileCreationTimeUtc = FileCreationTimeUtc,
        });
        return new FamilyScanResult(persistence, config, processes, events, detections);
    }

    /// <summary>Сканер с настоящими провайдерами Windows.</summary>
    [SupportedOSPlatform("windows")]
    public static ThreatFamilyScanner CreateDefault(FileAnalyzer analyzer, Func<string, bool>? isUserAllowed = null)
    {
        ArgumentNullException.ThrowIfNull(analyzer);
        var registry = RegistryProviderFactory.CreateDefault();
        var tasks = new WindowsTaskSchedulerProvider();
        var wmi = new WindowsWmiSubscriptionProvider();
        var network = new WindowsNetworkConnectionProvider();
        var processOptions = new ProcessAuditorOptions { NetworkConnections = network };
        return new ThreatFamilyScanner
        {
            Persistence = () => new PersistenceAuditor(PersistenceAuditorOptions.CreateDefault() with { IsUserAllowed = isUserAllowed }, registry, tasks, wmi, analyzer).Audit(),
            Config = () => new ConfigIntegrityAuditor(ConfigIntegrityAuditorOptions.CreateDefault() with { IsUserAllowed = isUserAllowed },
                registry, new WindowsRootCertificateProvider(), new WindowsDefenderExclusionSource(), analyzer).Audit(),
            Processes = exclusions => new ProcessAuditor(processOptions, analyzer).Audit(ProcessProviderFactory.CreateDefault().GetProcesses(), exclusions),
            DefenderEvents = new WindowsDefenderEventSource(),
            FileCreationTimeUtc = processOptions.FileCreationTimeUtc,
        };
    }

    /// <summary>Источники проверки после чистки (и после перезагрузки) для <see cref="ThreatFamilyPlaybook"/>.</summary>
    [SupportedOSPlatform("windows")]
    public FamilyVerificationProbe CreateProbe() => new()
    {
        Processes = () => ProcessProviderFactory.CreateDefault(TimeSpan.Zero).GetProcesses(),
        Connections = () => new WindowsNetworkConnectionProvider().GetConnections(),
        Exclusions = () => Config?.Invoke().DefenderExclusions ?? [],
        Persistence = Persistence,
    };
}
