using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Realtime;
using Sentinel.Core.Remediation;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Runtime;

/// <summary>Корень обхода при проверке: каталог и допустимая глубина рекурсии.</summary>
public sealed record ScanRoot(string Path, int MaxDepth = int.MaxValue);

/// <summary>
/// Зависимости и параметры рантайма. Все платформенные источники (процессы, аудит реестра,
/// телеметрия) инъектируются, поэтому рантайм целиком проверяется тестами в Linux.
/// </summary>
public sealed class SentinelRuntimeOptions
{
    public required string DataDirectory { get; init; }

    /// <summary><c>service</c> или <c>standalone</c> — только для отображения в интерфейсе.</summary>
    public string Mode { get; init; } = "standalone";

    public required FileAnalyzer Analyzer { get; init; }

    /// <summary>Общие сервисы (база угроз, облако, конфигурация); <c>null</c> в тестах с подставным анализатором.</summary>
    public SentinelServices? Services { get; init; }
    public required QuarantineManager Quarantine { get; init; }

    /// <summary>Движок нейтрализации; <c>null</c> — действия над системой недоступны (не Windows).</summary>
    public RemediationEngine? Engine { get; init; }

    public IProcessProvider? Processes { get; init; }
    public Func<PersistenceAuditReport>? PersistenceAudit { get; init; }
    public Func<ConfigAuditReport>? ConfigAudit { get; init; }
    public required ITelemetryProvider Telemetry { get; init; }
    public FileMonitorOptions Monitor { get; init; } = new();
    public IReadOnlyList<ScanRoot> QuickScanRoots { get; init; } = [];
    public IReadOnlyList<ScanRoot> FullScanRoots { get; init; } = [];
    public int RulesLoaded { get; init; }
    public bool RealtimeEnabledByDefault { get; init; } = true;
    public TimeSpan TelemetryInterval { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan ProcessAuditInterval { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan ConfigAuditInterval { get; init; } = TimeSpan.FromMinutes(5);
    public DispatcherOptions Dispatcher { get; init; } = new();
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Каталог данных по умолчанию: <c>%ProgramData%\Sentinel</c> (вне Windows — <c>~/.local/share/Sentinel</c>).</summary>
    public static string DefaultDataDirectory() =>
        Path.GetDirectoryName(QuarantineOptions.CreateDefault().QuarantineDirectory)!;

    /// <summary>Каталог правил рядом с исполняемым файлом (для однофайловой сборки — рядом с .exe).</summary>
    public static string DefaultRulesDirectory()
    {
        var nearBinary = Path.Combine(AppContext.BaseDirectory, "rules");
        return Directory.Exists(nearBinary) ? nearBinary : Path.GetFullPath("rules");
    }

    /// <summary>Рабочая конфигурация с настоящими провайдерами текущей ОС.</summary>
    public static SentinelRuntimeOptions CreateDefault(string mode, string? dataDirectory = null, string? rulesDirectory = null)
    {
        var data = Path.GetFullPath(dataDirectory ?? DefaultDataDirectory());
        var services = SentinelServices.Create(data, rulesDirectory ?? DefaultRulesDirectory());
        var rules = services.Rules;
        var whitelist = services.Whitelist;
        var analyzer = services.Analyzer;
        var quarantine = new QuarantineManager(whitelist, new QuarantineOptions { QuarantineDirectory = Path.Combine(data, "Quarantine") });

        RemediationEngine? engine = null;
        IProcessProvider? processes = null;
        Func<PersistenceAuditReport>? persistence = null;
        Func<ConfigAuditReport>? config = null;
        if (OperatingSystem.IsWindows())
        {
            engine = RemediationEngine.CreateDefault(whitelist, RemediationOptions.CreateDefault(data));
            processes = ProcessProviderFactory.CreateDefault();
            // Провайдеры создаются здесь, под проверкой платформы; аудиторы — заново на каждый прогон.
            var registry = RegistryProviderFactory.CreateDefault();
            var tasks = new WindowsTaskSchedulerProvider();
            var wmi = new WindowsWmiSubscriptionProvider();
            var certificates = new WindowsRootCertificateProvider();
            var defenderExclusions = new WindowsDefenderExclusionSource();
            persistence = () => new PersistenceAuditor(PersistenceAuditorOptions.CreateDefault() with { IsUserAllowed = services.IsUserAllowed }, registry, tasks, wmi, analyzer).Audit();
            config = () => new ConfigIntegrityAuditor(ConfigIntegrityAuditorOptions.CreateDefault() with { IsUserAllowed = services.IsUserAllowed }, registry, certificates, defenderExclusions, analyzer).Audit();
        }

        return new SentinelRuntimeOptions
        {
            DataDirectory = data,
            Mode = mode,
            Analyzer = analyzer,
            Quarantine = quarantine,
            Engine = engine,
            Processes = processes,
            PersistenceAudit = persistence,
            ConfigAudit = config,
            Telemetry = TelemetryProviderFactory.CreateDefault(),
            Monitor = FileMonitorOptions.CreateDefault(data),
            QuickScanRoots = DefaultQuickRoots(),
            FullScanRoots = DefaultFullRoots(),
            RulesLoaded = rules.Rules.Count,
            Services = services,
        };
    }

    /// <summary>Каталоги быстрой проверки: туда вредоносное ПО попадает и оттуда запускается чаще всего.</summary>
    public static IReadOnlyList<ScanRoot> DefaultQuickRoots()
    {
        var roots = new List<ScanRoot>();
        Add(Path.GetTempPath(), 3);
        Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), 1);
        Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup), 1);
        Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), 1);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(profile))
        {
            Add(Path.Combine(profile, "Downloads"), 2);
        }

        if (OperatingSystem.IsWindows())
        {
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 2);
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 1);
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrEmpty(windows))
            {
                Add(Path.Combine(windows, "Temp"), 3);
                var drive = Path.GetPathRoot(windows);
                if (!string.IsNullOrEmpty(drive))
                {
                    Add(Path.Combine(drive, "Users", "Public"), 3);
                }
            }
        }

        return roots;

        void Add(string? path, int depth)
        {
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path)
                && !roots.Exists(r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase)))
            {
                roots.Add(new ScanRoot(path, depth));
            }
        }
    }

    /// <summary>Корни полной проверки: все готовые локальные диски.</summary>
    public static IReadOnlyList<ScanRoot> DefaultFullRoots()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [new ScanRoot(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))];
        }

        return DriveInfo.GetDrives()
            .Where(d => d is { DriveType: DriveType.Fixed, IsReady: true })
            .Select(d => new ScanRoot(d.RootDirectory.FullName))
            .ToArray();
    }
}
