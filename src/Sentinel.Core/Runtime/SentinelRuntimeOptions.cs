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

    /// <summary>Мост к драйверу ядра SentinelDrv; <c>null</c> — профиль User-Mode EDR без попытки подключения.</summary>
    public Func<Kernel.IKernelBridge>? KernelBridgeFactory { get; init; }

    /// <summary>Лёгкий поставщик процессов для синхронизации защищаемых PID с драйвером (без замера CPU).</summary>
    public IProcessProvider? KernelProtectionProcesses { get; init; }

    public TimeSpan KernelSyncInterval { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Как часто проверять, не останавливают ли драйвер (тогда дескриптор устройства отпускается сразу).</summary>
    public TimeSpan KernelHealthInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Как часто без драйвера пробовать подключиться к нему снова.</summary>
    public TimeSpan KernelReconnectInterval { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Потоковый аудит памяти процессов (только Windows); <c>null</c> — память не проверяется.</summary>
    public Auditors.Memory.MemoryIntegrityScanner? MemoryScanner { get; init; }

    /// <summary>Фабрика источника событий старта процессов (WMI/опрос); <c>null</c> — мониторинг старта недоступен.</summary>
    public Func<Monitoring.IProcessCreationEventSource>? ProcessStartSource { get; init; }

    /// <summary>Фабрика замера активности процессов для детектора скрытых майнеров; <c>null</c> — детектор недоступен.</summary>
    public Func<Monitoring.Evasion.IProcessActivitySampler>? ActivitySampler { get; init; }

    /// <summary>Сведения о процессе для находок детектора скрытых майнеров (путь, командная строка, окна).</summary>
    public Monitoring.Evasion.IEvasionProcessInspector? EvasionInspector { get; init; }
    public Func<PersistenceAuditReport>? PersistenceAudit { get; init; }

    /// <summary>Таблица TCP-соединений для аудита процессов (узлы семейств, порты пулов, прослушивание).</summary>
    public INetworkConnectionProvider? NetworkConnections { get; init; }

    /// <summary>Источники перепроверки после чистки семейства (после перезагрузки); <c>null</c> — перепроверка недоступна.</summary>
    public Func<ThreatFamilies.FamilyVerificationProbe>? FamilyProbe { get; init; }
    public Func<ConfigAuditReport>? ConfigAudit { get; init; }
    public required ITelemetryProvider Telemetry { get; init; }
    public FileMonitorOptions Monitor { get; init; } = new();
    public IReadOnlyList<ScanRoot> QuickScanRoots { get; init; } = [];
    public IReadOnlyList<ScanRoot> FullScanRoots { get; init; } = [];

    /// <summary>Каталог правил (передаётся рабочим процессам пула).</summary>
    public string? RulesDirectory { get; init; }

    /// <summary>Кэш чистых файлов <c>scan_cache.bin</c> для быстрой и полной проверки.</summary>
    public bool UseVerdictCache { get; init; } = true;

    /// <summary>Фабрика пула проверки (по умолчанию — <see cref="Scanning.Pool.ScanPoolFactory"/>, выбор режима по наличию Sentinel.Cli.exe).</summary>
    public Func<Scanning.ScanVerdictCache?, Scanning.Pool.IScanPool>? ScanPoolFactory { get; init; }

    /// <summary>Корни проверки «Подключённые USB»: готовые съёмные диски.</summary>
    public Func<IReadOnlyList<ScanRoot>> RemovableRoots { get; init; } = DefaultRemovableRoots;
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
        Func<Monitoring.IProcessCreationEventSource>? processStarts = null;
        Func<Monitoring.Evasion.IProcessActivitySampler>? activitySampler = null;
        Monitoring.Evasion.IEvasionProcessInspector? evasionInspector = null;
        Auditors.Memory.MemoryIntegrityScanner? memoryScanner = null;
        Func<Kernel.IKernelBridge>? kernelBridge = null;
        IProcessProvider? kernelProcesses = null;
        Func<PersistenceAuditReport>? persistence = null;
        Func<ConfigAuditReport>? config = null;
        INetworkConnectionProvider? network = null;
        Func<ThreatFamilies.FamilyVerificationProbe>? familyProbe = null;
        if (OperatingSystem.IsWindows())
        {
            network = new WindowsNetworkConnectionProvider();
            engine = RemediationEngine.CreateDefault(whitelist, RemediationOptions.CreateDefault(data));
            processes = ProcessProviderFactory.CreateDefault();
            processStarts = Monitoring.ProcessCreationEventSourceFactory.CreateDefault;
            activitySampler = ActivitySamplerFactory();
            evasionInspector = new Monitoring.Evasion.WindowsEvasionProcessInspector();
            memoryScanner = new Auditors.Memory.MemoryIntegrityScanner(new Auditors.Memory.WindowsMemoryReader(), new SignatureEngine(rules));
            kernelBridge = Kernel.KernelBridgeFactory.CreateDefault;
            kernelProcesses = new WindowsProcessProvider(TimeSpan.Zero);
            // Провайдеры создаются здесь, под проверкой платформы; аудиторы — заново на каждый прогон.
            var registry = RegistryProviderFactory.CreateDefault();
            var tasks = new WindowsTaskSchedulerProvider();
            var wmi = new WindowsWmiSubscriptionProvider();
            var certificates = new WindowsRootCertificateProvider();
            var defenderExclusions = new WindowsDefenderExclusionSource();
            persistence = () => new PersistenceAuditor(PersistenceAuditorOptions.CreateDefault() with { IsUserAllowed = services.IsUserAllowed, IncludeCleanEntries = true },
                registry, tasks, wmi, analyzer).Audit();
            config = () => new ConfigIntegrityAuditor(ConfigIntegrityAuditorOptions.CreateDefault() with { IsUserAllowed = services.IsUserAllowed }, registry, certificates, defenderExclusions, analyzer).Audit();
            familyProbe = FamilyProbeFactory(analyzer, services.IsUserAllowed);
        }

        return new SentinelRuntimeOptions
        {
            DataDirectory = data,
            Mode = mode,
            Analyzer = analyzer,
            Quarantine = quarantine,
            Engine = engine,
            Processes = processes,
            ProcessStartSource = processStarts,
            ActivitySampler = activitySampler,
            EvasionInspector = evasionInspector,
            MemoryScanner = memoryScanner,
            KernelBridgeFactory = kernelBridge,
            KernelProtectionProcesses = kernelProcesses,
            PersistenceAudit = persistence,
            ConfigAudit = config,
            NetworkConnections = network,
            FamilyProbe = familyProbe,
            Telemetry = TelemetryProviderFactory.CreateDefault(),
            Monitor = FileMonitorOptions.CreateDefault(data),
            QuickScanRoots = DefaultQuickRoots(),
            FullScanRoots = DefaultFullRoots(),
            RulesLoaded = rules.Rules.Count,
            Services = services,
            RulesDirectory = rulesDirectory ?? DefaultRulesDirectory(),
        };
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static Func<Monitoring.Evasion.IProcessActivitySampler> ActivitySamplerFactory() =>
        () => new Monitoring.Evasion.WindowsProcessActivitySampler();

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static Func<ThreatFamilies.FamilyVerificationProbe> FamilyProbeFactory(FileAnalyzer analyzer, Func<string, bool>? isUserAllowed) =>
        () => ThreatFamilies.ThreatFamilyScanner.CreateDefault(analyzer, isUserAllowed).CreateProbe();

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

    /// <summary>Готовые съёмные диски (<see cref="DriveType.Removable"/>).</summary>
    public static IReadOnlyList<ScanRoot> DefaultRemovableRoots()
    {
        try
        {
            return DriveInfo.GetDrives()
                .Where(d => d is { DriveType: DriveType.Removable, IsReady: true })
                .Select(d => new ScanRoot(d.RootDirectory.FullName))
                .ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
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
