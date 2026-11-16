using Sentinel.Core.Behavioral;
using Sentinel.Core.Scanning;
using Sentinel.Core.Protection;
using Sentinel.Core.Signatures;
using Sentinel.Core.ThreatIntel;

namespace Sentinel.Core.Runtime;

/// <summary>Состояние поведенческого щита для интерфейса и CLI.</summary>
public sealed record BehavioralStatus(
    bool RansomwareShieldEnabled,
    bool CanaryEnabled,
    bool UsbShieldEnabled,
    bool ShadowMode,
    int CanaryCount,
    int CanaryTampered,
    IReadOnlyList<string> RecentChains);

/// <summary>Поведенческий щит, файлы-приманки и USB-щит рантайма (User-Mode, без чтения чужой памяти).</summary>
public sealed partial class SentinelRuntime
{
    private readonly Lazy<RansomwareBehaviorShield> _ransomware = new(() => new RansomwareBehaviorShield());
    private readonly Lazy<BehavioralCorrelationEngine> _correlation = new(() => new BehavioralCorrelationEngine());
    private readonly CanaryFileGuard _canary = new();
    private readonly object _chainSync = new();
    private readonly Queue<string> _recentChains = new();
    private int _canaryTampered;

    private SentinelConfig BehaviorConfig()
    {
        try
        {
            return _o.Services?.Config.Load() ?? new SentinelConfig();
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
        {
            return new SentinelConfig();
        }
    }

    /// <summary>Разворачивает файлы-приманки в пользовательских каталогах (если включено). Возвращает число созданных.</summary>
    public int DeployCanaryFiles(IEnumerable<string> directories)
    {
        ArgumentNullException.ThrowIfNull(directories);
        return BehaviorConfig().EnableCanaryFiles ? _canary.Deploy(directories).Count : 0;
    }

    /// <summary>Является ли путь файлом-приманкой (штатный сканер их пропускает).</summary>
    public bool IsCanaryFile(string path) => _canary.IsCanary(path);

    /// <summary>Наблюдает файловое событие поведенческим анти-шифровальщиком; при тревоге фиксирует цепочку и журналирует.</summary>
    public RansomwareAlert? ObserveFileActivity(FileEventKind kind, string path, string? oldPath = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var config = BehaviorConfig();

        if (config.EnableCanaryFiles && _canary.IsCanary(path) && _canary.Inspect(path) is { } tamper)
        {
            Interlocked.Increment(ref _canaryTampered);
            var canaryAlert = _ransomware.Value.RegisterCanaryTamper(tamper);
            RecordChain($"Canary: {tamper.Reason}");
            Log?.Invoke($"Анти-шифровальщик (приманка): {tamper.Reason}");
            return canaryAlert;
        }

        if (!config.EnableRansomwareShield)
        {
            return null;
        }

        var alert = _ransomware.Value.Observe(kind, path, oldPath);
        if (alert is not null)
        {
            RecordChain($"Ransomware: {alert.Reason}");
            Log?.Invoke($"Анти-шифровальщик: {alert.Reason} (балл {alert.Score}).");
        }

        return alert;
    }

    /// <summary>Сканирует съёмный носитель или произвольный путь USB-щитом. Пустой путь — все съёмные тома.</summary>
    public Task<IReadOnlyList<UsbFinding>> ScanRemovableAsync(string? pathOrDrive, CancellationToken cancellationToken = default)
    {
        var shield = new RemovableMediaShield(BinarySeverity);
        var findings = new List<UsbFinding>();
        var roots = string.IsNullOrWhiteSpace(pathOrDrive)
            ? _o.RemovableRoots().Select(r => r.Path)
            : [pathOrDrive];

        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                findings.AddRange(shield.ScanDirectory(root));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log?.Invoke($"USB-щит: каталог '{root}' недоступен: {ex.Message}");
            }
        }

        return Task.FromResult<IReadOnlyList<UsbFinding>>(findings);
    }

    public Task<BehavioralStatus> GetBehavioralStatusAsync(CancellationToken cancellationToken = default) => Task.FromResult(GetBehavioralStatus());

    public BehavioralStatus GetBehavioralStatus()
    {
        var config = BehaviorConfig();
        lock (_chainSync)
        {
            return new BehavioralStatus(
                config.EnableRansomwareShield,
                config.EnableCanaryFiles,
                config.EnableUsbShield,
                config.BehavioralShadowMode,
                _canary.Count,
                Volatile.Read(ref _canaryTampered),
                _recentChains.ToArray());
        }
    }

    private Severity? BinarySeverity(string path)
    {
        try
        {
            var result = _o.Analyzer.Analyze(path);
            if (result.Verdict is Verdict.Malicious or Verdict.Suspicious && result.Detections.Count > 0)
            {
                return result.Detections.Max(d => d.Severity);
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private void RecordChain(string chain)
    {
        lock (_chainSync)
        {
            _recentChains.Enqueue($"{_o.TimeProvider.GetUtcNow().UtcDateTime:HH:mm:ss} {chain}");
            while (_recentChains.Count > 50)
            {
                _recentChains.Dequeue();
            }
        }
    }
}
