using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.ThreatIntel;

/// <summary>Пользовательская конфигурация <c>sentinel_config.json</c>: ключи облачных сервисов и переключатели модулей.</summary>
public sealed record SentinelConfig
{
    public string? KasperskyOpenTipApiKey { get; init; }

    public string? VirusTotalApiKey { get; init; }

    /// <summary>Ключ abuse.ch (Auth-Key) для актуальных API MalwareBazaar, ThreatFox и URLhaus; необязателен.</summary>
    public string? AbuseChAuthKey { get; init; }

    public bool UsbShieldEnabled { get; init; } = true;

    public bool MemoryScanEnabled { get; init; } = true;

    public bool AutoUpdateDatabases { get; init; } = true;

    /// <summary>Поведенческий анти-шифровальщик (всплеск/энтропия/расширения).</summary>
    public bool EnableRansomwareShield { get; init; } = true;

    /// <summary>Файлы-приманки (canary) в пользовательских каталогах.</summary>
    public bool EnableCanaryFiles { get; init; } = true;

    /// <summary>USB-щит (сканирование съёмных носителей).</summary>
    public bool EnableUsbShield { get; init; } = true;

    /// <summary>Теневой аудит поведения: активные действия не выполняются автоматически, только запрос решения.</summary>
    public bool BehavioralShadowMode { get; init; }

    /// <summary>Детектор скрытых майнеров: процессы, которые прячут нагрузку при открытии Диспетчера задач.</summary>
    public bool EnableMonitorEvasionWatch { get; init; } = true;

    /// <summary>
    /// Проверять подозрительные неизвестные файлы по открытой базе известных программ CIRCL hashlookup (NSRL и др.) —
    /// аналог «белого облака» KSN. Отправляется только SHA-256; по умолчанию выключено (без согласия сеть не используется).
    /// </summary>
    public bool EnableKnownGoodLookup { get; init; }

    /// <summary>Режим ноутбука: от батареи плановый аудит автозагрузки реже (как отложенные задачи Касперского); скорость проверки не меняется.</summary>
    public bool PowerSaverOnBattery { get; init; } = true;

    public bool HasCloudKeys => !string.IsNullOrWhiteSpace(KasperskyOpenTipApiKey) || !string.IsNullOrWhiteSpace(VirusTotalApiKey);
}

/// <summary>Хранилище конфигурации: чтение с кэшированием по времени изменения, атомарная запись.</summary>
public sealed class SentinelConfigStore
{
    public const string FileName = "sentinel_config.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly object _sync = new();
    private SentinelConfig? _cached;
    private DateTime _stamp;

    public SentinelConfigStore(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Path = System.IO.Path.GetFullPath(path);
    }

    public string Path { get; }

    public static SentinelConfigStore ForDataDirectory(string dataDirectory) => new(System.IO.Path.Combine(dataDirectory, FileName));

    /// <summary>Отсутствующий файл — значения по умолчанию; повреждённый — <see cref="JsonException"/> (настройки не теряются молча).</summary>
    public SentinelConfig Load()
    {
        lock (_sync)
        {
            if (!File.Exists(Path))
            {
                return _cached = new SentinelConfig();
            }

            var stamp = File.GetLastWriteTimeUtc(Path);
            if (_cached is not null && stamp == _stamp)
            {
                return _cached;
            }

            using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            _cached = JsonSerializer.Deserialize<SentinelConfig>(stream, Json) ?? new SentinelConfig();
            _stamp = stamp;
            return _cached;
        }
    }

    public void Save(SentinelConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        lock (_sync)
        {
            var directory = System.IO.Path.GetDirectoryName(Path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var temp = Path + ".tmp";
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, config, Json);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, Path, overwrite: true);
            _cached = config;
            _stamp = File.GetLastWriteTimeUtc(Path);
        }
    }
}
