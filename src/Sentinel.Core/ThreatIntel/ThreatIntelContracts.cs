namespace Sentinel.Core.ThreatIntel;

/// <summary>Поиск SHA-256 в локальной базе известных угроз.</summary>
public interface IThreatHashLookup
{
    /// <summary>Есть ли хеш (64 hex-символа) в базе; <paramref name="family"/> — семейство угрозы.</summary>
    bool TryGetFamily(string sha256Hex, out string? family);
}

/// <summary>Вердикт облачной репутации по хешу файла.</summary>
public enum CloudReputation
{
    /// <summary>Нет данных, сервис недоступен или ключ не задан.</summary>
    Unknown = 0,

    /// <summary>Хеш известен сервису как безопасный/нейтральный.</summary>
    Clean = 1,

    /// <summary>Хеш признан вредоносным.</summary>
    Malicious = 2,
}

public sealed record CloudLookupResult(CloudReputation Reputation, string Source, string? Detail = null)
{
    public static CloudLookupResult Unknown { get; } = new(CloudReputation.Unknown, "none");
}

/// <summary>Облачная проверка репутации по SHA-256 (сам файл никуда не отправляется).</summary>
public interface ICloudReputationProvider
{
    CloudLookupResult Lookup(string sha256Hex);
}
