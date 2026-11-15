using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit.Config;

/// <summary>Параметры аудита целостности конфигурации безопасности.</summary>
public sealed class ConfigIntegrityAuditorOptions
{
    /// <summary>Доверенные каталоги бинарников (для оценки правил брандмауэра и исключений).</summary>
    public IReadOnlyList<string> TrustedBinaryDirectories { get; init; } = [];

    /// <summary>Пользовательский список разрешённого (<c>allowed_exclusions.json</c>): такие программы правилами брандмауэра не помечаются.</summary>
    public Func<string, bool>? IsUserAllowed { get; init; }

    /// <summary>Уровень правила для программы из Temp/Public.</summary>
    public Severity FirewallInboundTempSeverity { get; init; } = Severity.High;

    /// <summary>Сертификат считается «недавно установленным», если выдан не раньше, чем указанное число дней назад.</summary>
    public int RecentCertificateDays { get; init; } = 365;

    /// <summary>Минимально допустимая длина RSA-ключа корневого сертификата (бит).</summary>
    public int MinRsaKeyBits { get; init; } = 2048;

    /// <summary>«Сейчас» для оценки срока действия сертификатов (инъекция ради детерминизма тестов).</summary>
    public DateTime Now { get; init; } = DateTime.UtcNow;

    public static ConfigIntegrityAuditorOptions CreateDefault()
    {
        var persistence = PersistenceAuditorOptions.CreateDefault();
        return new ConfigIntegrityAuditorOptions
        {
            TrustedBinaryDirectories = persistence.TrustedBinaryDirectories,
        };
    }
}
