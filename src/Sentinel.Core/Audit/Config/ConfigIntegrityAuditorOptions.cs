using Sentinel.Core.Audit.Persistence;

namespace Sentinel.Core.Audit.Config;

/// <summary>Параметры аудита целостности конфигурации безопасности.</summary>
public sealed class ConfigIntegrityAuditorOptions
{
    /// <summary>Доверенные каталоги бинарников (для оценки правил брандмауэра и исключений).</summary>
    public IReadOnlyList<string> TrustedBinaryDirectories { get; init; } = [];

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
