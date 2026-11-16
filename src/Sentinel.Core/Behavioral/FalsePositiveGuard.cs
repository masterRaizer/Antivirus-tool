using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;

namespace Sentinel.Core.Behavioral;

/// <summary>Вердикт обязательного фильтра перед активным действием.</summary>
public enum GuardDecision
{
    /// <summary>Действие запрещено навсегда: самозащита, системный файл, белый список или кэш чистых файлов.</summary>
    Protected,

    /// <summary>Только журнал (низкий риск), без действий.</summary>
    LogOnly,

    /// <summary>Спорно: спросить пользователя (серая зона или теневой режим).</summary>
    AskUser,

    /// <summary>Разрешено активное действие (карантин/блокировка).</summary>
    Act,
}

/// <summary>Исходные данные для решения: путь, хеш, балл, признак доверенной подписи, теневой режим.</summary>
public sealed record GuardContext
{
    public string? Path { get; init; }

    public string? Sha256 { get; init; }

    public int Score { get; init; }

    /// <summary>Файл имеет действительную подпись доверенного издателя (проверено WinVerifyTrust выше по стеку).</summary>
    public bool HasValidTrustedSignature { get; init; }

    /// <summary>Теневой аудит: активные действия не выполняются автоматически — только запрос решения.</summary>
    public bool ShadowMode { get; init; }
}

public sealed record GuardVerdict(GuardDecision Decision, int EffectiveScore, string Reason);

/// <summary>
/// Единый фильтр ложных срабатываний перед карантином/блокировкой. Порядок: (1) абсолютная самозащита с защитой от
/// маскировки — системное имя даёт иммунитет только для файла в System32/Windows/ядре, поэтому поддельный
/// <c>C:\Temp\lsass.exe</c> иммунитета не получает; (2) пользовательский белый список (пути/маски/SHA-256);
/// (3) кэш чистых файлов; (4) доверенная подпись (−35 баллов, запрет авто-карантина в теневом режиме). Затем порог.
/// </summary>
public sealed class FalsePositiveGuard
{
    public const int TrustedSignatureModifier = -35;

    private readonly AllowedExclusions _allowed;
    private readonly Func<string, bool>? _isKnownClean;
    private readonly IReadOnlyList<string> _ownDirectories;
    private readonly int _actThreshold;
    private readonly int _askThreshold;

    public FalsePositiveGuard(
        AllowedExclusions? allowed = null,
        Func<string, bool>? isKnownClean = null,
        IEnumerable<string>? extraOwnDirectories = null,
        int actThreshold = 80,
        int askThreshold = 50)
    {
        _allowed = allowed ?? AllowedExclusions.Empty;
        _isKnownClean = isKnownClean;
        _ownDirectories = (extraOwnDirectories ?? []).ToArray();
        _actThreshold = actThreshold;
        _askThreshold = askThreshold;
    }

    public GuardVerdict Evaluate(GuardContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var path = context.Path;

        if (!string.IsNullOrEmpty(path) && SelfProtection.IsProtectedFile(path, [.. _ownDirectories]))
        {
            return new GuardVerdict(GuardDecision.Protected, 0, "Самозащита: критический системный файл или каталог Sentinel.");
        }

        if (SelfProtection.IsOwnBinaryHash(context.Sha256))
        {
            return new GuardVerdict(GuardDecision.Protected, 0, "Исполняемый файл Sentinel (SHA-256 совпадает с установленной версией).");
        }

        if (!string.IsNullOrEmpty(path) && _allowed.IsPathAllowed(path))
        {
            return new GuardVerdict(GuardDecision.Protected, 0, "Путь в пользовательском списке разрешённого (allowed_exclusions.json).");
        }

        if (_allowed.IsHashAllowed(context.Sha256))
        {
            return new GuardVerdict(GuardDecision.Protected, 0, "SHA-256 в пользовательском списке разрешённого.");
        }

        if (!string.IsNullOrEmpty(path) && _isKnownClean?.Invoke(path) == true)
        {
            return new GuardVerdict(GuardDecision.Protected, 0, "Файл не изменялся и ранее признан чистым (кэш).");
        }

        var effective = context.Score + (context.HasValidTrustedSignature ? TrustedSignatureModifier : 0);
        effective = Math.Clamp(effective, 0, 100);

        if (effective < _askThreshold)
        {
            return new GuardVerdict(GuardDecision.LogOnly, effective, "Риск ниже порога — только запись в журнал.");
        }

        if (effective >= _actThreshold && !context.ShadowMode && !context.HasValidTrustedSignature)
        {
            return new GuardVerdict(GuardDecision.Act, effective, "Высокий риск — автоматическая нейтрализация.");
        }

        var reason = context.ShadowMode
            ? "Теневой режим: активные действия отключены, требуется решение пользователя."
            : context.HasValidTrustedSignature
                ? "Файл подписан доверенным издателем — автоматический карантин запрещён, решает пользователь."
                : "Серая зона риска — требуется решение пользователя.";
        return new GuardVerdict(GuardDecision.AskUser, effective, reason);
    }
}
