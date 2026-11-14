namespace Sentinel.Core.Trust;

public enum SignatureStatus
{
    /// <summary>Подпись корректна, цепочка доверена.</summary>
    Valid,
    NotSigned,
    /// <summary>Хеш файла не совпадает с подписанным (файл изменён после подписания).</summary>
    HashMismatch,
    /// <summary>Корневой сертификат не доверен или цепочка не строится.</summary>
    Untrusted,
    Expired,
    Revoked,
    /// <summary>Сертификат явно запрещён пользователем/администратором.</summary>
    Distrusted,
    Error,
    /// <summary>Проверка невозможна на текущей ОС.</summary>
    Unsupported,
}

public enum SignatureSource
{
    None,
    Embedded,
    Catalog,
}

public sealed record SignatureVerificationResult(
    SignatureStatus Status,
    SignatureSource Source,
    string? SignerSubject,
    string? IssuerSubject,
    string? Thumbprint,
    string? CatalogFile,
    int HResult,
    string Message)
{
    public bool IsValid => Status == SignatureStatus.Valid;

    public static SignatureVerificationResult Unsupported(string message) =>
        new(SignatureStatus.Unsupported, SignatureSource.None, null, null, null, null, 0, message);

    public static SignatureVerificationResult Failed(int hresult, string message) =>
        new(SignatureStatus.Error, SignatureSource.None, null, null, null, null, hresult, message);
}

/// <summary>Проверка цифровой подписи исполняемого файла (Authenticode / каталоги Windows).</summary>
public interface ISignatureVerifier
{
    SignatureVerificationResult Verify(string path);
}

public sealed record WhitelistDecision(bool IsWhitelisted, string Reason, SignatureVerificationResult? Signature)
{
    public static WhitelistDecision No(string reason, SignatureVerificationResult? signature = null) => new(false, reason, signature);
}

/// <summary>
/// Белый список: решает, является ли файл доверенным системным компонентом,
/// который нельзя помещать в карантин или удалять.
/// </summary>
public interface IWhitelistProvider
{
    WhitelistDecision Evaluate(string path);

    /// <summary>Находится ли путь в защищённом системном каталоге (без проверки подписи).</summary>
    bool IsProtectedLocation(string path);
}
