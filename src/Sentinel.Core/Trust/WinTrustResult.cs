namespace Sentinel.Core.Trust;

/// <summary>Отображение HRESULT функции WinVerifyTrust в статус подписи (платформонезависимо).</summary>
internal static class WinTrustResult
{
    internal static SignatureStatus MapStatus(int hr) => unchecked((uint)hr) switch
    {
        0 => SignatureStatus.Valid,
        0x800B0100 => SignatureStatus.NotSigned,       // TRUST_E_NOSIGNATURE
        0x800B0003 => SignatureStatus.NotSigned,       // TRUST_E_SUBJECT_FORM_UNKNOWN
        0x800B0001 => SignatureStatus.NotSigned,       // TRUST_E_PROVIDER_UNKNOWN
        0x80096010 => SignatureStatus.HashMismatch,    // TRUST_E_BAD_DIGEST
        0x80096011 => SignatureStatus.HashMismatch,    // TRUST_E_MALFORMED_SIGNATURE
        0x800B0111 => SignatureStatus.Distrusted,      // TRUST_E_EXPLICIT_DISTRUST
        0x800B0004 => SignatureStatus.Untrusted,       // TRUST_E_SUBJECT_NOT_TRUSTED
        0x800B0109 => SignatureStatus.Untrusted,       // CERT_E_UNTRUSTEDROOT
        0x800B010A => SignatureStatus.Untrusted,       // CERT_E_CHAINING
        0x800B010F => SignatureStatus.Untrusted,       // CERT_E_CN_NO_MATCH
        0x80092026 => SignatureStatus.Untrusted,       // CRYPT_E_SECURITY_SETTINGS
        0x800B0101 => SignatureStatus.Expired,         // CERT_E_EXPIRED
        0x800B010C => SignatureStatus.Revoked,         // CERT_E_REVOKED
        0x80092010 => SignatureStatus.Revoked,         // CRYPT_E_REVOKED
        _ => SignatureStatus.Error,
    };

    internal static string Describe(int hr) => unchecked((uint)hr) switch
    {
        0 => "Подпись действительна.",
        0x800B0100 => "Файл не подписан.",
        0x80096010 => "Хеш файла не совпадает с подписью (файл изменён).",
        0x800B0111 => "Сертификат явно запрещён.",
        0x800B0109 => "Корневой сертификат не является доверенным.",
        0x800B0101 => "Срок действия сертификата истёк.",
        0x800B010C or 0x80092010 => "Сертификат отозван.",
        _ => $"WinVerifyTrust вернул 0x{hr:X8}.",
    };
}
