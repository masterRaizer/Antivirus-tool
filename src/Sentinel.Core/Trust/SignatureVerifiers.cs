namespace Sentinel.Core.Trust;

/// <summary>
/// Верификатор для ОС без WinTrust: честно сообщает, что проверка недоступна.
/// Такой результат никогда не считается доверенным, поэтому белый список
/// на таких платформах не срабатывает (fail-closed).
/// </summary>
public sealed class UnavailableSignatureVerifier : ISignatureVerifier
{
    public SignatureVerificationResult Verify(string path) =>
        SignatureVerificationResult.Unsupported("Проверка Authenticode доступна только в Windows (WinVerifyTrust).");
}

public static class SignatureVerifierFactory
{
    public static ISignatureVerifier CreateDefault(bool checkRevocation = false) =>
        OperatingSystem.IsWindows()
            ? new WinTrustSignatureVerifier(checkRevocation)
            : new UnavailableSignatureVerifier();
}
