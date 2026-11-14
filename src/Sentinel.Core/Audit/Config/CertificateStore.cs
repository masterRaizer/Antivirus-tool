using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace Sentinel.Core.Audit.Config;

/// <summary>Сведения о сертификате из хранилища (без приватного ключа).</summary>
public sealed record CertificateInfo(
    string Subject,
    string Issuer,
    string Thumbprint,
    DateTime NotBefore,
    DateTime NotAfter,
    bool SelfSigned,
    int KeyBits,
    string KeyAlgorithm)
{
    public bool IsExpired(DateTime now) => NotAfter < now;

    public bool IsWeakRsa(int minBits) =>
        string.Equals(KeyAlgorithm, "RSA", StringComparison.OrdinalIgnoreCase) && KeyBits > 0 && KeyBits < minBits;

    /// <summary>Содержит ли субъект поле организации (O=). Легитимные корневые CA его имеют.</summary>
    public bool HasOrganization => Subject.Contains("O=", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Поставщик содержимого хранилища корневых сертификатов.</summary>
public interface ICertificateStoreProvider
{
    IReadOnlyList<CertificateInfo> GetRootCertificates();
}

/// <summary>
/// Чтение машинного хранилища доверенных корневых центров (StoreName.Root / LocalMachine)
/// через <see cref="X509Store"/>. Только чтение.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRootCertificateProvider : ICertificateStoreProvider
{
    public IReadOnlyList<CertificateInfo> GetRootCertificates()
    {
        var result = new List<CertificateInfo>();
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        foreach (var cert in store.Certificates)
        {
            int keyBits;
            string algorithm;
            try
            {
                using var rsa = cert.GetRSAPublicKey();
                using var ecdsa = cert.GetECDsaPublicKey();
                if (rsa is not null)
                {
                    keyBits = rsa.KeySize;
                    algorithm = "RSA";
                }
                else if (ecdsa is not null)
                {
                    keyBits = ecdsa.KeySize;
                    algorithm = "ECDSA";
                }
                else
                {
                    keyBits = cert.PublicKey.EncodedKeyValue.RawData.Length * 8;
                    algorithm = cert.PublicKey.Oid.FriendlyName ?? "unknown";
                }
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                keyBits = 0;
                algorithm = "unknown";
            }

            result.Add(new CertificateInfo(
                cert.Subject,
                cert.Issuer,
                cert.Thumbprint,
                cert.NotBefore,
                cert.NotAfter,
                string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase),
                keyBits,
                algorithm));
        }

        return result;
    }
}
