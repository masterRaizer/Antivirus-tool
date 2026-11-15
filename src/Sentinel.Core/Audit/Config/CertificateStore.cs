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
    /// <summary>Корень из программы доверенных корней Microsoft (в LocalMachine\AuthRoot) либо штатный исторический корень Microsoft.</summary>
    public bool IsStandard { get; init; }

    /// <summary>Хранилище-источник: <c>LocalMachine\Root</c> или <c>CurrentUser\Root</c>.</summary>
    public string Store { get; init; } = string.Empty;

    /// <summary>Штатные исторические корни Microsoft, оставленные для обратной совместимости старых подписей.</summary>
    public bool IsKnownMicrosoftRoot =>
        Subject.StartsWith("CN=Microsoft Root", StringComparison.OrdinalIgnoreCase)
        || Subject.StartsWith("CN=Microsoft Authenticode", StringComparison.OrdinalIgnoreCase)
        || Subject.StartsWith("CN=Microsoft ECC", StringComparison.OrdinalIgnoreCase)
        || Subject.StartsWith("CN=Microsoft RSA Root", StringComparison.OrdinalIgnoreCase);

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
/// Чтение хранилищ доверенных корней (LocalMachine\\Root и CurrentUser\\Root) через <see cref="X509Store"/> с дедупликацией по отпечатку;
/// штатные корни определяются по LocalMachine\\AuthRoot. Только чтение.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRootCertificateProvider : ICertificateStoreProvider
{
    public IReadOnlyList<CertificateInfo> GetRootCertificates()
    {
        // Корни из автообновляемого списка доверия Microsoft (CTL) лежат в LocalMachine\AuthRoot: это штатные корни.
        var standard = ReadThumbprints(StoreName.AuthRoot, StoreLocation.LocalMachine);
        var result = new Dictionary<string, CertificateInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var (location, label) in new[] { (StoreLocation.LocalMachine, "LocalMachine\\Root"), (StoreLocation.CurrentUser, "CurrentUser\\Root") })
        {
            using var store = new X509Store(StoreName.Root, location);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                continue;
            }

            foreach (var cert in store.Certificates)
            {
                // Один и тот же сертификат часто присутствует в обоих хранилищах: учитывается один раз по отпечатку.
                if (result.ContainsKey(cert.Thumbprint))
                {
                    continue;
                }

                result[cert.Thumbprint] = Describe(cert, label, standard.Contains(cert.Thumbprint));
            }
        }

        return [.. result.Values];
    }

    private static HashSet<string> ReadThumbprints(StoreName name, StoreLocation location)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var cert in store.Certificates)
            {
                set.Add(cert.Thumbprint);
            }
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Хранилища может не быть (например, при отключённом автообновлении корней) — тогда «штатными» считаются только известные корни Microsoft.
        }

        return set;
    }

    private static CertificateInfo Describe(X509Certificate2 cert, string label, bool standard)
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

        return new CertificateInfo(
            cert.Subject,
            cert.Issuer,
            cert.Thumbprint,
            cert.NotBefore,
            cert.NotAfter,
            string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase),
            keyBits,
            algorithm)
        {
            IsStandard = standard,
            Store = label,
        };
    }
}
