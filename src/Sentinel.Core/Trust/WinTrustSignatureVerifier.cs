using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core.Trust;

/// <summary>
/// Проверка подписи через WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2).
/// Сначала проверяется встроенная Authenticode-подпись; если её нет — поиск файла
/// в системных каталогах (.cat) через CryptCATAdmin*, так подписано большинство файлов System32.
/// Сертификат подписанта извлекается из состояния WinTrust (WTHelper*), а не из файла повторно.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WinTrustSignatureVerifier : ISignatureVerifier
{
    private readonly bool _checkRevocation;

    /// <param name="checkRevocation">
    /// Проверять отзыв по всей цепочке. Требует сети; при false используются только кешированные CRL.
    /// </param>
    public WinTrustSignatureVerifier(bool checkRevocation = false)
    {
        _checkRevocation = checkRevocation;
    }

    public SignatureVerificationResult Verify(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                return SignatureVerificationResult.Failed(unchecked((int)0x80070002), "Файл не найден.");
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return SignatureVerificationResult.Failed(ex.HResult, ex.Message);
        }

        var embedded = VerifyEmbedded(fullPath);
        if (embedded.Status != SignatureStatus.NotSigned)
        {
            return embedded;
        }

        var catalog = VerifyCatalog(fullPath);
        return catalog ?? embedded;
    }

    private SignatureVerificationResult VerifyEmbedded(string path)
    {
        var filePathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePathPtr,
        };
        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            return RunWinTrust(NativeMethods.WTD_CHOICE_FILE, fileInfoPtr, SignatureSource.Embedded, catalogFile: null);
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
            Marshal.FreeHGlobal(filePathPtr);
        }
    }

    private SignatureVerificationResult? VerifyCatalog(string path)
    {
        // Каталоги Win8+ используют SHA256, более старые — SHA1.
        foreach (var algorithm in new[] { "SHA256", "SHA1" })
        {
            var result = VerifyCatalogWith(path, algorithm);
            if (result is not null)
            {
                return result;
            }
        }

        return null;
    }

    private SignatureVerificationResult? VerifyCatalogWith(string path, string algorithm)
    {
        if (!NativeMethods.CryptCATAdminAcquireContext2(out var catAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
        {
            return null;
        }

        var catInfo = IntPtr.Zero;
        try
        {
            byte[] hash;
            using (var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                uint size = 0;
                NativeMethods.CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref size, null, 0);
                if (size == 0 || size > 1024)
                {
                    return null;
                }

                hash = new byte[size];
                if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref size, hash, 0))
                {
                    return null;
                }
            }

            var prev = IntPtr.Zero;
            catInfo = NativeMethods.CryptCATAdminEnumCatalogFromHash(catAdmin, hash, (uint)hash.Length, 0, ref prev);
            if (catInfo == IntPtr.Zero)
            {
                return null;
            }

            var info = new NativeMethods.CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<NativeMethods.CATALOG_INFO>() };
            if (!NativeMethods.CryptCATCatalogInfoFromContext(catInfo, ref info, 0))
            {
                return null;
            }

            var catalogFile = info.wszCatalogFile;
            var memberTag = Convert.ToHexString(hash);

            var catalogPtr = Marshal.StringToHGlobalUni(catalogFile);
            var tagPtr = Marshal.StringToHGlobalUni(memberTag);
            var memberPtr = Marshal.StringToHGlobalUni(path);
            var hashPtr = Marshal.AllocHGlobal(hash.Length);
            var structPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.Copy(hash, 0, hashPtr, hash.Length);
                var catalogInfo = new NativeMethods.WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = catalogPtr,
                    pcwszMemberTag = tagPtr,
                    pcwszMemberFilePath = memberPtr,
                    pbCalculatedFileHash = hashPtr,
                    cbCalculatedFileHash = (uint)hash.Length,
                    hCatAdmin = catAdmin,
                };
                Marshal.StructureToPtr(catalogInfo, structPtr, false);
                return RunWinTrust(NativeMethods.WTD_CHOICE_CATALOG, structPtr, SignatureSource.Catalog, catalogFile);
            }
            finally
            {
                Marshal.FreeHGlobal(structPtr);
                Marshal.FreeHGlobal(hashPtr);
                Marshal.FreeHGlobal(memberPtr);
                Marshal.FreeHGlobal(tagPtr);
                Marshal.FreeHGlobal(catalogPtr);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return SignatureVerificationResult.Failed(ex.HResult, ex.Message);
        }
        finally
        {
            if (catInfo != IntPtr.Zero)
            {
                NativeMethods.CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            }

            NativeMethods.CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    private SignatureVerificationResult RunWinTrust(uint unionChoice, IntPtr unionPtr, SignatureSource source, string? catalogFile)
    {
        var data = new NativeMethods.WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
            dwUIChoice = NativeMethods.WTD_UI_NONE,
            fdwRevocationChecks = _checkRevocation ? NativeMethods.WTD_REVOKE_WHOLECHAIN : NativeMethods.WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pUnion = unionPtr,
            dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY,
            dwProvFlags = _checkRevocation
                ? NativeMethods.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                : NativeMethods.WTD_CACHE_ONLY_URL_RETRIEVAL | NativeMethods.WTD_REVOCATION_CHECK_NONE,
        };

        var action = NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2;
        var hr = NativeMethods.WinVerifyTrust(NativeMethods.INVALID_HANDLE_VALUE, ref action, ref data);
        string? subject = null, issuer = null, thumbprint = null;
        try
        {
            if (data.hWVTStateData != IntPtr.Zero)
            {
                (subject, issuer, thumbprint) = ReadSigner(data.hWVTStateData);
            }
        }
        finally
        {
            // Освобождение состояния WinTrust; код возврата CLOSE не влияет на вердикт.
            data.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
            _ = NativeMethods.WinVerifyTrust(NativeMethods.INVALID_HANDLE_VALUE, ref action, ref data);
        }

        var status = WinTrustResult.MapStatus(hr);
        return new SignatureVerificationResult(
            status,
            status == SignatureStatus.NotSigned ? SignatureSource.None : source,
            subject,
            issuer,
            thumbprint,
            catalogFile,
            hr,
            WinTrustResult.Describe(hr));
    }

    private static (string?, string?, string?) ReadSigner(IntPtr stateData)
    {
        var provData = NativeMethods.WTHelperProvDataFromStateData(stateData);
        if (provData == IntPtr.Zero)
        {
            return (null, null, null);
        }

        var signer = NativeMethods.WTHelperGetProvSignerFromChain(provData, 0, false, 0);
        if (signer == IntPtr.Zero)
        {
            return (null, null, null);
        }

        var provCert = NativeMethods.WTHelperGetProvCertFromChain(signer, 0);
        if (provCert == IntPtr.Zero)
        {
            return (null, null, null);
        }

        // CRYPT_PROVIDER_CERT { DWORD cbStruct; PCCERT_CONTEXT pCert; ... } — указатель выровнен по размеру указателя.
        var certContext = Marshal.ReadIntPtr(provCert, IntPtr.Size);
        if (certContext == IntPtr.Zero)
        {
            return (null, null, null);
        }

        // Конструктор дублирует CERT_CONTEXT, поэтому сертификат живёт дольше состояния WinTrust.
        using var cert = new X509Certificate2(certContext);
        return (cert.Subject, cert.Issuer, cert.Thumbprint);
    }

    private static class NativeMethods
    {
        public const uint WTD_UI_NONE = 2;
        public const uint WTD_REVOKE_NONE = 0;
        public const uint WTD_REVOKE_WHOLECHAIN = 1;
        public const uint WTD_CHOICE_FILE = 1;
        public const uint WTD_CHOICE_CATALOG = 2;
        public const uint WTD_STATEACTION_VERIFY = 1;
        public const uint WTD_STATEACTION_CLOSE = 2;
        public const uint WTD_REVOCATION_CHECK_NONE = 0x10;
        public const uint WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x80;
        public const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

        public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        public static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 => new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential)]
        public struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pUnion;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CATALOG_INFO
        {
            public uint cbStruct;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", ExactSpelling = true)]
        public static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        public static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        public static extern IntPtr WTHelperGetProvSignerFromChain(
            IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        public static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminAcquireContext2(
            out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminCalcHashFromFileHandle2(
            IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, [Out] byte[]? pbHash, uint dwFlags);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr CryptCATAdminEnumCatalogFromHash(
            IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
    }
}
