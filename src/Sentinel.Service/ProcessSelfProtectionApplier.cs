using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Sentinel.Core.Protection;

namespace Sentinel.Service;

/// <summary>
/// Применяет усиленный DACL к собственному процессу службы: снимает у Administrators и Authenticated Users права
/// завершения, записи в память, операций с памятью и приостановки (оставляя чтение состояния и SYNCHRONIZE).
/// Расчёт прав — в <see cref="ProcessSelfProtection"/> (ядро, кросс-платформенно); здесь — только биндинг к Win32.
/// Любая ошибка не фатальна: служба продолжает работу без усиленного DACL.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ProcessSelfProtectionApplier
{
    private const uint DaclSecurityInformation = 0x00000004;

    public static bool Harden()
    {
        try
        {
            var process = GetCurrentProcess();
            if (!TryGetDacl(process, out var sd, out var dacl))
            {
                return false;
            }

            var changed = false;
            for (var i = 0; i < dacl.Count; i++)
            {
                if (dacl[i] is not CommonAce ace || ace.AceType != AceType.AccessAllowed)
                {
                    continue;
                }

                var category = Categorize(ace.SecurityIdentifier);
                if (category is ProcessSidCategory.LocalSystem or ProcessSidCategory.SentinelSelf)
                {
                    continue;
                }

                var reduced = ProcessSelfProtection.ReduceMask(ace.AccessMask);
                if (reduced != ace.AccessMask)
                {
                    dacl.RemoveAce(i);
                    dacl.InsertAce(i, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, reduced, ace.SecurityIdentifier, false, null));
                    changed = true;
                }
            }

            if (!changed)
            {
                return false;
            }

            var binary = new byte[sd.BinaryLength];
            sd.GetBinaryForm(binary, 0);
            return SetKernelObjectSecurity(process, DaclSecurityInformation, binary);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    private static ProcessSidCategory Categorize(SecurityIdentifier sid)
    {
        if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            return ProcessSidCategory.LocalSystem;
        }

        if (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
        {
            return ProcessSidCategory.Administrators;
        }

        if (sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid))
        {
            return ProcessSidCategory.AuthenticatedUsers;
        }

        return ProcessSidCategory.Other;
    }

    private static bool TryGetDacl(IntPtr process, out RawSecurityDescriptor descriptor, out RawAcl dacl)
    {
        descriptor = null!;
        dacl = null!;
        uint needed = 0;
        GetKernelObjectSecurity(process, DaclSecurityInformation, null, 0, ref needed);
        if (needed == 0)
        {
            return false;
        }

        var buffer = new byte[needed];
        if (!GetKernelObjectSecurity(process, DaclSecurityInformation, buffer, needed, ref needed))
        {
            return false;
        }

        descriptor = new RawSecurityDescriptor(buffer, 0);
        dacl = descriptor.DiscretionaryAcl ?? new RawAcl(GenericAclRevision, 1);
        descriptor.DiscretionaryAcl = dacl;
        return true;
    }

    private const byte GenericAclRevision = 2;

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(IntPtr handle, uint securityInformation, byte[]? descriptor, uint length, ref uint lengthNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(IntPtr handle, uint securityInformation, byte[] descriptor);
}
