using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Sentinel.Service;

/// <summary>
/// Защита каталога данных службы: карантин, манифесты отката и <c>allowed_exclusions.json</c>
/// доступны только SYSTEM и администраторам. Иначе непривилегированный процесс мог бы
/// внести себя в белый список или подменить манифест. Интерфейс работает с данными через IPC.
/// </summary>
internal static class DataDirectorySecurity
{
    [SupportedOSPlatform("windows")]
    public static void Harden(string directory)
    {
        var info = Directory.CreateDirectory(directory);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(security);
    }
}
