using Sentinel.Core.Protection;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class SelfProtectionHardeningTests
{
    // ---- ProcessSelfProtection (DACL) ----

    [Fact]
    public void ReduceMask_StripsDangerousRights_KeepsSafeOnes()
    {
        const int full = ProcessSelfProtection.ProcessTerminate | ProcessSelfProtection.ProcessVmWrite
            | ProcessSelfProtection.ProcessVmOperation | ProcessSelfProtection.ProcessSuspendResume
            | ProcessSelfProtection.Synchronize | ProcessSelfProtection.ProcessQueryLimitedInformation
            | ProcessSelfProtection.ProcessVmRead;

        var reduced = ProcessSelfProtection.ReduceMask(full);

        Assert.Equal(0, reduced & ProcessSelfProtection.ProcessTerminate);
        Assert.Equal(0, reduced & ProcessSelfProtection.ProcessVmWrite);
        Assert.Equal(0, reduced & ProcessSelfProtection.ProcessVmOperation);
        Assert.Equal(0, reduced & ProcessSelfProtection.ProcessSuspendResume);
        Assert.Equal(ProcessSelfProtection.Synchronize, reduced & ProcessSelfProtection.Synchronize);
        Assert.Equal(ProcessSelfProtection.ProcessQueryLimitedInformation, reduced & ProcessSelfProtection.ProcessQueryLimitedInformation);
        Assert.Equal(ProcessSelfProtection.ProcessVmRead, reduced & ProcessSelfProtection.ProcessVmRead);
    }

    [Fact]
    public void Harden_StripsDangerousFromAdminAndAuthUsers_PreservesSystemSelfAndDeny()
    {
        const int full = ProcessSelfProtection.ProcessTerminate | ProcessSelfProtection.ProcessVmWrite | ProcessSelfProtection.Synchronize;
        var aces = new[]
        {
            new ProcessDaclAce(ProcessSidCategory.LocalSystem, Allow: true, full),
            new ProcessDaclAce(ProcessSidCategory.SentinelSelf, Allow: true, full),
            new ProcessDaclAce(ProcessSidCategory.Administrators, Allow: true, full),
            new ProcessDaclAce(ProcessSidCategory.AuthenticatedUsers, Allow: true, full),
            new ProcessDaclAce(ProcessSidCategory.Other, Allow: true, full),
            new ProcessDaclAce(ProcessSidCategory.Administrators, Allow: false, ProcessSelfProtection.ProcessTerminate),
        };

        var hardened = ProcessSelfProtection.Harden(aces);

        Assert.Equal(full, hardened[0].Mask); // LocalSystem не тронут
        Assert.Equal(full, hardened[1].Mask); // Sentinel не тронут
        Assert.Equal(0, hardened[2].Mask & ProcessSelfProtection.ProcessTerminate); // admin урезан
        Assert.Equal(0, hardened[3].Mask & ProcessSelfProtection.ProcessVmWrite);   // authusers урезан
        Assert.Equal(0, hardened[4].Mask & ProcessSelfProtection.ProcessTerminate); // other урезан
        Assert.Equal(ProcessSelfProtection.ProcessTerminate, hardened[5].Mask);     // deny-ACE сохранён как есть
        Assert.Equal(aces.Length, hardened.Count);
    }

    // ---- CriticalProcessGuard ----

    private sealed class FakeVerifier(bool microsoft) : ISignatureVerifier
    {
        public SignatureVerificationResult Verify(string path) => microsoft
            ? new SignatureVerificationResult(SignatureStatus.Valid, SignatureSource.Embedded, "CN=Microsoft Windows, O=Microsoft Corporation", "CN=MS", "AB", "x", 0, "ok")
            : new SignatureVerificationResult(SignatureStatus.NotSigned, SignatureSource.Embedded, null, null, null, null, -1, "no");
    }

    [Fact]
    public void Guard_ProtectsKernelPids_SystemProcessesInSystemDir_AndSentinelItself()
    {
        Assert.True(CriticalProcessGuard.IsProtectedProcess(4, "System", null));
        Assert.True(CriticalProcessGuard.IsProtectedProcess(600, "lsass.exe", @"C:\Windows\System32\lsass.exe"));
        Assert.True(CriticalProcessGuard.IsProtectedProcess(700, "svchost.exe", @"C:\Windows\System32\svchost.exe"));
        Assert.True(CriticalProcessGuard.IsProtectedProcess(900, "Sentinel.Service.exe", @"C:\Program Files\Sentinel\Sentinel.Service.exe"));
        Assert.True(CriticalProcessGuard.IsProtectedProcess(650, "lsass.exe", null)); // системный процесс без доступного пути
    }

    [Fact]
    public void Guard_DoesNotProtectMasqueradingSystemNameOutsideSystemDir()
    {
        Assert.False(CriticalProcessGuard.IsProtectedProcess(5000, "lsass.exe", @"C:\Users\Bob\AppData\Local\Temp\lsass.exe"));
        Assert.False(CriticalProcessGuard.IsProtectedProcess(5001, "svchost.exe", @"C:\Users\Public\svchost.exe"));
    }

    [Fact]
    public void Guard_ProtectsTrustedMicrosoftSignedBinary_ButNotUnsignedUserBinary()
    {
        Assert.True(CriticalProcessGuard.IsProtectedProcess(5100, "updater.exe", @"C:\Users\Bob\AppData\Local\app\updater.exe", new FakeVerifier(microsoft: true)));
        Assert.False(CriticalProcessGuard.IsProtectedProcess(5101, "evil.exe", @"C:\Users\Bob\Downloads\evil.exe", new FakeVerifier(microsoft: false)));
    }

    [Fact]
    public void Guard_DoesNotProtectOrdinaryUserProcess() =>
        Assert.False(CriticalProcessGuard.IsProtectedProcess(6000, "game.exe", @"C:\Games\game.exe"));
}
