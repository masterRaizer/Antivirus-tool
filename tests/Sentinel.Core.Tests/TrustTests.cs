using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

internal sealed class FakeVerifier : ISignatureVerifier
{
    private readonly Func<string, SignatureVerificationResult> _impl;

    public FakeVerifier(Func<string, SignatureVerificationResult> impl) => _impl = impl;

    public List<string> Calls { get; } = [];

    public static FakeVerifier Valid(string subject) => new(_ => new SignatureVerificationResult(
        SignatureStatus.Valid, SignatureSource.Catalog, subject, "CN=Microsoft Windows Production PCA 2011", "AB", "x.cat", 0, "ok"));

    public static FakeVerifier WithStatus(SignatureStatus status) => new(_ => new SignatureVerificationResult(
        status, SignatureSource.Embedded, null, null, null, null, -1, status.ToString()));

    public SignatureVerificationResult Verify(string path)
    {
        Calls.Add(path);
        return _impl(path);
    }
}

public class SystemWhitelistTests
{
    private const string MsSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    private static (TempDir Tmp, string Protected, string Outside) Layout()
    {
        var tmp = new TempDir();
        var prot = Path.Combine(tmp.Path, "Windows", "System32");
        var outside = Path.Combine(tmp.Path, "Users", "Public");
        Directory.CreateDirectory(prot);
        Directory.CreateDirectory(outside);
        return (tmp, prot, outside);
    }

    private static SystemWhitelist Create(ISignatureVerifier v, string protectedDir) =>
        new(v, new WhitelistOptions { ProtectedDirectories = [protectedDir] });

    [Fact]
    public void SignedMicrosoftFile_InProtectedDirectory_IsWhitelisted()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Windows/System32/kernel32.dll", [1]);
            var decision = Create(FakeVerifier.Valid(MsSubject), prot).Evaluate(file);
            Assert.True(decision.IsWhitelisted, decision.Reason);
            Assert.Equal(SignatureSource.Catalog, decision.Signature!.Source);
        }
    }

    [Theory]
    [InlineData(SignatureStatus.NotSigned)]
    [InlineData(SignatureStatus.HashMismatch)]
    [InlineData(SignatureStatus.Untrusted)]
    [InlineData(SignatureStatus.Revoked)]
    [InlineData(SignatureStatus.Unsupported)]
    [InlineData(SignatureStatus.Error)]
    public void InvalidSignature_InProtectedDirectory_IsNotWhitelisted(SignatureStatus status)
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Windows/System32/dropper.exe", [1]);
            Assert.False(Create(FakeVerifier.WithStatus(status), prot).Evaluate(file).IsWhitelisted);
        }
    }

    [Fact]
    public void ValidThirdPartySignature_InProtectedDirectory_IsNotWhitelisted()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Windows/System32/vendor.sys", [1]);
            var d = Create(FakeVerifier.Valid("CN=Some Vendor LLC, O=Some Vendor LLC, C=US"), prot).Evaluate(file);
            Assert.False(d.IsWhitelisted);
            Assert.Contains("доверенных издателей", d.Reason, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void SignedFile_OutsideProtectedDirectory_IsNotWhitelisted_AndSignatureNotChecked()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Users/Public/kernel32.dll", [1]);
            var verifier = FakeVerifier.Valid(MsSubject);
            Assert.False(Create(verifier, prot).Evaluate(file).IsWhitelisted);
            Assert.Empty(verifier.Calls);
        }
    }

    [Fact]
    public void PrefixLookalikeDirectory_IsNotProtected()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Windows/System32evil/x.exe", [1]);
            var wl = Create(FakeVerifier.Valid(MsSubject), prot);
            Assert.False(wl.IsProtectedLocation(file));
            Assert.False(wl.Evaluate(file).IsWhitelisted);
        }
    }

    [Fact]
    public void PathTraversal_IsNormalizedBeforeCheck()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Users/Public/evil.exe", [1]);
            var tricky = Path.Combine(prot, "..", "..", "Users", "Public", "evil.exe");
            Assert.False(Create(FakeVerifier.Valid(MsSubject), prot).Evaluate(tricky).IsWhitelisted);
            Assert.True(File.Exists(file));
        }
    }

    [Fact]
    public void Symlink_FromProtectedDirectoryToOutside_IsNotWhitelisted()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var target = tmp.Write("Users/Public/payload.exe", [1]);
            var link = Path.Combine(prot, "link.exe");
            try
            {
                File.CreateSymbolicLink(link, target);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return; // нет прав на создание ссылок (Windows без Developer Mode)
            }

            var verifier = FakeVerifier.Valid(MsSubject);
            var decision = Create(verifier, prot).Evaluate(link);
            Assert.False(decision.IsWhitelisted);
            Assert.Empty(verifier.Calls);
        }
    }

    [Fact]
    public void UnavailableVerifier_NeverWhitelists()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Windows/System32/ntdll.dll", [1]);
            Assert.False(Create(new UnavailableSignatureVerifier(), prot).Evaluate(file).IsWhitelisted);
        }
    }

    [Fact]
    public void RequireTrustedPublisherFalse_AcceptsAnyValidSignature()
    {
        var (tmp, prot, _) = Layout();
        using (tmp)
        {
            var file = tmp.Write("Windows/System32/vendor.sys", [1]);
            var wl = new SystemWhitelist(FakeVerifier.Valid("CN=Vendor"), new WhitelistOptions
            {
                ProtectedDirectories = [prot],
                RequireTrustedPublisher = false,
            });
            Assert.True(wl.Evaluate(file).IsWhitelisted);
        }
    }

    [Theory]
    [InlineData(MsSubject, true)]
    [InlineData("CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation", true)]
    [InlineData("CN=\"Microsoft Corporation\", C=US", true)]
    [InlineData("CN=Microsoft Corporation Fake Ltd, O=Evil", false)]
    [InlineData("OU=Microsoft Corporation, CN=Evil", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void TrustedPublisher_MatchesExactCnOrO(string? subject, bool expected)
    {
        var wl = new SystemWhitelist(new UnavailableSignatureVerifier(), new WhitelistOptions());
        Assert.Equal(expected, wl.IsTrustedPublisher(subject));
    }

    [Fact]
    public void DefaultOptions_OnWindowsIncludeSystem32()
    {
        var options = WhitelistOptions.CreateDefault();
        if (OperatingSystem.IsWindows())
        {
            Assert.Contains(options.ProtectedDirectories, d => d.EndsWith("System32", StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            Assert.Empty(options.ProtectedDirectories);
        }
    }
}

public class SignatureVerifierTests
{
    [Theory]
    [InlineData(0, SignatureStatus.Valid)]
    [InlineData(unchecked((int)0x800B0100), SignatureStatus.NotSigned)]
    [InlineData(unchecked((int)0x80096010), SignatureStatus.HashMismatch)]
    [InlineData(unchecked((int)0x800B0109), SignatureStatus.Untrusted)]
    [InlineData(unchecked((int)0x800B0111), SignatureStatus.Distrusted)]
    [InlineData(unchecked((int)0x800B0101), SignatureStatus.Expired)]
    [InlineData(unchecked((int)0x800B010C), SignatureStatus.Revoked)]
    [InlineData(unchecked((int)0x80004005), SignatureStatus.Error)]
    public void WinTrustHResults_MapToStatus(int hr, SignatureStatus expected) =>
        Assert.Equal(expected, WinTrustResult.MapStatus(hr));

    [Fact]
    public void Factory_ReturnsPlatformVerifier()
    {
        var verifier = SignatureVerifierFactory.CreateDefault();
        if (OperatingSystem.IsWindows())
        {
            Assert.IsType<WinTrustSignatureVerifier>(verifier);
        }
        else
        {
            Assert.IsType<UnavailableSignatureVerifier>(verifier);
            Assert.Equal(SignatureStatus.Unsupported, verifier.Verify("/bin/sh").Status);
        }
    }

    [Fact]
    public void WinTrust_OnWindows_UnsignedSyntheticFileIsNotSigned_AndSystemFileIsValid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // реальная проверка WinVerifyTrust возможна только в Windows
        }

        using var tmp = new TempDir();
        var unsigned = tmp.Write("stub.exe", Testing.SyntheticArtifacts.BuildPe());
        var verifier = new WinTrustSignatureVerifier();
        Assert.Equal(SignatureStatus.NotSigned, verifier.Verify(unsigned).Status);

        var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
        var result = verifier.Verify(notepad);
        Assert.Equal(SignatureStatus.Valid, result.Status);
        Assert.Contains("Microsoft", result.SignerSubject, StringComparison.Ordinal);
    }
}
