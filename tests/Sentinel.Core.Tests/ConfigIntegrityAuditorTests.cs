using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Tests;

internal sealed class FakeCertStore(params CertificateInfo[] certs) : ICertificateStoreProvider
{
    public IReadOnlyList<CertificateInfo> GetRootCertificates() => certs;
}

public class FirewallRuleParserTests
{
    [Fact]
    public void Parse_ExtractsFields()
    {
        var rule = FirewallRuleParser.Parse("{GUID}",
            @"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\Temp\evil.exe|Name=Backdoor|");
        Assert.True(rule.Allow);
        Assert.True(rule.Enabled);
        Assert.True(rule.IsInbound);
        Assert.Equal(@"C:\Temp\evil.exe", rule.AppPath);
        Assert.Equal("4444", rule.LocalPort);
        Assert.Equal("Backdoor", rule.DisplayName);
    }

    [Fact]
    public void Parse_BlockRule()
    {
        var rule = FirewallRuleParser.Parse("x", "v2.31|Action=Block|Dir=Out|Active=FALSE|");
        Assert.False(rule.Allow);
        Assert.False(rule.Enabled);
    }

    [Fact]
    public void Parse_EmptyString_Defaults()
    {
        var rule = FirewallRuleParser.Parse("x", null);
        Assert.False(rule.Allow);
        Assert.Null(rule.AppPath);
    }
}

public class ConfigIntegrityAuditorTests
{
    private const string DefenderPaths = @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths";
    private const string DefenderExt = @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions";
    private const string FirewallRules = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    private const string ProxyKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private static ConfigFinding Single(ConfigAuditReport r, ConfigArea area) => Assert.Single(r.ByArea(area));

    [Fact]
    public void Audit_DefenderPathExclusionInUserWritable_FlagsHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, DefenderPaths), @"C:\Users\Bob\AppData\Local\Temp", "0");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        var f = Single(report, ConfigArea.DefenderExclusion);
        Assert.Equal("CFG-DEFENDER-EXCL", f.Finding.Id);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void Audit_DefenderExeExtensionExclusion_FlagsHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, DefenderExt), "exe", "0");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        Assert.Equal(Severity.High, Single(report, ConfigArea.DefenderExclusion).Severity);
    }

    [Fact]
    public void Audit_DefenderNormalPathExclusion_FlagsMedium()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, DefenderPaths), @"C:\Program Files\MyApp", "0");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        Assert.Equal(Severity.Medium, Single(report, ConfigArea.DefenderExclusion).Severity);
    }

    [Fact]
    public void Audit_FirewallAllowInboundFromTemp_FlagsHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, FirewallRules), "{R1}",
            @"v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\Temp\evil.exe|Name=bd|");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        var f = Single(report, ConfigArea.FirewallRule);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void Audit_FirewallAllowForTrustedApp_NotFlagged()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, FirewallRules), "{R2}",
            @"v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\Program Files\App\app.exe|Name=ok|");
        var options = new ConfigIntegrityAuditorOptions { TrustedBinaryDirectories = [@"C:\Program Files"] };
        var report = new ConfigIntegrityAuditor(options, reg).Audit();
        Assert.Empty(report.ByArea(ConfigArea.FirewallRule));
    }

    [Fact]
    public void Audit_ProxyServerAndPac_Flagged()
    {
        var reg = new InMemoryRegistryProvider();
        var key = new RegistryKeyPath(RegistryHive.CurrentUser, ProxyKey);
        reg.Set(key, "ProxyEnable", "1", RegistryValueKind.Dword);
        reg.Set(key, "ProxyServer", "203.0.113.9:8080");
        reg.Set(key, "AutoConfigURL", "http://evil.test/proxy.pac");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        Assert.Contains(report.ByArea(ConfigArea.SystemProxy), f => f.Finding.Id == "CFG-PROXY-SERVER");
        var pac = report.ByArea(ConfigArea.SystemProxy).Single(f => f.Finding.Id == "CFG-PROXY-PAC");
        Assert.Equal(Severity.High, pac.Severity); // http PAC
    }

    [Fact]
    public void Audit_ProxyDisabled_NotFlagged()
    {
        var reg = new InMemoryRegistryProvider();
        var key = new RegistryKeyPath(RegistryHive.CurrentUser, ProxyKey);
        reg.Set(key, "ProxyEnable", "0", RegistryValueKind.Dword);
        reg.Set(key, "ProxyServer", "");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        Assert.Empty(report.ByArea(ConfigArea.SystemProxy));
    }

    [Fact]
    public void Audit_RootCertWithoutOrganization_FlagsMitm()
    {
        var now = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var cert = new CertificateInfo("CN=DO_NOT_TRUST_FiddlerRoot", "CN=DO_NOT_TRUST_FiddlerRoot",
            "AABBCC", now.AddYears(-1), now.AddYears(5), SelfSigned: true, KeyBits: 2048, KeyAlgorithm: "RSA");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions { Now = now },
            certificates: new FakeCertStore(cert)).Audit();
        Assert.Contains(report.ByArea(ConfigArea.RootCertificate), f => f.Finding.Id == "CFG-CERT-NOORG");
    }

    [Fact]
    public void Audit_LegitRootCert_NotFlagged()
    {
        var now = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var cert = new CertificateInfo(
            "CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, C=US",
            "CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, C=US",
            "DD", now.AddYears(-5), now.AddYears(10), SelfSigned: true, KeyBits: 4096, KeyAlgorithm: "RSA");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions { Now = now },
            certificates: new FakeCertStore(cert)).Audit();
        Assert.Empty(report.ByArea(ConfigArea.RootCertificate));
    }

    [Fact]
    public void Audit_WeakAndExpiredAndNonRootCerts_Flagged()
    {
        var now = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var weak = new CertificateInfo("CN=Weak, O=X", "CN=Weak, O=X", "01",
            now.AddYears(-1), now.AddYears(5), SelfSigned: true, KeyBits: 1024, KeyAlgorithm: "RSA");
        var expired = new CertificateInfo("CN=Old, O=Y", "CN=Old, O=Y", "02",
            now.AddYears(-10), now.AddYears(-1), SelfSigned: true, KeyBits: 2048, KeyAlgorithm: "RSA");
        var nonRoot = new CertificateInfo("CN=Leaf, O=Z", "CN=Some Intermediate, O=Z", "03",
            now.AddYears(-1), now.AddYears(5), SelfSigned: false, KeyBits: 2048, KeyAlgorithm: "RSA");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions { Now = now },
            certificates: new FakeCertStore(weak, expired, nonRoot)).Audit();
        Assert.Contains(report.ByArea(ConfigArea.RootCertificate), f => f.Finding.Id == "CFG-CERT-WEAKKEY");
        Assert.Contains(report.ByArea(ConfigArea.RootCertificate), f => f.Finding.Id == "CFG-CERT-EXPIRED");
        Assert.Contains(report.ByArea(ConfigArea.RootCertificate), f => f.Finding.Id == "CFG-CERT-NONROOT");
    }

    [Fact]
    public void Audit_EcdsaRootCert_NotFlaggedAsWeak()
    {
        var now = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var ecdsa = new CertificateInfo("CN=ECC Root, O=CA", "CN=ECC Root, O=CA", "EE",
            now.AddYears(-1), now.AddYears(10), SelfSigned: true, KeyBits: 256, KeyAlgorithm: "ECDSA");
        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions { Now = now },
            certificates: new FakeCertStore(ecdsa)).Audit();
        Assert.Empty(report.ByArea(ConfigArea.RootCertificate));
    }

    [Fact]
    public void Audit_NoProviders_EmptyReport()
    {
        Assert.Empty(new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions()).Audit().Findings);
    }
}
