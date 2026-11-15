using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>Исправления по разбору реального отчёта 1.0.0: брандмауэр, корневые сертификаты, автозагрузка, WMI.</summary>
public class AuditNoiseReductionTests
{
    private const string FirewallRules = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
    private static readonly DateTime Now = new(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc);

    private static FileAnalyzer Analyzer(ISignatureVerifier verifier) =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), verifier);

    private static InMemoryRegistryProvider FirewallWith(params (string Id, string Name, string App, string Dir, string Protocol)[] rules)
    {
        var reg = new InMemoryRegistryProvider();
        foreach (var r in rules)
        {
            reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, FirewallRules), r.Id,
                $"v2.31|Action=Allow|Active=TRUE|Dir={r.Dir}|Protocol={r.Protocol}|App={r.App}|Name={r.Name}|");
        }

        return reg;
    }

    private static ConfigFinding[] Firewall(InMemoryRegistryProvider reg, FileAnalyzer? analyzer = null, Func<string, bool>? allowed = null) =>
        new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions { IsUserAllowed = allowed }, reg, analyzer: analyzer).Audit().ByArea(ConfigArea.FirewallRule).ToArray();

    [Fact]
    public void Firewall_TcpAndUdpRulesOfOneApp_ProduceOneCard()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var app = tmp.Write(Path.Combine("AppData", "Local", "Programs", "Opera GX", "opera.exe"), SyntheticBytes());
        var reg = FirewallWith(("{1}", "opera.exe", app, "In", "6"), ("{2}", "opera.exe", app, "In", "17"));

        var findings = Firewall(reg, Analyzer(new UnavailableSignatureVerifier()));

        var single = Assert.Single(findings);
        Assert.Equal(Severity.Info, single.Severity); // неподписанная пользовательская программа — только журнал
    }

    [Fact]
    public void Firewall_TrustedPublisherSignature_IsClean()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var app = tmp.Write(Path.Combine("AppData", "Local", "Programs", "Discord", "Discord.exe"), SyntheticBytes());
        var verifier = FakeVerifier.Valid("CN=Discord Inc., O=Discord Inc., L=San Francisco, S=California, C=US");
        Assert.Empty(Firewall(FirewallWith(("{1}", "Discord", app, "In", "6")), Analyzer(verifier)));
    }

    [Fact]
    public void Firewall_ValidSignatureOfUnknownPublisher_IsNotTrustedAutomatically()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var app = tmp.Write(Path.Combine("AppData", "Local", "Programs", "Tool", "tool.exe"), SyntheticBytes());
        var verifier = FakeVerifier.Valid("CN=Red Fox UK Limited, O=Red Fox UK Limited");
        var finding = Assert.Single(Firewall(FirewallWith(("{1}", "tool", app, "In", "6")), Analyzer(verifier)));
        Assert.Equal(Severity.Info, finding.Severity);
    }

    [Fact]
    public void Firewall_AppInTemp_IsHigh_AndAllowListSilencesIt()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var app = tmp.Write(Path.Combine("Users", "Bob", "AppData", "Local", "Temp", "dropper.exe"), SyntheticBytes());
        var reg = FirewallWith(("{1}", "dropper", app, "In", "6"));

        var finding = Assert.Single(Firewall(reg, Analyzer(new UnavailableSignatureVerifier())));
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Empty(Firewall(reg, Analyzer(new UnavailableSignatureVerifier()), allowed: p => p == app));
    }

    [Fact]
    public void Firewall_HighThreatScore_IsHighEvenOutsideTemp()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var app = tmp.Write(Path.Combine("AppData", "Local", "Programs", "Bad", "bad.exe"), Sentinel.Core.Detection.Eicar.CreateTestFileBytes());
        var finding = Assert.Single(Firewall(FirewallWith(("{1}", "bad", app, "In", "6")), Analyzer(new UnavailableSignatureVerifier())));
        Assert.Equal(Severity.High, finding.Severity);
    }

    [Fact]
    public void Firewall_MissingFile_NoCard()
    {
        var reg = FirewallWith(("{1}", "gone", @"C:\Users\Bob\AppData\Local\Programs\Gone\gone.exe", "In", "6"));
        Assert.Single(Firewall(reg, Analyzer(new UnavailableSignatureVerifier())));
    }

    private static CertificateInfo Cert(string subject, string thumb, DateTime notBefore, DateTime notAfter, int bits = 2048, bool standard = false, bool self = true) =>
        new(subject, self ? subject : "CN=Issuer, O=Issuer", thumb, notBefore, notAfter, self, bits, "RSA") { IsStandard = standard };

    private static ConfigFinding[] Certs(params CertificateInfo[] certs) =>
        new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions { Now = Now }, certificates: new FakeCertStore(certs)).Audit().ByArea(ConfigArea.RootCertificate).ToArray();

    [Fact]
    public void Certificates_SameThumbprintInBothStores_ReportedOnce()
    {
        var mitm = Cert("CN=Corp Proxy CA", "AA11", Now.AddDays(-20), Now.AddYears(3));
        var findings = Certs(mitm, mitm with { Store = "CurrentUser\\Root" });
        Assert.Single(findings);
        Assert.Equal("CFG-CERT-NOORG", findings[0].Finding.Id);
        Assert.Equal(Severity.Medium, findings[0].Severity); // свежий нестандартный корень без организации
    }

    [Fact]
    public void Certificates_HistoricalMicrosoftRoots_AreNotNoOrg()
    {
        var findings = Certs(
            Cert("CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com", "01", Now.AddYears(-25), Now.AddYears(-3), bits: 4096),
            Cert("CN=Microsoft Root Authority, OU=Microsoft Corporation, OU=Copyright (c) 1997 Microsoft Corp.", "02", Now.AddYears(-29), Now.AddYears(-3)));
        Assert.DoesNotContain(findings, f => f.Finding.Id == "CFG-CERT-NOORG");
        Assert.All(findings, f => Assert.Equal(Severity.Info, f.Severity));
    }

    [Fact]
    public void Certificates_StandardExpiredAndWeak_AreOneInfoCardEach_NotHundreds()
    {
        var many = Enumerable.Range(0, 158).Select(i => Cert($"CN=Old CA {i}, O=Vendor {i}", $"T{i:D4}", Now.AddYears(-20), Now.AddYears(-1), standard: true))
            .Concat(Enumerable.Range(0, 19).Select(i => Cert($"CN=Weak CA {i}, O=Vendor {i}", $"W{i:D4}", Now.AddYears(-20), Now.AddYears(5), bits: 1024, standard: true)))
            .ToArray();

        var findings = Certs(many);

        Assert.Equal(2, findings.Length);
        Assert.All(findings, f => Assert.Equal(Severity.Info, f.Severity));
    }

    [Fact]
    public void Certificates_StandardRootWithoutOrganization_IsNotFlagged()
    {
        Assert.Empty(Certs(Cert("CN=ComSign Advanced Security CA", "C1", Now.AddYears(-15), Now.AddYears(10), bits: 4096, standard: true)));
    }

    [Fact]
    public void Certificates_VendorCodeSigningCertInRootStore_IsInfoOnly()
    {
        var logitech = Cert("CN=Logitech Inc, O=Logitech Inc, L=Newark", "L1", Now.AddYears(-1), Now.AddYears(2), bits: 4096, self: false);
        var other = Cert("CN=Unknown Vendor, O=Unknown Vendor", "L2", Now.AddYears(-1), Now.AddYears(2), bits: 4096, self: false);
        var findings = Certs(logitech, other);
        Assert.Equal(Severity.Info, findings.Single(f => f.Finding.Evidence.Any(e => e.Value.Contains("Logitech", StringComparison.Ordinal))).Severity);
        Assert.Equal(Severity.Medium, findings.Single(f => f.Finding.Evidence.Any(e => e.Value.Contains("Unknown Vendor", StringComparison.Ordinal))).Severity);
    }

    private static byte[] SyntheticBytes() => Sentinel.Core.Testing.SyntheticArtifacts.BuildPe();

    private static PersistenceAuditReport Persistence(InMemoryRegistryProvider reg, FileAnalyzer analyzer, IWmiSubscriptionProvider? wmi = null,
        ITaskSchedulerProvider? tasks = null, Func<string, bool>? allowed = null) =>
        new PersistenceAuditor(new PersistenceAuditorOptions { IsUserAllowed = allowed }, reg, tasks, wmi, analyzer).Audit();

    private static void Service(InMemoryRegistryProvider reg, string name, string image, string start = "3")
    {
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, ServicesKey + "\\" + name);
        reg.Set(key, "ImagePath", image);
        reg.Set(key, "Start", start, RegistryValueKind.Dword);
    }

    [Fact]
    public void ServiceInUserDirectory_SignedByMicrosoftOrGoogle_IsNotFlagged_ButUnknownPublisherDriverIs()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var defender = tmp.Write(Path.Combine("ProgramData", "Microsoft", "Windows Defender", "Platform", "MpDefenderCoreService.exe"), SyntheticBytes());
        var driver = tmp.Write(Path.Combine("Users", "Bob", "AppData", "Local", "Temp", "72r2MSxm.sys"), SyntheticBytes());
        var reg = new InMemoryRegistryProvider();
        Service(reg, "MDCoreSvc", "\"" + defender + "\"", "2");
        Service(reg, "72r2MSxm.sys", @"\??\" + driver);

        var trusted = Persistence(reg, Analyzer(FakeVerifier.Valid("CN=Microsoft Windows Publisher, O=Microsoft Corporation")));
        Assert.DoesNotContain(trusted.Entries, e => e.Findings.Any(f => f.Id == "PERS-SERVICE-USERWRITABLE"));

        var redFox = Persistence(reg, Analyzer(FakeVerifier.Valid("CN=Red Fox UK Limited, OU=Development, O=Red Fox UK Limited")));
        Assert.Equal(2, redFox.Entries.Count(e => e.Findings.Any(f => f.Id == "PERS-SERVICE-USERWRITABLE")));
    }

    [Fact]
    public void ServiceInUserDirectory_AllowedByUser_IsNotFlagged()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var tool = tmp.Write(Path.Combine("Users", "Bob", "AppData", "Local", "Tool", "svc.exe"), SyntheticBytes());
        var reg = new InMemoryRegistryProvider();
        Service(reg, "ToolSvc", "\"" + tool + "\"", "2");
        Assert.Empty(Persistence(reg, Analyzer(new UnavailableSignatureVerifier()), allowed: p => p == tool).Entries.Where(e => e.Findings.Any(f => f.Id == "PERS-SERVICE-USERWRITABLE")));
        Assert.Single(Persistence(reg, Analyzer(new UnavailableSignatureVerifier())).Entries.Where(e => e.Findings.Any(f => f.Id == "PERS-SERVICE-USERWRITABLE")));
    }

    [Fact]
    public void ScheduledTaskAndStartup_SignedByGoogle_AreNotFlagged()
    {
        using var tmp = TempDir.OutsideSystemTemp();
        var updater = tmp.Write(Path.Combine("Users", "Bob", "AppData", "Local", "Google", "GoogleUpdater", "updater.exe"), SyntheticBytes());
        var task = new ScheduledTaskInfo("GoogleUpdaterTask", "\\GoogleUser\\GoogleUpdater\\Task", true, [new ScheduledTaskAction(updater, "--wake")]);
        var report = Persistence(new InMemoryRegistryProvider(), Analyzer(FakeVerifier.Valid("CN=Google LLC, O=Google LLC, L=Mountain View")), tasks: new FakeTaskProvider(task));
        Assert.DoesNotContain(report.Entries, e => e.Findings.Any(f => f.Id == "PERS-TASK-USERWRITABLE"));

        var unsigned = Persistence(new InMemoryRegistryProvider(), Analyzer(new UnavailableSignatureVerifier()), tasks: new FakeTaskProvider(task));
        Assert.Contains(unsigned.Entries, e => e.Findings.Any(f => f.Id == "PERS-TASK-USERWRITABLE"));
    }

    [Fact]
    public void WmiBuiltInScmEventLogConsumer_IsNotReported_ButCommandLineConsumerIs()
    {
        var scm = new WmiConsumer("SCM Event Log Consumer", "NTEventLogEventConsumer", null, null, null);
        var scmLegacy = new WmiConsumer("SCM Event Log Consumer", "EventConsumer", null, null, null);
        var evil = new WmiConsumer("SCM Event Log Consumer", "CommandLineEventConsumer", null, "powershell.exe -enc AAAA", null);
        var other = new WmiConsumer("Updater", "CommandLineEventConsumer", null, "calc.exe", null);
        var snapshot = new WmiSubscriptionSnapshot([], [scm, scmLegacy, evil, other]);

        var report = Persistence(new InMemoryRegistryProvider(), Analyzer(new UnavailableSignatureVerifier()), new FakeWmiProvider(snapshot));

        Assert.Equal(2, report.Entries.Count(e => e.Findings.Any(f => f.Id == "PERS-WMI-CONSUMER")));
    }

    [Theory]
    [InlineData("CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US", true)]
    [InlineData("CN=Ollama Inc., O=Ollama Inc., L=Toronto, S=Ontario, C=CA", true)]
    [InlineData("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond", true)]
    [InlineData("CN=Opera Norway AS, O=Opera Norway AS, C=NO", true)]
    [InlineData("CN=Red Fox UK Limited, OU=Development, O=Red Fox UK Limited", false)]
    [InlineData("CN=Not Google LLC Fake, O=Fake Corp", false)]
    [InlineData("O=\"Spotify AB\", C=SE", true)]
    [InlineData("", false)]
    public void TrustedPublishers_MatchWholeFieldsOnly(string subject, bool expected) => Assert.Equal(expected, TrustedPublishers.IsTrusted(subject));
}
