using Sentinel.Core.Signatures;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Testing;

namespace Sentinel.Core.Tests;

public class HostsFileParserTests
{
    [Fact]
    public void Parse_SkipsCommentsAndBlankLines()
    {
        const string content = "# header\n\n127.0.0.1 localhost\n  # comment\n";
        var entries = HostsFileParser.Parse(content);
        var e = Assert.Single(entries);
        Assert.Equal("localhost", e.Host);
        Assert.True(e.IsLoopback);
    }

    [Fact]
    public void Parse_ExpandsMultipleHostsAndInlineComments()
    {
        var entries = HostsFileParser.Parse("0.0.0.0 ads.example a.test # block\n203.0.113.9 evil.test");
        Assert.Equal(3, entries.Count);
        Assert.True(entries[0].IsLoopback); // 0.0.0.0
        Assert.False(entries[2].IsLoopback); // внешний адрес
        Assert.Equal("evil.test", entries[2].Host);
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.5.5.5", true)]
    [InlineData("::1", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("203.0.113.1", false)]
    public void IsLoopbackOrNull_Classifies(string address, bool expected)
    {
        Assert.Equal(expected, HostsFileParser.IsLoopbackOrNull(address));
    }
}

public class ShellLinkParserTests
{
    [Fact]
    public void Parse_ExtractsTargetPath()
    {
        var lnk = SyntheticArtifacts.BuildShellLink(@"C:\Windows\System32\calc.exe");
        var info = ShellLinkParser.Parse(lnk);
        Assert.NotNull(info);
        Assert.Equal(@"C:\Windows\System32\calc.exe", info!.TargetPath);
    }

    [Fact]
    public void Parse_ExtractsTargetAndArguments()
    {
        var lnk = SyntheticArtifacts.BuildShellLink(@"C:\Temp\run.exe", "-silent -x 1");
        var info = ShellLinkParser.Parse(lnk);
        Assert.NotNull(info);
        Assert.Equal(@"C:\Temp\run.exe", info!.TargetPath);
        Assert.Equal("-silent -x 1", info.Arguments);
    }

    [Fact]
    public void Parse_NonLnkData_ReturnsNull()
    {
        Assert.Null(ShellLinkParser.Parse("not a lnk"u8.ToArray()));
        Assert.False(ShellLinkParser.IsShellLink("MZ"u8.ToArray()));
    }
}

public class TaskXmlParserTests
{
    private const string TaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><Author>EvilCorp</Author></RegistrationInfo>
          <Settings><Enabled>true</Enabled></Settings>
          <Actions>
            <Exec><Command>C:\Temp\payload.exe</Command><Arguments>-run</Arguments></Exec>
            <Exec><Command>powershell.exe</Command><Arguments>-enc AAAA</Arguments></Exec>
          </Actions>
        </Task>
        """;

    [Fact]
    public void Parse_ExtractsExecActionsAndMetadata()
    {
        var task = TaskXmlParser.Parse("Evil", "\\Evil", TaskXml);
        Assert.True(task.Enabled);
        Assert.Equal("EvilCorp", task.Author);
        Assert.Equal(2, task.ExecActions.Count);
        Assert.Equal(@"C:\Temp\payload.exe", task.ExecActions[0].Command);
        Assert.Equal("-run", task.ExecActions[0].Arguments);
        Assert.Equal("-enc AAAA", task.ExecActions[1].Arguments);
    }

    [Fact]
    public void Parse_DisabledTask()
    {
        var xml = TaskXml.Replace("<Enabled>true</Enabled>", "<Enabled>false</Enabled>", StringComparison.Ordinal);
        Assert.False(TaskXmlParser.Parse("x", "\\x", xml).Enabled);
    }
}

public class WmiJsonParserTests
{
    [Fact]
    public void ParseConsumers_HandlesArray()
    {
        const string json = """
            [
              {"Name":"Evil","__CLASS":"CommandLineEventConsumer","CommandLineTemplate":"powershell -enc AAAA","ExecutablePath":null,"ScriptText":null},
              {"Name":"Scr","__CLASS":"ActiveScriptEventConsumer","ScriptText":"GET http://x.test"}
            ]
            """;
        var consumers = WmiSubscriptionJsonParser.ParseConsumers(json);
        Assert.Equal(2, consumers.Count);
        Assert.Equal("CommandLineEventConsumer", consumers[0].ConsumerType);
        Assert.Equal("powershell -enc AAAA", consumers[0].CommandLineTemplate);
    }

    [Fact]
    public void ParseConsumers_HandlesSingleObject()
    {
        var consumers = WmiSubscriptionJsonParser.ParseConsumers(
            """{"Name":"One","__CLASS":"CommandLineEventConsumer","CommandLineTemplate":"calc.exe"}""");
        Assert.Single(consumers);
        Assert.Equal("One", consumers[0].Name);
    }

    [Fact]
    public void Parse_EmptyOrInvalid_ReturnsEmpty()
    {
        Assert.Empty(WmiSubscriptionJsonParser.ParseConsumers(null));
        Assert.Empty(WmiSubscriptionJsonParser.ParseConsumers(""));
        Assert.Empty(WmiSubscriptionJsonParser.ParseFilters("{ broken"));
    }
}

public class PathClassifierTests
{
    private static readonly string[] Trusted = [@"C:\Windows\System32", @"C:\Program Files"];

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe", true)]
    [InlineData(@"C:\Program Files\App\app.exe", true)]
    [InlineData(@"C:\Users\Bob\AppData\Local\x.exe", false)]
    public void IsInTrustedDirectory_Works(string path, bool expected)
    {
        Assert.Equal(expected, PathClassifier.IsInTrustedDirectory(path, Trusted));
    }

    [Theory]
    [InlineData(@"C:\Users\Bob\AppData\Local\Temp\x.exe", true)]
    [InlineData(@"C:\Temp\x.exe", true)]
    [InlineData(@"C:\ProgramData\x.exe", true)]
    [InlineData(@"C:\Windows\System32\x.exe", false)]
    public void IsUserWritableLocation_Works(string path, bool expected)
    {
        Assert.Equal(expected, PathClassifier.IsUserWritableLocation(path));
    }
}

public class InMemoryRegistryProviderTests
{
    [Fact]
    public void SetAndGet_RoundTrips()
    {
        var reg = new InMemoryRegistryProvider();
        var key = new RegistryKeyPath(RegistryHive.CurrentUser, @"Software\TestAV\Run");
        reg.Set(key, "Updater", @"C:\x.exe");
        Assert.True(reg.KeyExists(key));
        Assert.Equal(@"C:\x.exe", reg.GetValue(key, "Updater")!.Value);
        Assert.Single(reg.GetValues(key));
    }

    [Fact]
    public void GetSubKeyNames_ReturnsImmediateChildren()
    {
        var reg = new InMemoryRegistryProvider();
        var services = new RegistryKeyPath(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services");
        reg.Set(services with { SubKey = services.SubKey + @"\Svc1" }, "ImagePath", @"C:\a.exe");
        reg.Set(services with { SubKey = services.SubKey + @"\Svc2" }, "ImagePath", @"C:\b.exe");
        var names = reg.GetSubKeyNames(services);
        Assert.Equal(2, names.Count);
        Assert.Contains("Svc1", names);
        Assert.Contains("Svc2", names);
    }
}

public class HostsClassificationTests
{
    private static PersistenceAuditReport Audit(string content)
    {
        using var tmp = new TempDir();
        var hosts = tmp.WriteText("hosts", content);
        return new PersistenceAuditor(new PersistenceAuditorOptions { HostsFilePath = hosts }).Audit();
    }

    [Theory]
    [InlineData("0.0.0.0 vortex.data.microsoft.com")]
    [InlineData("0.0.0.0 v10.events.data.microsoft.com")]
    [InlineData("127.0.0.1 watson.telemetry.microsoft.com")]
    [InlineData("0.0.0.0 nw-umwatson.events.data.microsoft.com")]
    [InlineData("0.0.0.0 settings-win.data.microsoft.com")]
    [InlineData("0.0.0.0 compatexchange.cloudapp.net")]
    [InlineData("0.0.0.0 browser.aria.microsoft.com")]
    public void TelemetryBlock_IsInfoAndNeverAutoRemediated(string line)
    {
        var report = Audit(line + "\n");
        var entry = Assert.Single(report.Entries);
        Assert.Equal(Severity.Info, entry.MaxSeverity);
        Assert.Equal("PERS-HOSTS-TELEMETRY", entry.Findings[0].Id);
    }

    [Fact]
    public void UpdateOrAntivirusBlock_IsMedium()
    {
        var entry = Assert.Single(Audit("0.0.0.0 windowsupdate.com\n").Entries);
        Assert.Equal(Severity.Medium, entry.MaxSeverity);
    }

    [Fact]
    public void RedirectToExternalAddress_IsCritical()
    {
        var entry = Assert.Single(Audit("203.0.113.9 bank.test\n").Entries);
        Assert.Equal(Severity.Critical, entry.MaxSeverity);
    }

    [Fact]
    public void Localhost_IsIgnored() => Assert.Empty(Audit("127.0.0.1 localhost\n::1 localhost\n").Entries);
}
