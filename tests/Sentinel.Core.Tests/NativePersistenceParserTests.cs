using System.Text;
using Sentinel.Core.Auditors.Persistence;

namespace Sentinel.Core.Tests;

public class NativePersistenceParserTests
{
    private static string Win => @"C:\Windows";

    private static bool Has(IEnumerable<Sentinel.Core.Audit.AuditFinding> findings, string id) => findings.Any(f => f.Id == id);

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\svc.exe\" -k net", @"C:\Program Files\App\svc.exe", "-k net")]
    [InlineData(@"C:\Windows\system32\svchost.exe -k netsvcs", @"C:\Windows\system32\svchost.exe", "-k netsvcs")]
    [InlineData(@"C:\Tools\run.bat arg1 arg2", @"C:\Tools\run.bat", "arg1 arg2")]
    [InlineData(@"C:\Tools\tool.exe", @"C:\Tools\tool.exe", null)]
    [InlineData("rundll32.exe shell32.dll,Control_RunDLL", "rundll32.exe", "shell32.dll,Control_RunDLL")]
    public void Split_SeparatesExecutableFromArguments(string input, string exe, string? args)
    {
        var (executable, arguments) = CommandLineSplitter.Split(input);
        Assert.Equal(exe, executable);
        Assert.Equal(args, arguments);
    }

    [Theory]
    [InlineData(@"\SystemRoot\system32\drivers\x.sys", @"C:\Windows\system32\drivers\x.sys")]
    [InlineData(@"\??\C:\Windows\system32\x.exe", @"C:\Windows\system32\x.exe")]
    [InlineData(@"system32\svchost.exe", @"C:\Windows\system32\svchost.exe")]
    [InlineData("%SystemRoot%\\system32\\x.exe", @"C:\Windows\system32\x.exe")]
    public void NormalizeServiceImagePath_ResolvesSystemPrefixes(string input, string expected) =>
        Assert.Equal(expected, CommandLineSplitter.NormalizeServiceImagePath(input, Win));

    [Fact]
    public void UnquotedServicePath_IsDetected_WithHijackCandidates()
    {
        var svc = new RawServiceRecord("Vuln", @"C:\Program Files\Sub Dir\service.exe -k", 2, 0x10, "LocalSystem");
        var result = UnquotedServicePathDetector.Detect(svc, Win);
        Assert.NotNull(result);
        Assert.Contains(@"C:\Program.exe", result!.HijackPaths);
        Assert.Contains(@"C:\Program Files\Sub.exe", result.HijackPaths);
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\Sub Dir\\service.exe\"")] // в кавычках
    [InlineData(@"C:\Windows\system32\svc.exe")]               // System32
    [InlineData(@"C:\NoSpaces\svc.exe")]                        // без пробелов
    public void UnquotedServicePath_NotFlagged_ForSafeForms(string imagePath) =>
        Assert.Null(UnquotedServicePathDetector.Detect(new RawServiceRecord("S", imagePath, 2, 0x10, "LocalSystem"), Win));

    [Fact]
    public void UnquotedServicePath_NotFlagged_ForManualStartService() =>
        Assert.Null(UnquotedServicePathDetector.Detect(new RawServiceRecord("S", @"C:\Program Files\Sub Dir\svc.exe", 3, 0x10, "LocalSystem"), Win));

    [Fact]
    public void Service_ServiceDll_FailureCommand_UserPath_AreFlagged()
    {
        var svc = new RawServiceRecord("Evil", @"C:\Users\Bob\AppData\Local\Temp\e.exe", 2, 0x10, "LocalSystem")
        {
            ServiceDll = @"C:\Users\Bob\AppData\Roaming\hijack.dll",
            FailureCommand = @"C:\Users\Public\payload.exe",
        };
        var findings = NativePersistenceParser.AnalyzeService(svc, Win).ToList();
        Assert.True(Has(findings, "PERS-SVC-SERVICEDLL"));
        Assert.True(Has(findings, "PERS-SVC-FAILURECMD"));
        Assert.True(Has(findings, "PERS-SVC-USERPATH"));
    }

    [Fact]
    public void RegistryItems_IfeoSafeBootAppInitWinlogon_AreClassified()
    {
        var items = new[]
        {
            new RawRegistryPersistenceItem("IFEO-Debugger", @"HKLM\...\IFEO\sethc.exe", "sethc.exe", @"C:\Windows\system32\cmd.exe"),
            new RawRegistryPersistenceItem("SafeBoot", @"HKLM\...\SafeBoot\Minimal\EvilSvc", "EvilSvc", "Service"),
            new RawRegistryPersistenceItem("SafeBoot", @"HKLM\...\SafeBoot\Minimal\SentinelService", "SentinelService", "Service"),
            new RawRegistryPersistenceItem("AppInit_DLLs", @"HKLM\...\Windows", "AppInit_DLLs", @"C:\evil.dll"),
            new RawRegistryPersistenceItem("Winlogon", @"HKLM\...\Winlogon", "Shell", @"explorer.exe, C:\evil.exe"),
        };
        var findings = items.SelectMany(NativePersistenceParser.AnalyzeRegistryItem).ToList();
        Assert.True(Has(findings, "PERS-IFEO-DEBUGGER"));
        Assert.True(Has(findings, "PERS-APPINIT"));
        Assert.True(Has(findings, "PERS-WINLOGON"));
        Assert.Single(findings, f => f.Id == "PERS-SAFEBOOT"); // SentinelService в белом списке — не находка
        Assert.Contains("EvilSvc", findings.Single(f => f.Id == "PERS-SAFEBOOT").Description);
    }

    [Fact]
    public void Reconcile_FindsGhostOrphanAndHiddenTasks()
    {
        var disk = new[]
        {
            new RawScheduledTaskRecord(@"Microsoft\Windows\UpdateTask", @"\Microsoft\Windows\UpdateTask") { PresentOnDisk = true },
            new RawScheduledTaskRecord(@"OrphanJob", @"\OrphanJob") { PresentOnDisk = true },
            new RawScheduledTaskRecord(@"EvilHidden", @"\EvilHidden") { PresentOnDisk = true, Hidden = true },
        };
        var cache = new[] { @"Microsoft\Windows\UpdateTask", @"GhostJob", @"EvilHidden" };

        var findings = ScheduledTaskReconciler.Reconcile(disk, cache);

        Assert.Contains(findings, f => f.Kind == TaskReconciliationKind.GhostTask && f.TaskName == "GhostJob");
        Assert.Contains(findings, f => f.Kind == TaskReconciliationKind.OrphanXml && f.TaskName == "OrphanJob");
        Assert.Contains(findings, f => f.Kind == TaskReconciliationKind.HiddenNonMicrosoft && f.TaskName == "EvilHidden");
        Assert.DoesNotContain(findings, f => f.TaskName == @"Microsoft\Windows\UpdateTask");
    }

    [Fact]
    public void TaskXml_StreamReader_ParsesExecComHandlerAndHidden_Utf8AndUtf16()
    {
        const string xml = """
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
              <Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
              <Actions>
                <Exec><Command>powershell.exe</Command><Arguments>-enc ZQBj</Arguments><WorkingDirectory>C:\Temp</WorkingDirectory></Exec>
                <ComHandler><ClassId>{00000000-1111-2222-3333-444444444444}</ClassId><Data>payload</Data></ComHandler>
              </Actions>
            </Task>
            """;
        using var tmp = new TempDir();
        foreach (var (name, encoding) in new (string, Encoding)[] { ("u8.xml", new UTF8Encoding(false)), ("u16.xml", Encoding.Unicode) })
        {
            var file = Path.Combine(tmp.Path, name);
            File.WriteAllText(file, xml, encoding);
            var data = TaskXmlStreamReader.ReadFile(file);
            Assert.True(data.Hidden);
            Assert.Equal(true, data.Enabled);
            Assert.Equal("S-1-5-18", data.UserId);
            Assert.Equal("HighestAvailable", data.RunLevel);
            var exec = Assert.Single(data.ExecActions);
            Assert.Equal("powershell.exe", exec.Command);
            Assert.Equal("-enc ZQBj", exec.Arguments);
            var com = Assert.Single(data.ComHandlers);
            Assert.Equal("{00000000-1111-2222-3333-444444444444}", com.ClassId);
        }
    }

    [Fact]
    public void TaskXml_StreamReader_RejectsDtdAndExternalEntities()
    {
        const string xml = """
            <?xml version="1.0"?>
            <!DOCTYPE Task [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <Task><Settings><Enabled>true</Enabled></Settings></Task>
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        Assert.Throws<System.Xml.XmlException>(() => TaskXmlStreamReader.Read(stream));
    }

    [Fact]
    public void TaskDirectoryWalker_SkipsReparsePoints()
    {
        using var tmp = new TempDir();
        var real = Path.Combine(tmp.Path, "Microsoft");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "RealTask"), "<Task/>");
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(tmp.Path, "LinkedTasks"), real);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return;
        }

        var names = TaskDirectoryWalker.Enumerate(tmp.Path).Select(t => t.Name).ToArray();
        Assert.Contains(@"Microsoft\RealTask", names);
        Assert.DoesNotContain(names, n => n.StartsWith("LinkedTasks", StringComparison.Ordinal));
    }

    [Fact]
    public void TaskXml_StreamReader_RealFile_ReadsThroughStreamingPath()
    {
        using var tmp = new TempDir();
        var file = tmp.WriteText("task.xml", "<Task><Settings><Enabled>false</Enabled></Settings><Actions><Exec><Command>calc.exe</Command></Exec></Actions></Task>");
        var data = TaskXmlStreamReader.ReadFile(file);
        Assert.Equal(false, data.Enabled);
        Assert.Equal("calc.exe", Assert.Single(data.ExecActions).Command);
    }

    [Fact]
    public void Analyze_EndToEnd_ProducesComHandlerAndInterpreterFindings()
    {
        var tasks = new[]
        {
            new RawScheduledTaskRecord("Evil", "\\Evil")
            {
                PresentOnDisk = true,
                ComHandlers = [new RawComHandler("{abc}", null, @"C:\Users\Bob\AppData\Local\Temp\evil.dll")],
                ExecActions = [new RawExecAction("powershell.exe", "-enc ZQBjAGgAbw", null)],
            },
        };
        var findings = NativePersistenceParser.Analyze([], tasks, ["Evil"], [], Win);
        Assert.True(Has(findings, "PERS-TASK-COMHANDLER"));
        Assert.Contains(findings, f => f.Id.StartsWith("PROC-", StringComparison.Ordinal)); // интерпретатор -enc
    }
}
