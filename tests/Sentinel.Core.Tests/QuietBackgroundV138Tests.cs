using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>1.3.8: фоновая нагрузка службы (шум вентиляторов на Katana) — кэш результатов проверки и выборочное чтение памяти.</summary>
public class QuietBackgroundV138Tests
{
    private static FileAnalyzer Analyzer(FakeVerifier verifier, Func<long>? generation = null) =>
        new(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), verifier, null,
            new FileAnalyzerOptions { ResultCacheDuration = TimeSpan.FromMinutes(30), CacheGeneration = generation });

    [Fact]
    public void UnchangedFile_IsAnalyzedOnce_ChangedFileAgain()
    {
        using var tmp = new TempDir();
        var file = tmp.Write("svc.exe", SyntheticArtifacts.BuildPe());
        var verifier = FakeVerifier.WithStatus(SignatureStatus.NotSigned);
        var analyzer = Analyzer(verifier);

        analyzer.Analyze(file);
        analyzer.Analyze(file);
        analyzer.Analyze(file, null, new ScoreContext(PersistenceBound: true)); // другой контекст — своя запись
        Assert.Equal(2, verifier.Calls.Count);

        File.WriteAllBytes(file, [.. SyntheticArtifacts.BuildPe(), 0x90]);
        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddMinutes(1));
        analyzer.Analyze(file);
        Assert.Equal(3, verifier.Calls.Count);
    }

    [Fact]
    public void GenerationChange_AndPriorityScan_BypassTheCache()
    {
        using var tmp = new TempDir();
        var file = tmp.Write("svc.exe", SyntheticArtifacts.BuildPe());
        var verifier = FakeVerifier.WithStatus(SignatureStatus.NotSigned);
        long generation = 1;
        var analyzer = Analyzer(verifier, () => generation);

        analyzer.Analyze(file);
        analyzer.Analyze(file);
        generation = 2; // изменён список разрешённого или обновлены базы угроз
        analyzer.Analyze(file);
        analyzer.Analyze(file, new PriorityScanContext("исключение Защитника"));
        analyzer.Analyze(file, new PriorityScanContext("исключение Защитника"));

        Assert.Equal(4, verifier.Calls.Count);
    }

    [Fact]
    public void MemoryScan_SkipsCleanTrustedApps_ButNotHostsUnsignedOrFlagged()
    {
        var trusted = new FileScanResult
        {
            Path = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            Signature = new SignatureVerificationResult(SignatureStatus.Valid, SignatureSource.Embedded, "CN=Google LLC, O=Google LLC", null, null, null, 0, "ok"),
        };
        ProcessSnapshot P(string name, string path) => new() { Pid = 10, Name = name, ExecutablePath = path };

        Assert.False(ProcessAuditor.MemoryScanWorthwhile(P("chrome.exe", trusted.Path), trusted, []));
        Assert.True(ProcessAuditor.MemoryScanWorthwhile(P("chrome.exe", trusted.Path), trusted, [AuditFinding.Create("X", Severity.Low, "t", "d")]));
        Assert.True(ProcessAuditor.MemoryScanWorthwhile(P("rundll32.exe", @"C:\Windows\System32\rundll32.exe"), trusted with { Path = @"C:\Windows\System32\rundll32.exe" }, []));
        Assert.True(ProcessAuditor.MemoryScanWorthwhile(P("tool.exe", @"C:\Users\u\AppData\Local\tool.exe"), trusted, []));
        Assert.True(ProcessAuditor.MemoryScanWorthwhile(P("app.exe", @"C:\Program Files\App\app.exe"), null, []));
    }
}
