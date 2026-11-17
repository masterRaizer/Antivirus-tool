using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Remediation;
using Sentinel.Core.Reporting;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Tests;

/// <summary>1.3.4: журнал действий с файлами и скрытие справочных записей конфигурации (отчёт Katana, пункты 13, 14).</summary>
public class V134Tests
{
    [Fact]
    public async Task Quarantine_AppendsToFileActionJournal_ForQuarantineRestoreAndDelete()
    {
        using var tmp = new TempDir();
        var file = tmp.WriteText(Path.Combine("samples", "a.bin"), "synthetic sample");
        using var quarantine = new QuarantineManager(new FakeWhitelist(), new QuarantineOptions { QuarantineDirectory = Path.Combine(tmp.Path, "data", "Quarantine") });

        var q = await quarantine.QuarantineAsync(file, "тест");
        await quarantine.RestoreAsync(q.Record!.Id);
        var q2 = await quarantine.QuarantineAsync(file, "тест 2");
        await quarantine.DeleteAsync(q2.Record!.Id);

        Assert.Equal(Path.Combine(tmp.Path, "data", "Logs", QuarantineManager.JournalFileName), quarantine.JournalPath);
        var lines = await File.ReadAllLinesAsync(quarantine.JournalPath);
        Assert.Equal(4, lines.Length);
        Assert.Contains("\"action\":\"quarantine\"", lines[0], StringComparison.Ordinal);
        Assert.Contains("\"action\":\"restore\"", lines[1], StringComparison.Ordinal);
        Assert.Contains("\"action\":\"delete\"", lines[3], StringComparison.Ordinal);
        Assert.All(lines, l => Assert.Contains(q.Record.Sha256, l, StringComparison.Ordinal));
    }

    [Fact]
    public void ConfigInfoFindings_AreHiddenFromReport_ButCounted()
    {
        var info = new ConfigFinding(ConfigArea.RootCertificate, AuditFinding.Create("CFG-CERT-EXPIRED", Severity.Info, "Просроченные штатные корни", "d"));
        var real = new ConfigFinding(ConfigArea.SystemProxy, AuditFinding.Create("CFG-PROXY-PAC", Severity.High, "PAC", "d"));
        var report = new ReportBuilder("test").AddConfigAudit(new ConfigAuditReport([info, real])).Build(TimeSpan.Zero);

        var finding = Assert.Single(report.Findings);
        Assert.Equal("CFG-PROXY-PAC", finding.Rule);
        var area = Assert.Single(report.Areas);
        Assert.Equal(1, area.Found);
        Assert.Contains("справочных записей скрыто: 1", area.Note, StringComparison.Ordinal);
    }
}
