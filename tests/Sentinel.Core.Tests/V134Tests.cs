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

/// <summary>Раздел «Автозагрузка и службы»: штатные автозапускаемые службы и включённые задачи видны, драйверы — нет.</summary>
public class StartupCleanEntriesTests
{
    [Fact]
    public void IncludeCleanEntries_ListsAutoServicesAndEnabledTasks_ButNotDriversOrDisabled()
    {
        var reg = new Audit.Persistence.Registry.InMemoryRegistryProvider();
        void Service(string name, string image, string start, string type)
        {
            var key = new Audit.Persistence.Registry.RegistryKeyPath(Audit.Persistence.Registry.RegistryHive.LocalMachine, $@"SYSTEM\CurrentControlSet\Services\{name}");
            reg.Set(key, "ImagePath", image).Set(key, "Start", start, Audit.Persistence.Registry.RegistryValueKind.Dword)
                .Set(key, "Type", type, Audit.Persistence.Registry.RegistryValueKind.Dword);
        }

        Service("Spooler", @"C:\Windows\System32\spoolsv.exe", "2", "16");
        Service("ManualSvc", @"C:\Windows\System32\manual.exe", "3", "16");
        Service("SomeDriver", @"\SystemRoot\System32\drivers\some.sys", "2", "1");
        var enabled = new Audit.Persistence.Tasks.ScheduledTaskInfo("Backup", @"\Backup", true, [new(@"C:\Windows\System32\wbem\wmic.exe", null)]);
        var disabled = new Audit.Persistence.Tasks.ScheduledTaskInfo("Old", @"\Old", false, [new(@"C:\Windows\System32\cmd.exe", null)]);
        var tasks = new FakeTaskProvider(enabled, disabled);

        var clean = new Audit.Persistence.PersistenceAuditor(new Audit.Persistence.PersistenceAuditorOptions { IncludeCleanEntries = true }, reg, tasks).Audit();
        var flaggedOnly = new Audit.Persistence.PersistenceAuditor(new Audit.Persistence.PersistenceAuditorOptions(), reg, tasks).Audit();

        Assert.Equal(["Spooler"], clean.Entries.Where(e => e.Kind == Audit.Persistence.PersistenceKind.Service).Select(e => e.Name));
        Assert.Equal(["Backup"], clean.Entries.Where(e => e.Kind == Audit.Persistence.PersistenceKind.ScheduledTask).Select(e => e.Name));
        Assert.All(clean.Entries, e => Assert.False(e.HasFindings));
        Assert.Empty(flaggedOnly.Entries);
    }
}
