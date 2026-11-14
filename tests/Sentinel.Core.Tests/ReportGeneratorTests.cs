using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Core.Audit;
using Sentinel.Core.Remediation;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

public class ReportGeneratorTests
{
    private const string Sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static FileScanResult Scan(string path, Verdict verdict, Severity severity, string name, SignatureStatus? signature = null) => new()
    {
        Path = path,
        Size = 68,
        Sha256 = Sha,
        Entropy = 4.8127,
        Verdict = verdict,
        Detections = verdict == Verdict.Clean
            ? Array.Empty<Scanning.Detection>()
            : new[] { new Scanning.Detection(name, severity, "test", DetectionSource.Signature, "SNT-TEST-0001", "Описание детекта.", []) },
        Signature = signature is null ? null : new SignatureVerificationResult(signature.Value, SignatureSource.None, null, null, null, null, 0, "нет подписи"),
    };

    private static SentinelReport Sample()
    {
        var builder = new ReportBuilder("scan C:\\Temp --remediate", new DateTime(2026, 11, 14, 10, 0, 0, DateTimeKind.Utc));
        builder.AddFileScan("Файлы",
        [
            Scan(@"C:\Temp\eicar.com", Verdict.Malicious, Severity.High, "EICAR-Test-File"),
            Scan(@"C:\Temp\packed.exe", Verdict.Suspicious, Severity.Medium, "Heuristic.PackedUnsignedPE", SignatureStatus.NotSigned),
            Scan(@"C:\Temp\readme.txt", Verdict.Clean, Severity.Info, "-"),
        ]);
        builder.SetAction(ReportBuilder.FileKey(@"C:\Temp\eicar.com"), FindingActionStatus.Quarantined, "запись карантина abc");
        builder.SetAction("pers:x", new RemediationAction(RemediationActionKind.RollbackPersistence, "HKCU\\Run → Updater", RemediationStatus.Done, "значение удалено") { RollbackId = "rb-1" }, FindingActionStatus.Cleaned);
        return builder.Build(TimeSpan.FromSeconds(3.21), "remediate");
    }

    [Fact]
    public void Builder_ComputesSummary()
    {
        var report = Sample();
        Assert.Equal(3, report.TotalChecked);
        Assert.Equal(2, report.Found);
        Assert.Equal(1, report.Quarantined);
        Assert.Equal(0, report.ConfigCleaned);
        Assert.Equal(Severity.High, report.Findings[0].Severity); // отсортировано по критичности
        var area = Assert.Single(report.Areas);
        Assert.Equal(("Файлы", 3, 2), (area.Name, area.Checked, area.Found));
        Assert.Single(report.Actions);
    }

    [Fact]
    public void Builder_SetAction_UnknownKey_ReturnsFalse_AndDeduplicatesFiles()
    {
        var builder = new ReportBuilder("scan");
        var scan = Scan("/tmp/a.com", Verdict.Malicious, Severity.High, "X");
        builder.AddFileScan("A", [scan]).AddFileScan("B", [scan]);
        Assert.Single(builder.Findings);
        Assert.False(builder.SetAction("file:/nope", FindingActionStatus.Failed, null));
        Assert.True(builder.SetAction(ReportBuilder.FileKey("/tmp/a.com"),
            new QuarantineResult(QuarantineStatus.BlockedByWhitelist, "запрещено")));
        Assert.Equal(FindingActionStatus.Blocked, builder.Findings[0].ActionStatus);
    }

    [Fact]
    public void Json_IsStructured_AndRoundTripsKeyFields()
    {
        using var tmp = new TempDir();
        var path = Path.Combine(tmp.Path, "out", "report.json");
        ReportGenerator.WriteJson(Sample(), path);

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        Assert.Equal("remediate", root.GetProperty("Mode").GetString());
        Assert.Equal(3, root.GetProperty("TotalChecked").GetInt32());
        Assert.Equal(2, root.GetProperty("Found").GetInt32());
        Assert.Equal(1, root.GetProperty("Quarantined").GetInt32());
        Assert.Equal("00:00:03.2100000", root.GetProperty("Duration").GetString());
        var first = root.GetProperty("Findings")[0];
        Assert.Equal("eicar.com", first.GetProperty("Name").GetString());
        Assert.Equal(@"C:\Temp\eicar.com", first.GetProperty("Path").GetString());
        Assert.Equal(Sha, first.GetProperty("Sha256").GetString());
        Assert.Equal("High", first.GetProperty("Severity").GetString());
        Assert.Equal("Quarantined", first.GetProperty("ActionStatus").GetString());
        Assert.Contains("SNT-TEST-0001", first.GetProperty("Rule").GetString());
        Assert.Equal(4.8127, first.GetProperty("Entropy").GetDouble(), 4);
        Assert.Contains("Файлы", File.ReadAllText(path)); // кириллица не превращена в \uXXXX
    }

    [Fact]
    public void Html_IsSelfContained_NoExternalResources()
    {
        var html = ReportGenerator.ToHtml(Sample());

        Assert.StartsWith("<!DOCTYPE html>", html);
        Assert.Contains("default-src 'none'", html);
        Assert.DoesNotMatch(new Regex(@"<(script|link|img|iframe)[^>]+(src|href)\s*=", RegexOptions.IgnoreCase), html);
        Assert.DoesNotMatch(new Regex(@"https?://|@import|url\(", RegexOptions.IgnoreCase), html);
        Assert.Contains("color-scheme:dark", html);
        Assert.Single(Regex.Matches(html, "<script>"));
        Assert.Single(Regex.Matches(html, "<style>"));
    }

    [Fact]
    public void Html_ContainsSummaryCards_AreasTable_FindingDetails_AndFilters()
    {
        var html = ReportGenerator.ToHtml(Sample());

        foreach (var label in new[] { "Всего проверено", "Найдено", "Изолировано", "Очищено в конфигурации", "Время работы", "Проверенные области" })
        {
            Assert.Contains(label, html);
        }

        Assert.Contains("3.21 с", html);
        Assert.Equal(2, Regex.Matches(html, "<article class=\"finding").Count);
        Assert.Contains(@"C:\Temp\eicar.com", html);
        Assert.Contains(Sha, html);
        Assert.Contains("4.8127 бит/байт", html);
        Assert.Contains("NotSigned", html);
        Assert.Contains("EICAR-Test-File [SNT-TEST-0001]", html);
        Assert.Contains("data-severity=\"High\" data-status=\"Quarantined\"", html);
        Assert.Contains("data-severity=\"Medium\" data-status=\"Detected\"", html);
        Assert.Contains("id=\"f-severity\"", html);
        Assert.Contains("id=\"f-status\"", html);
        Assert.Contains("<option value=\"Quarantined\">Изолировано</option>", html);
        Assert.Contains("c.dataset.severity === sev.value", html);
        Assert.Contains("Журнал действий", html);
        Assert.Contains("rb-1", html);
    }

    [Fact]
    public void Html_EscapesAttackerControlledValues()
    {
        var builder = new ReportBuilder("scan <b>x</b>");
        builder.AddFileScan("Файлы", [Scan("/tmp/<script>alert(1)</script>\"onload=\"x.exe", Verdict.Malicious, Severity.Critical, "<img src=x onerror=alert(1)>")]);
        var html = ReportGenerator.ToHtml(builder.Build(TimeSpan.Zero));

        Assert.DoesNotContain("<script>alert(1)", html);
        Assert.DoesNotContain("<img src=x", html);
        Assert.DoesNotContain("<b>x</b>", html);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html);
        Assert.Single(Regex.Matches(html, "<script>"));
    }

    [Fact]
    public void Html_EmptyReport_ShowsCleanState_AndWritesFile()
    {
        using var tmp = new TempDir();
        var path = Path.Combine(tmp.Path, "r.html");
        ReportGenerator.WriteHtml(new ReportBuilder("audit-config").Build(TimeSpan.FromMinutes(2)), path);
        var html = File.ReadAllText(path);
        Assert.Contains("Угроз и отклонений не обнаружено.", html);
        Assert.DoesNotContain("<article", html);
        Assert.Contains("2:00 мин", html);
    }

    [Theory]
    [InlineData(0.5, "0.50 с")]
    [InlineData(75, "1:15 мин")]
    [InlineData(3723, "1:02:03")]
    public void FormatDuration_IsHumanReadable(double seconds, string expected)
    {
        Assert.Equal(expected, ReportGenerator.FormatDuration(TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public void Evidence_IsRenderedInDetails()
    {
        var builder = new ReportBuilder("scan");
        builder.AddFileScan("Файлы", [Scan("/tmp/a.com", Verdict.Malicious, Severity.High, "X")]);
        var html = ReportGenerator.ToHtml(builder.Build(TimeSpan.Zero));
        Assert.Contains("Доказательства (2)", html);
        Assert.Contains(Evidence.Of("verdict", "Malicious").Value, html);
    }
}
