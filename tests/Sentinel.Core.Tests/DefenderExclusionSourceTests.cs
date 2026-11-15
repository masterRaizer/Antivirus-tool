using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence.Registry;

namespace Sentinel.Core.Tests;

public sealed class DefenderExclusionSourceTests
{
    private sealed class FakeSource(params DefenderExclusion[] items) : IDefenderExclusionSource
    {
        public IReadOnlyList<DefenderExclusion> GetExclusions() => items;
    }

    [Fact]
    public void Parse_ReadsStringsArraysAndSkipsNullAndNotAdministratorPlaceholders()
    {
        const string json = """
            {"ExclusionPath":["C:\\Tools","C:\\Temp\\x"],"ExclusionProcess":"evil.exe","ExclusionExtension":null,
             "ExclusionIpAddress":["N/A: Must be an administrator or have increased privileges."]}
            """;

        var list = DefenderExclusionJson.Parse(json);

        Assert.Equal(3, list.Count);
        Assert.Contains(list, e => e.Kind == DefenderExclusionKind.Path && e.Value == @"C:\Tools");
        Assert.Contains(list, e => e.Kind == DefenderExclusionKind.Path && e.Value == @"C:\Temp\x");
        Assert.Contains(list, e => e.Kind == DefenderExclusionKind.Process && e.Value == "evil.exe");
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("42")]
    public void Parse_InvalidOrEmptyInput_ReturnsEmpty(string json) =>
        Assert.Empty(DefenderExclusionJson.Parse(json));

    [Fact]
    public void Audit_WithOnlyDefenderSource_ReportsItsExclusions()
    {
        var source = new FakeSource(new DefenderExclusion(DefenderExclusionKind.Process, "powershell.exe", DefenderExclusionJson.SourceKey));

        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), defenderExclusions: source).Audit();

        var exclusion = Assert.Single(report.DefenderExclusions);
        Assert.Equal("powershell.exe", exclusion.Value);
        var finding = Assert.Single(report.Findings);
        Assert.Equal("CFG-DEFENDER-EXCL", finding.Finding.Id);
    }

    [Fact]
    public void Audit_DuplicateOfRegistryExclusion_IsReportedOnce()
    {
        var registry = new InMemoryRegistryProvider();
        registry.Set(new RegistryKeyPath(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"), @"C:\Tools", "0");
        var source = new FakeSource(
            new DefenderExclusion(DefenderExclusionKind.Path, @"c:\tools", DefenderExclusionJson.SourceKey),
            new DefenderExclusion(DefenderExclusionKind.Path, @"C:\Other", DefenderExclusionJson.SourceKey));

        var report = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), registry, defenderExclusions: source).Audit();

        Assert.Equal(2, report.DefenderExclusions.Count);
        Assert.Equal(2, report.Findings.Count(f => f.Finding.Id == "CFG-DEFENDER-EXCL"));
    }
}
