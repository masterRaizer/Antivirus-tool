using System.Security.Cryptography;
using Sentinel.Core.Behavioral;

namespace Sentinel.Core.Tests;

public class RansomwareBehaviorTests
{
    private sealed class FakeTime(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    private static readonly DateTimeOffset T0 = new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero);

    private static string UserDir(TempDir tmp, string leaf)
    {
        var dir = Path.Combine(tmp.Path, "Users", "Bob", leaf);
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string WriteHighEntropy(string path)
    {
        var bytes = new byte[8192];
        RandomNumberGenerator.Fill(bytes);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static string WriteLowEntropy(string path, int index)
    {
        File.WriteAllText(path, new string((char)('a' + (index % 5)), 4096));
        return path;
    }

    [Fact]
    public void EncryptionBurst_WithHighEntropyExtensionChangeAndDeletion_RaisesAlert()
    {
        using var tmp = new TempDir();
        var docs = UserDir(tmp, "Documents");
        var shield = new RansomwareBehaviorShield(timeProvider: new FakeTime(T0));

        RansomwareAlert? alert = null;
        for (var i = 0; i < 15; i++)
        {
            var original = WriteLowEntropy(Path.Combine(docs, $"report{i}.txt"), i);
            var encrypted = WriteHighEntropy(Path.Combine(docs, $"report{i}.txt.locked"));
            alert ??= shield.Observe(FileEventKind.Created, encrypted);
            alert ??= shield.Observe(FileEventKind.Deleted, original);
        }

        Assert.NotNull(alert);
        Assert.True(alert!.Score >= 75, alert.Reason);
        Assert.Contains(".locked", alert.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BurstAndExtensionWithoutHighEntropy_StaysInGrayZone_NoAlert()
    {
        using var tmp = new TempDir();
        var docs = UserDir(tmp, "Documents");
        var shield = new RansomwareBehaviorShield(timeProvider: new FakeTime(T0));

        RansomwareAlert? alert = null;
        for (var i = 0; i < 15; i++)
        {
            var low = WriteLowEntropy(Path.Combine(docs, $"doc{i}.locked"), i);
            alert ??= shield.Observe(FileEventKind.Created, low);
        }

        Assert.Null(alert); // 30 (всплеск) + 25 (расширение) = 55 < 75 → решение пользователя
    }

    [Fact]
    public void NormalBurstOfTextFiles_IsNotFlagged()
    {
        using var tmp = new TempDir();
        var docs = UserDir(tmp, "Documents");
        var shield = new RansomwareBehaviorShield(timeProvider: new FakeTime(T0));

        for (var i = 0; i < 25; i++)
        {
            var file = WriteLowEntropy(Path.Combine(docs, $"note{i}.txt"), i);
            Assert.Null(shield.Observe(FileEventKind.Created, file));
        }
    }

    [Fact]
    public void RapidSourceFilesInGitAndNodeModules_AreExcluded()
    {
        using var tmp = new TempDir();
        var git = UserDir(tmp, Path.Combine("Documents", "repo", ".git"));
        var modules = UserDir(tmp, Path.Combine("Documents", "repo", "node_modules"));
        var shield = new RansomwareBehaviorShield(timeProvider: new FakeTime(T0));

        for (var i = 0; i < 30; i++)
        {
            var g = WriteHighEntropy(Path.Combine(git, $"obj{i}.pack"));
            var m = WriteHighEntropy(Path.Combine(modules, $"chunk{i}.locked"));
            Assert.Null(shield.Observe(FileEventKind.Created, g));
            Assert.Null(shield.Observe(FileEventKind.Created, m));
        }

        Assert.True(RansomwareBehaviorShield.IsExcludedPath(@"C:\Users\Bob\Documents\repo\.git\index"));
        Assert.True(RansomwareBehaviorShield.IsExcludedPath(@"C:\Users\Bob\proj\node_modules\x\a.js"));
    }

    [Fact]
    public void DuplicateModifiedEvents_WithinDebounce_AreSuppressed()
    {
        using var tmp = new TempDir();
        var docs = UserDir(tmp, "Documents");
        var time = new FakeTime(T0);
        var shield = new RansomwareBehaviorShield(timeProvider: time);
        var file = WriteHighEntropy(Path.Combine(docs, "a.dat"));

        // 20 событий Modified по одному пути за 100 мс — после дебаунса это один файл, всплеска нет.
        for (var i = 0; i < 20; i++)
        {
            Assert.Null(shield.Observe(FileEventKind.Modified, file));
            time.Advance(TimeSpan.FromMilliseconds(5));
        }
    }

    [Fact]
    public void SlidingWindow_DropsOldEvents_SoSlowChangesDoNotAccumulate()
    {
        using var tmp = new TempDir();
        var docs = UserDir(tmp, "Documents");
        var time = new FakeTime(T0);
        var shield = new RansomwareBehaviorShield(timeProvider: time);

        for (var i = 0; i < 20; i++)
        {
            var enc = WriteHighEntropy(Path.Combine(docs, $"slow{i}.locked"));
            var low = WriteLowEntropy(Path.Combine(docs, $"slow{i}.txt"), i);
            Assert.Null(shield.Observe(FileEventKind.Created, enc));
            Assert.Null(shield.Observe(FileEventKind.Deleted, low));
            time.Advance(TimeSpan.FromSeconds(2)); // раз в 2 с — окно 5 с не наберёт порог
        }
    }

    [Fact]
    public void CanaryGuard_DeploysIsCanaryDetectsTamperAndCleansUp()
    {
        using var tmp = new TempDir();
        var docs = UserDir(tmp, "Documents");
        var guard = new CanaryFileGuard();

        var created = guard.Deploy([docs]);
        Assert.NotEmpty(created);
        Assert.All(created, p => Assert.True(guard.IsCanary(p)));
        Assert.False(guard.IsCanary(Path.Combine(docs, "real.txt")));

        var canary = created[0];
        Assert.Null(guard.Inspect(canary)); // нетронут

        File.WriteAllText(canary, "ENCRYPTED-BY-RANSOMWARE");
        var tamper = guard.Inspect(canary);
        Assert.NotNull(tamper);

        var shield = new RansomwareBehaviorShield(timeProvider: new FakeTime(T0));
        var alert = shield.RegisterCanaryTamper(tamper!);
        Assert.Equal(85, alert.Score);

        guard.RemoveUntouched();
        Assert.True(File.Exists(canary)); // изменённую приманку не удаляем
        Assert.Equal(0, guard.Count);
    }

    [Fact]
    public void CanaryGuard_RemoveUntouched_DeletesIntactDecoys()
    {
        using var tmp = new TempDir();
        var docs = UserDir(tmp, "Documents");
        var guard = new CanaryFileGuard();
        var created = guard.Deploy([docs]);

        guard.RemoveUntouched();

        Assert.All(created, p => Assert.False(File.Exists(p)));
    }
}
