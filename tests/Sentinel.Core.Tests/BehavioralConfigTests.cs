using Sentinel.Core.ThreatIntel;

namespace Sentinel.Core.Tests;

public class BehavioralConfigTests
{
    [Fact]
    public void OldConfigWithoutBehavioralFlags_DefaultsToEnabled()
    {
        using var tmp = new TempDir();
        var path = System.IO.Path.Combine(tmp.Path, SentinelConfigStore.FileName);
        // Конфиг времён v1.1.x — новых полей нет.
        File.WriteAllText(path, "{\"usbShieldEnabled\":true,\"autoUpdateDatabases\":false}");
        var config = new SentinelConfigStore(path).Load();

        Assert.True(config.EnableRansomwareShield);
        Assert.True(config.EnableCanaryFiles);
        Assert.True(config.EnableUsbShield);
        Assert.False(config.BehavioralShadowMode);
        Assert.False(config.AutoUpdateDatabases);
    }

    [Fact]
    public void BehavioralFlags_RoundTrip()
    {
        using var tmp = new TempDir();
        var store = SentinelConfigStore.ForDataDirectory(tmp.Path);
        store.Save(new SentinelConfig { EnableRansomwareShield = false, BehavioralShadowMode = true });
        var reloaded = new SentinelConfigStore(store.Path).Load();
        Assert.False(reloaded.EnableRansomwareShield);
        Assert.True(reloaded.BehavioralShadowMode);
        Assert.True(reloaded.EnableCanaryFiles);
    }
}
