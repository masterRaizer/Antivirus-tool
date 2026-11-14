using System.Runtime.Versioning;
using Sentinel.Core.Audit.Persistence.Registry;

namespace Sentinel.Core.Tests;

/// <summary>
/// Безопасные интеграционные тесты реального провайдера реестра Windows.
/// Пишут и читают только в изолированной ветке <c>HKCU\Software\TestAV</c>, которая
/// гарантированно удаляется после каждого теста. Критические ветки ОС не затрагиваются.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRegistryIntegrationTests : IDisposable
{
    private const string TestRoot = @"Software\TestAV";

    public WindowsRegistryIntegrationTests() => Cleanup();

    public void Dispose() => Cleanup();

    private static void Cleanup()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(TestRoot, throwOnMissingSubKey: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            // недостаточно прав — тест будет пропущен/провалится явно
        }
    }

    [WindowsFact]
    public void WindowsRegistryProvider_ReadsValuesWrittenToTestAV()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var runKey = TestRoot + @"\Run";
        using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(runKey))
        {
            key.SetValue("Updater", @"C:\Temp\updater.exe", Microsoft.Win32.RegistryValueKind.String);
            key.SetValue("Count", 7, Microsoft.Win32.RegistryValueKind.DWord);
            key.SetValue("Expand", "%SystemRoot%\\x.exe", Microsoft.Win32.RegistryValueKind.ExpandString);
        }

        var provider = new WindowsRegistryProvider();
        var path = new RegistryKeyPath(RegistryHive.CurrentUser, runKey);

        Assert.True(provider.KeyExists(path));

        var updater = provider.GetValue(path, "Updater");
        Assert.NotNull(updater);
        Assert.Equal(@"C:\Temp\updater.exe", updater!.Value);
        Assert.Equal(RegistryValueKind.Sz, updater.Kind);

        Assert.Equal(RegistryValueKind.Dword, provider.GetValue(path, "Count")!.Kind);
        Assert.Equal(RegistryValueKind.ExpandSz, provider.GetValue(path, "Expand")!.Kind);
        Assert.Equal(3, provider.GetValues(path).Count);
    }

    [WindowsFact]
    public void WindowsRegistryProvider_EnumeratesSubKeysUnderTestAV()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using (Microsoft.Win32.Registry.CurrentUser.CreateSubKey(TestRoot + @"\Services\Svc1"))
        using (Microsoft.Win32.Registry.CurrentUser.CreateSubKey(TestRoot + @"\Services\Svc2"))
        {
            // только создаём подключи
        }

        var provider = new WindowsRegistryProvider();
        var servicesPath = new RegistryKeyPath(RegistryHive.CurrentUser, TestRoot + @"\Services");

        var names = provider.GetSubKeyNames(servicesPath);
        Assert.Contains("Svc1", names);
        Assert.Contains("Svc2", names);
    }

    [WindowsFact]
    public void WindowsRegistryProvider_MissingKey_ReturnsEmpty()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var provider = new WindowsRegistryProvider();
        var path = new RegistryKeyPath(RegistryHive.CurrentUser, TestRoot + @"\DoesNotExist");
        Assert.False(provider.KeyExists(path));
        Assert.Empty(provider.GetValues(path));
        Assert.Empty(provider.GetSubKeyNames(path));
        Assert.Null(provider.GetValue(path, "whatever"));
    }
}
