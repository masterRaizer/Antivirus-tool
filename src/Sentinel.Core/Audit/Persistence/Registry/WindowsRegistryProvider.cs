using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Sentinel.Core.Audit.Persistence.Registry;

/// <summary>
/// Чтение реального реестра Windows через <see cref="Microsoft.Win32.RegistryKey"/>.
/// Открывает ключи в режиме только для чтения в заданном представлении (32/64).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRegistryProvider : IRegistryProvider
{
    public bool KeyExists(RegistryKeyPath key)
    {
        using var k = Open(key);
        return k is not null;
    }

    public IReadOnlyList<string> GetSubKeyNames(RegistryKeyPath key)
    {
        using var k = Open(key);
        return k is null ? [] : k.GetSubKeyNames();
    }

    public IReadOnlyList<RegistryValue> GetValues(RegistryKeyPath key)
    {
        using var k = Open(key);
        if (k is null)
        {
            return [];
        }

        var values = new List<RegistryValue>();
        foreach (var name in k.GetValueNames())
        {
            values.Add(ReadValue(k, name));
        }

        return values;
    }

    public RegistryValue? GetValue(RegistryKeyPath key, string name)
    {
        using var k = Open(key);
        if (k is null)
        {
            return null;
        }

        var exists = k.GetValueNames().Any(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
        return exists ? ReadValue(k, name) : null;
    }

    private static RegistryValue ReadValue(RegistryKey key, string name)
    {
        var kind = MapKind(key.GetValueKind(name));
        var raw = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return new RegistryValue(name, Stringify(raw), kind);
    }

    private static string? Stringify(object? raw) => raw switch
    {
        null => null,
        string s => s,
        string[] arr => string.Join(";", arr),
        int i => i.ToString(CultureInfo.InvariantCulture),
        long l => l.ToString(CultureInfo.InvariantCulture),
        byte[] b => Convert.ToHexString(b),
        _ => raw.ToString(),
    };

    private static RegistryValueKind MapKind(Microsoft.Win32.RegistryValueKind kind) => kind switch
    {
        Microsoft.Win32.RegistryValueKind.String => RegistryValueKind.Sz,
        Microsoft.Win32.RegistryValueKind.ExpandString => RegistryValueKind.ExpandSz,
        Microsoft.Win32.RegistryValueKind.MultiString => RegistryValueKind.MultiSz,
        Microsoft.Win32.RegistryValueKind.DWord => RegistryValueKind.Dword,
        Microsoft.Win32.RegistryValueKind.QWord => RegistryValueKind.Qword,
        Microsoft.Win32.RegistryValueKind.Binary => RegistryValueKind.Binary,
        _ => RegistryValueKind.Unknown,
    };

    private static RegistryKey? Open(RegistryKeyPath key)
    {
        var view = key.View switch
        {
            RegistryView.Registry32 => Microsoft.Win32.RegistryView.Registry32,
            RegistryView.Registry64 => Microsoft.Win32.RegistryView.Registry64,
            _ => Microsoft.Win32.RegistryView.Default,
        };

        var hive = key.Hive switch
        {
            RegistryHive.CurrentUser => Microsoft.Win32.RegistryHive.CurrentUser,
            RegistryHive.LocalMachine => Microsoft.Win32.RegistryHive.LocalMachine,
            RegistryHive.ClassesRoot => Microsoft.Win32.RegistryHive.ClassesRoot,
            RegistryHive.Users => Microsoft.Win32.RegistryHive.Users,
            RegistryHive.CurrentConfig => Microsoft.Win32.RegistryHive.CurrentConfig,
            _ => Microsoft.Win32.RegistryHive.LocalMachine,
        };

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            return baseKey.OpenSubKey(key.SubKey, writable: false);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}

/// <summary>Фабрика провайдера реестра: Windows-реализация или явный отказ на других ОС.</summary>
public static class RegistryProviderFactory
{
    public static bool IsSupported => OperatingSystem.IsWindows();

    public static IRegistryProvider CreateDefault() =>
        OperatingSystem.IsWindows()
            ? new WindowsRegistryProvider()
            : throw new PlatformNotSupportedException("Чтение реестра доступно только в Windows.");
}
