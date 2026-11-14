using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Sentinel.Core.Audit.Persistence.Registry;

/// <summary>
/// Доступ к реальному реестру Windows через <see cref="Microsoft.Win32.RegistryKey"/>.
/// Чтение открывает ключи только для чтения в заданном представлении (32/64); запись
/// (<see cref="IRegistryEditor"/>) используется исключительно модулем нейтрализации.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRegistryProvider : IRegistryEditor
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

    public void SetValue(RegistryKeyPath key, string name, string? value, RegistryValueKind kind)
    {
        object data = kind switch
        {
            RegistryValueKind.Sz or RegistryValueKind.ExpandSz => value ?? string.Empty,
            RegistryValueKind.MultiSz => string.IsNullOrEmpty(value) ? [] : value.Split(';'),
            RegistryValueKind.Dword => unchecked((int)long.Parse(value ?? "0", CultureInfo.InvariantCulture)),
            RegistryValueKind.Qword => long.Parse(value ?? "0", CultureInfo.InvariantCulture),
            RegistryValueKind.Binary => Convert.FromHexString(value ?? string.Empty),
            _ => throw new NotSupportedException($"Запись значения типа {kind} не поддерживается."),
        };
        var nativeKind = kind switch
        {
            RegistryValueKind.Sz => Microsoft.Win32.RegistryValueKind.String,
            RegistryValueKind.ExpandSz => Microsoft.Win32.RegistryValueKind.ExpandString,
            RegistryValueKind.MultiSz => Microsoft.Win32.RegistryValueKind.MultiString,
            RegistryValueKind.Dword => Microsoft.Win32.RegistryValueKind.DWord,
            RegistryValueKind.Qword => Microsoft.Win32.RegistryValueKind.QWord,
            _ => Microsoft.Win32.RegistryValueKind.Binary,
        };

        using var baseKey = RegistryKey.OpenBaseKey(MapHive(key.Hive), MapView(key.View));
        using var k = baseKey.CreateSubKey(key.SubKey, writable: true)
            ?? throw new IOException($"Не удалось открыть ключ {key} для записи.");
        k.SetValue(name, data, nativeKind);
    }

    public bool DeleteValue(RegistryKeyPath key, string name)
    {
        using var baseKey = RegistryKey.OpenBaseKey(MapHive(key.Hive), MapView(key.View));
        using var k = baseKey.OpenSubKey(key.SubKey, writable: true);
        if (k is null || !k.GetValueNames().Any(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        k.DeleteValue(name, throwOnMissingValue: false);
        return true;
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

    private static Microsoft.Win32.RegistryView MapView(RegistryView view) => view switch
    {
        RegistryView.Registry32 => Microsoft.Win32.RegistryView.Registry32,
        RegistryView.Registry64 => Microsoft.Win32.RegistryView.Registry64,
        _ => Microsoft.Win32.RegistryView.Default,
    };

    private static Microsoft.Win32.RegistryHive MapHive(RegistryHive hive) => hive switch
    {
        RegistryHive.CurrentUser => Microsoft.Win32.RegistryHive.CurrentUser,
        RegistryHive.LocalMachine => Microsoft.Win32.RegistryHive.LocalMachine,
        RegistryHive.ClassesRoot => Microsoft.Win32.RegistryHive.ClassesRoot,
        RegistryHive.Users => Microsoft.Win32.RegistryHive.Users,
        RegistryHive.CurrentConfig => Microsoft.Win32.RegistryHive.CurrentConfig,
        _ => Microsoft.Win32.RegistryHive.LocalMachine,
    };

    private static RegistryKey? Open(RegistryKeyPath key)
    {
        var view = MapView(key.View);
        var hive = MapHive(key.Hive);

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

    public static IRegistryProvider CreateDefault() => CreateEditor();

    /// <summary>Провайдер с правом записи — для модуля нейтрализации.</summary>
    public static IRegistryEditor CreateEditor() =>
        OperatingSystem.IsWindows()
            ? new WindowsRegistryProvider()
            : throw new PlatformNotSupportedException("Доступ к реестру возможен только в Windows.");
}
