namespace Sentinel.Core.Audit.Persistence.Registry;

/// <summary>Куст реестра Windows.</summary>
public enum RegistryHive
{
    CurrentUser,
    LocalMachine,
    ClassesRoot,
    Users,
    CurrentConfig,
}

/// <summary>
/// Представление реестра: разрядность. На 64-битной ОС 32-битные приложения видят
/// <see cref="Registry32"/> (ветки Wow6432Node). Нужно для проверки обоих представлений.
/// </summary>
public enum RegistryView
{
    Default,
    Registry32,
    Registry64,
}

/// <summary>Тип значения реестра (подмножество, достаточное для анализа автозапуска).</summary>
public enum RegistryValueKind
{
    Sz,
    ExpandSz,
    MultiSz,
    Dword,
    Qword,
    Binary,
    Unknown,
}

/// <summary>Одно значение реестра: имя, строковое представление и тип.</summary>
public sealed record RegistryValue(string Name, string? Value, RegistryValueKind Kind);

/// <summary>Ссылка на ключ реестра.</summary>
public sealed record RegistryKeyPath(RegistryHive Hive, string SubKey, RegistryView View = RegistryView.Default)
{
    public override string ToString()
    {
        var prefix = Hive switch
        {
            RegistryHive.CurrentUser => "HKCU",
            RegistryHive.LocalMachine => "HKLM",
            RegistryHive.ClassesRoot => "HKCR",
            RegistryHive.Users => "HKU",
            RegistryHive.CurrentConfig => "HKCC",
            _ => Hive.ToString(),
        };
        var view = View == RegistryView.Default ? string.Empty : $" [{View}]";
        return $"{prefix}\\{SubKey}{view}";
    }
}

/// <summary>
/// Абстракция чтения реестра. Единственная платформенно-зависимая реализация — Windows
/// (<see cref="WindowsRegistryProvider"/>); для unit-тестов на Linux используется
/// <see cref="InMemoryRegistryProvider"/>. Только чтение — аудитор никогда не меняет реестр.
/// </summary>
public interface IRegistryProvider
{
    /// <summary>Существует ли ключ.</summary>
    bool KeyExists(RegistryKeyPath key);

    /// <summary>Имена непосредственных подключей. Если ключа нет — пустой список.</summary>
    IReadOnlyList<string> GetSubKeyNames(RegistryKeyPath key);

    /// <summary>Все значения ключа. Если ключа нет — пустой список.</summary>
    IReadOnlyList<RegistryValue> GetValues(RegistryKeyPath key);

    /// <summary>Одно значение по имени (пустое имя — значение по умолчанию) или null.</summary>
    RegistryValue? GetValue(RegistryKeyPath key, string name);
}
