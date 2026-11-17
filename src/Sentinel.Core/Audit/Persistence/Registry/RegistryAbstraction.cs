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
    /// <summary>
    /// Обратный разбор строки вида <c>HKLM\Software\X [Registry32]</c> (формат <see cref="ToString"/>),
    /// в котором аудиторы сообщают расположение находок.
    /// </summary>
    public static bool TryParse(string? text, out RegistryKeyPath? key)
    {
        key = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var body = text.Trim();
        var view = RegistryView.Default;
        if (body.EndsWith(']'))
        {
            var open = body.LastIndexOf(" [", StringComparison.Ordinal);
            if (open < 0 || !Enum.TryParse(body[(open + 2)..^1], ignoreCase: false, out view))
            {
                return false;
            }

            body = body[..open];
        }

        var sep = body.IndexOf('\\', StringComparison.Ordinal);
        if (sep <= 0 || sep == body.Length - 1)
        {
            return false;
        }

        RegistryHive? hive = body[..sep].ToUpperInvariant() switch
        {
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            "HKU" or "HKEY_USERS" => RegistryHive.Users,
            "HKCC" or "HKEY_CURRENT_CONFIG" => RegistryHive.CurrentConfig,
            _ => null,
        };
        if (hive is null)
        {
            return false;
        }

        key = new RegistryKeyPath(hive.Value, body[(sep + 1)..], view);
        return true;
    }

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

/// <summary>
/// Изменение реестра для модуля нейтрализации. Отделено от <see cref="IRegistryProvider"/>:
/// аудиторы получают только чтение, право записи есть лишь у <c>RemediationEngine</c>.
/// </summary>
public interface IRegistryEditor : IRegistryProvider
{
    /// <summary>Создаёт ключ при необходимости и задаёт значение (строковое представление — как в <see cref="RegistryValue"/>).</summary>
    void SetValue(RegistryKeyPath key, string name, string? value, RegistryValueKind kind);

    /// <summary>Удаляет значение. Возвращает <c>false</c>, если значения (или ключа) не было.</summary>
    bool DeleteValue(RegistryKeyPath key, string name);
}

/// <summary>
/// Время последней записи ключа (<c>RegQueryInfoKey</c>). Отдельный интерфейс: у отдельного значения реестра времени нет,
/// поэтому корреляция «Run-значение создано рядом по времени с файлом» использует время изменения ключа Run.
/// </summary>
public interface IRegistryKeyTimestampProvider
{
    DateTime? GetLastWriteTimeUtc(RegistryKeyPath key);
}
