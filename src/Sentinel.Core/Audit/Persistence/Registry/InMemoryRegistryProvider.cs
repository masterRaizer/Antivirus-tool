namespace Sentinel.Core.Audit.Persistence.Registry;

/// <summary>
/// Реестр в памяти для unit-тестов (и как эталон семантики провайдера).
/// Ключи сопоставляются по (куст, представление, нормализованный путь без учёта регистра).
/// </summary>
public sealed class InMemoryRegistryProvider : IRegistryProvider
{
    private readonly Dictionary<string, List<RegistryValue>> _keys = new(StringComparer.OrdinalIgnoreCase);

    private static string Normalize(RegistryHive hive, RegistryView view, string subKey) =>
        $"{hive}|{view}|{subKey.Trim('\\').Replace('/', '\\')}";

    private static string Key(RegistryKeyPath k) => Normalize(k.Hive, k.View, k.SubKey);

    /// <summary>Создаёт ключ (если нужно) и задаёт значение.</summary>
    public InMemoryRegistryProvider Set(RegistryKeyPath key, string name, string? value, RegistryValueKind kind = RegistryValueKind.Sz)
    {
        var id = Key(key);
        if (!_keys.TryGetValue(id, out var list))
        {
            list = [];
            _keys[id] = list;
        }

        list.RemoveAll(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase));
        list.Add(new RegistryValue(name, value, kind));
        return this;
    }

    /// <summary>Создаёт пустой ключ без значений.</summary>
    public InMemoryRegistryProvider CreateKey(RegistryKeyPath key)
    {
        var id = Key(key);
        if (!_keys.ContainsKey(id))
        {
            _keys[id] = [];
        }

        return this;
    }

    public bool KeyExists(RegistryKeyPath key) => _keys.ContainsKey(Key(key));

    public IReadOnlyList<string> GetSubKeyNames(RegistryKeyPath key)
    {
        var prefix = Key(key) + "\\";
        var names = new List<string>();
        foreach (var existing in _keys.Keys)
        {
            if (!existing.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var rest = existing[prefix.Length..];
            var sep = rest.IndexOf('\\', StringComparison.Ordinal);
            var child = sep < 0 ? rest : rest[..sep];
            if (child.Length > 0 && !names.Contains(child, StringComparer.OrdinalIgnoreCase))
            {
                names.Add(child);
            }
        }

        return names;
    }

    public IReadOnlyList<RegistryValue> GetValues(RegistryKeyPath key) =>
        _keys.TryGetValue(Key(key), out var list) ? list.ToArray() : [];

    public RegistryValue? GetValue(RegistryKeyPath key, string name) =>
        _keys.TryGetValue(Key(key), out var list)
            ? list.FirstOrDefault(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase))
            : null;
}
