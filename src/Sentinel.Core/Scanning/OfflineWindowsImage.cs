using System.Collections.Concurrent;

namespace Sentinel.Core.Scanning;

/// <summary>
/// Неработающая копия Windows на другом диске (старая установка, подключённый диск другого компьютера, образ
/// восстановления): <c>X:\Windows\System32\ntoskrnl.exe</c> есть, но это не <c>%SystemRoot%</c> текущей системы.
/// Файлы Microsoft в такой копии подписаны каталогами самой копии (<c>X:\Windows\System32\CatRoot</c>), которых живая
/// система не видит, поэтому выглядят неподписанными, а их импорты (AMSI, VirtualProtect, внедрение у отладчиков)
/// дают эвристический балл. Эвристика без сигнатуры или хеша для таких файлов не является находкой.
/// </summary>
public static class OfflineWindowsImage
{
    private static readonly ConcurrentDictionary<string, bool> Roots = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Файл лежит в каталоге Windows неработающей копии (проверка ядра кэшируется на диск).</summary>
    public static bool Contains(string path) =>
        Contains(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows), File.Exists);

    /// <summary>Вариант для тестов: каталог Windows живой системы и проверка существования файла задаются явно.</summary>
    public static bool Contains(string path, string? liveWindowsDirectory, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        var p = path.Replace('/', '\\');
        // Только «<диск>:\Windows\…» — каталог Windows в корне диска.
        if (p.Length < 12 || p[1] != ':' || p[2] != '\\' || !p.AsSpan(3).StartsWith(@"Windows\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var root = p[..10]; // «H:\Windows»
        if (!string.IsNullOrEmpty(liveWindowsDirectory)
            && string.Equals(root, liveWindowsDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (fileExists == File.Exists)
        {
            return Roots.GetOrAdd(root, r => File.Exists(Path.Combine(r, "System32", "ntoskrnl.exe")));
        }

        return fileExists(root + @"\System32\ntoskrnl.exe");
    }
}
