namespace Sentinel.Core.Audit.Persistence;

/// <summary>
/// Классификация Windows-путей без обращения к файловой системе и без <see cref="Path.GetFullPath(string)"/>
/// (чтобы корректно работать и при прогоне тестов на Linux). Разделители '\' и '/' равнозначны.
/// </summary>
public static class PathClassifier
{
    private static readonly string[] UserWritableMarkers =
    [
        "\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\", "\\public\\",
        "\\$recycle.bin\\", "\\programdata\\", "\\users\\public\\", "\\perflogs\\",
    ];

    /// <summary>Нормализует путь: унифицирует разделители к '\' и приводит к нижнему регистру.</summary>
    public static string Normalize(string path) => path.Replace('/', '\\').ToLowerInvariant();

    /// <summary>Каталог пути (до последнего разделителя). null — разделителя нет.</summary>
    public static string? GetDirectory(string path)
    {
        var idx = path.LastIndexOfAny(['\\', '/']);
        return idx <= 0 ? null : path[..idx].Replace('/', '\\').TrimEnd('\\');
    }

    /// <summary>Лежит ли путь в одном из доверенных каталогов (System32, Program Files и т.п.).</summary>
    public static bool IsInTrustedDirectory(string path, IReadOnlyList<string> trustedDirectories)
    {
        var norm = Normalize(path);
        foreach (var dir in trustedDirectories)
        {
            if (string.IsNullOrWhiteSpace(dir))
            {
                continue;
            }

            var d = Normalize(dir).TrimEnd('\\') + "\\";
            if (norm.StartsWith(d, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Каталоги, откуда запускаются преимущественно вредоносные файлы: временные и общедоступные (<c>%TEMP%</c>, <c>Users\Public</c>).</summary>
    public static bool IsTempOrPublic(string path)
    {
        var norm = Normalize(path);
        return norm.Contains("\\temp\\", StringComparison.Ordinal)
            || norm.Contains("\\users\\public\\", StringComparison.Ordinal) || norm.Contains("\\$recycle.bin\\", StringComparison.Ordinal);
    }

    /// <summary>Расположен ли путь в каталоге, в который обычно может писать непривилегированный пользователь.</summary>
    public static bool IsUserWritableLocation(string path)
    {
        var norm = Normalize(path);
        return UserWritableMarkers.Any(m => norm.Contains(m, StringComparison.Ordinal));
    }
}
