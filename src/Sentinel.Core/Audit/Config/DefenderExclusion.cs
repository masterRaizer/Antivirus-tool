using System.Text.RegularExpressions;
using Sentinel.Core.Audit.Persistence;

namespace Sentinel.Core.Audit.Config;

/// <summary>Вид исключения встроенной защиты Windows (свойства <c>MSFT_MpPreference</c>).</summary>
public enum DefenderExclusionKind
{
    /// <summary><c>ExclusionPath</c> — файл или каталог.</summary>
    Path,

    /// <summary><c>ExclusionProcess</c> — образ процесса (полный путь или только имя).</summary>
    Process,

    /// <summary><c>ExclusionExtension</c> — расширение файлов.</summary>
    Extension,

    /// <summary><c>ExclusionIpAddress</c> — IP-адрес, исключённый из сетевой защиты.</summary>
    IpAddress,
}

/// <summary>
/// Одно исключение встроенной защиты. Значение хранится как в реестре; сопоставление с путями
/// выполняется строковой нормализацией в стиле Windows (без обращения к файловой системе),
/// поэтому работает одинаково в Windows и при прогоне тестов в Linux.
/// </summary>
public sealed record DefenderExclusion(DefenderExclusionKind Kind, string Value, string SourceKey, bool FromPolicy = false)
{
    /// <summary>Имя свойства <c>MSFT_MpPreference</c>, в котором хранится исключение.</summary>
    public string PreferenceProperty => Kind switch
    {
        DefenderExclusionKind.Path => "ExclusionPath",
        DefenderExclusionKind.Process => "ExclusionProcess",
        DefenderExclusionKind.Extension => "ExclusionExtension",
        _ => "ExclusionIpAddress",
    };

    /// <summary>Значение с раскрытыми переменными окружения (<c>%TEMP%</c> и т.п.) и без кавычек.</summary>
    public string ExpandedValue => Environment.ExpandEnvironmentVariables(Value.Trim().Trim('"'));

    public bool HasWildcard => Value.Contains('*', StringComparison.Ordinal) || Value.Contains('?', StringComparison.Ordinal);

    /// <summary>Задано ли исключение процесса только именем образа (без каталога).</summary>
    public bool IsBareProcessName =>
        Kind == DefenderExclusionKind.Process && ExpandedValue.IndexOfAny(['\\', '/']) < 0;

    /// <summary>
    /// Покрывает ли исключение указанный файл: для <see cref="DefenderExclusionKind.Path"/> — сам файл
    /// или любой файл внутри каталога; для <see cref="DefenderExclusionKind.Process"/> — образ процесса;
    /// для <see cref="DefenderExclusionKind.Extension"/> — файлы с этим расширением.
    /// </summary>
    public bool CoversFile(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return false;
        }

        var file = Normalize(filePath);
        switch (Kind)
        {
            case DefenderExclusionKind.Path:
            {
                var target = Normalize(ExpandedValue);
                if (target.Length == 0)
                {
                    return false;
                }

                if (HasWildcard)
                {
                    return GlobToRegex(target, prefixMatch: true).IsMatch(file);
                }

                return file == target || file.StartsWith(target + "\\", StringComparison.Ordinal);
            }

            case DefenderExclusionKind.Process:
                return CoversProcess(FileNameOf(file), filePath);

            case DefenderExclusionKind.Extension:
            {
                var ext = ExpandedValue.TrimStart('*').TrimStart('.').ToLowerInvariant();
                return ext.Length > 0 && file.EndsWith("." + ext, StringComparison.Ordinal);
            }

            default:
                return false;
        }
    }

    /// <summary>Покрывает ли исключение <c>ExclusionProcess</c> процесс с данным именем образа/путём.</summary>
    public bool CoversProcess(string? imageName, string? executablePath)
    {
        if (Kind != DefenderExclusionKind.Process)
        {
            return false;
        }

        var target = Normalize(ExpandedValue);
        if (target.Length == 0)
        {
            return false;
        }

        var path = string.IsNullOrWhiteSpace(executablePath) ? null : Normalize(executablePath);
        var name = !string.IsNullOrWhiteSpace(imageName)
            ? imageName.Trim().ToLowerInvariant()
            : path is null ? null : FileNameOf(path);

        if (IsBareProcessName)
        {
            return name is not null && (HasWildcard ? GlobToRegex(target, prefixMatch: false).IsMatch(name) : name == target);
        }

        if (path is null)
        {
            return false;
        }

        return HasWildcard ? GlobToRegex(target, prefixMatch: false).IsMatch(path) : path == target;
    }

    public override string ToString() => $"{PreferenceProperty}: {Value}";

    private static string Normalize(string path) =>
        PathClassifier.Normalize(path.Trim().Trim('"')).TrimEnd('\\');

    private static string FileNameOf(string normalizedPath)
    {
        var idx = normalizedPath.LastIndexOf('\\');
        return idx < 0 ? normalizedPath : normalizedPath[(idx + 1)..];
    }

    /// <summary>
    /// Шаблон Defender → регулярное выражение: <c>*</c> — любые символы в пределах одного
    /// компонента пути, <c>?</c> — один символ. При <paramref name="prefixMatch"/> совпадение
    /// с каталогом распространяется на его содержимое.
    /// </summary>
    private static Regex GlobToRegex(string normalizedPattern, bool prefixMatch)
    {
        var body = Regex.Escape(normalizedPattern)
            .Replace(@"\*", @"[^\\]*", StringComparison.Ordinal)
            .Replace(@"\?", @"[^\\]", StringComparison.Ordinal);
        var tail = prefixMatch ? @"(\\.*)?$" : "$";
        return new Regex("^" + body + tail, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    }
}
