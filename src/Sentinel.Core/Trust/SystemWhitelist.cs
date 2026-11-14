using System.Text.RegularExpressions;

namespace Sentinel.Core.Trust;

public sealed class WhitelistOptions
{
    /// <summary>Защищённые каталоги (полные пути).</summary>
    public IReadOnlyList<string> ProtectedDirectories { get; init; } = [];

    /// <summary>Издатели (O= или CN= подписанта), которым доверяют файлы в защищённых каталогах.</summary>
    public IReadOnlyList<string> TrustedPublishers { get; init; } =
    [
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "Microsoft Windows Hardware Compatibility Publisher",
    ];

    /// <summary>Требовать совпадения подписанта с <see cref="TrustedPublishers"/>.</summary>
    public bool RequireTrustedPublisher { get; init; } = true;

    /// <summary>Каталоги Windows по умолчанию: System32, SysWOW64, WinSxS, servicing, drivers.</summary>
    public static WhitelistOptions CreateDefault()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windows))
        {
            return new WhitelistOptions();
        }

        return new WhitelistOptions
        {
            ProtectedDirectories =
            [
                Path.Combine(windows, "System32"),
                Path.Combine(windows, "SysWOW64"),
                Path.Combine(windows, "WinSxS"),
                Path.Combine(windows, "servicing"),
                Path.Combine(windows, "SystemApps"),
            ],
        };
    }
}

/// <summary>
/// Белый список системных файлов. Файл доверен, только если одновременно:
/// 1) реальный путь (после разрешения ссылок) лежит в защищённом каталоге;
/// 2) подпись (встроенная или каталожная) действительна;
/// 3) подписант — доверенный издатель (по умолчанию Microsoft).
/// Одно лишь расположение в System32 не делает файл доверенным: неподписанный
/// файл, подброшенный в System32, должен проверяться как обычный.
/// Локальные исключения встроенной защиты (Defender ExclusionPath/ExclusionProcess/ExclusionExtension)
/// намеренно не читаются и не учитываются: их может добавить вредонос, поэтому они никогда
/// не являются основанием для доверия — решение зависит только от пути и подписи.
/// </summary>
public sealed partial class SystemWhitelist : IWhitelistProvider
{
    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private readonly ISignatureVerifier _verifier;
    private readonly WhitelistOptions _options;
    private readonly string[] _directories;

    public SystemWhitelist(ISignatureVerifier verifier, WhitelistOptions options)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(options);
        _verifier = verifier;
        _options = options;
        _directories = options.ProtectedDirectories
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => EnsureTrailingSeparator(NormalizePath(d)))
            .ToArray();
    }

    public IReadOnlyList<string> ProtectedDirectories => _directories;

    public bool IsProtectedLocation(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (HasAlternateDataStream(path))
        {
            return false;
        }

        var full = NormalizePath(path);
        return _directories.Any(d => full.StartsWith(d, PathComparison));
    }

    public WhitelistDecision Evaluate(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (HasAlternateDataStream(path))
        {
            return WhitelistDecision.No("Путь указывает на альтернативный поток NTFS.");
        }

        string realPath;
        try
        {
            realPath = ResolveRealPath(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return WhitelistDecision.No($"Не удалось разрешить путь: {ex.Message}");
        }

        if (!IsProtectedLocation(realPath))
        {
            return WhitelistDecision.No("Файл вне защищённых системных каталогов.");
        }

        var signature = _verifier.Verify(realPath);
        if (!signature.IsValid)
        {
            return WhitelistDecision.No($"Подпись недействительна: {signature.Status} ({signature.Message}).", signature);
        }

        if (_options.RequireTrustedPublisher && !IsTrustedPublisher(signature.SignerSubject))
        {
            return WhitelistDecision.No($"Подписант '{signature.SignerSubject}' не входит в список доверенных издателей.", signature);
        }

        return new WhitelistDecision(true, $"Системный файл с действительной подписью ({signature.Source}): {signature.SignerSubject}", signature);
    }

    internal bool IsTrustedPublisher(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return false;
        }

        foreach (Match m in DnPartRegex().Matches(subject))
        {
            var value = m.Groups["q"].Success ? m.Groups["q"].Value : m.Groups["v"].Value.Trim();
            if (_options.TrustedPublishers.Any(p => string.Equals(p, value, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    [GeneratedRegex("""(?:^|,)\s*(?:CN|O)=(?:"(?<q>[^"]*)"|(?<v>[^,]*))""", RegexOptions.IgnoreCase)]
    private static partial Regex DnPartRegex();

    private static string ResolveRealPath(string path)
    {
        var info = new FileInfo(NormalizePath(path));
        if (info.LinkTarget is not null)
        {
            var target = info.ResolveLinkTarget(returnFinalTarget: true);
            if (target is not null)
            {
                return NormalizePath(target.FullName);
            }
        }

        return info.FullName;
    }

    internal static string NormalizePath(string path)
    {
        var p = path;
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) && !p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            p = p[4..];
        }

        return Path.GetFullPath(p);
    }

    /// <summary>"C:\Windows\System32\a.exe:evil" — двоеточие после буквы диска означает ADS.</summary>
    internal static bool HasAlternateDataStream(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var p = path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
        var start = p.Length >= 2 && p[1] == ':' ? 2 : 0;
        return p.IndexOf(':', start) >= 0;
    }

    private static string EnsureTrailingSeparator(string dir) =>
        Path.EndsInDirectorySeparator(dir) ? dir : dir + Path.DirectorySeparatorChar;
}
