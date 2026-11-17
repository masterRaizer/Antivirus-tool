using System.Text.RegularExpressions;

namespace Sentinel.Core.Audit.Persistence;

/// <summary>
/// Признаки «скачать и выполнить» в команде автозапуска или задачи: <c>irm … | iex</c>, <c>DownloadString</c>,
/// <c>Net.WebClient</c>, <c>-enc</c>, <c>FromBase64String</c>, <c>mshta http…</c>, <c>bitsadmin /transfer</c>,
/// <c>certutil -urlcache</c>, <c>curl/wget</c> с последующим запуском. Настоящие задачи Windows и Office запускают
/// подписанные exe без таких конструкций.
/// </summary>
public static partial class DownloadExecHeuristics
{
    [GeneratedRegex(@"\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|curl(?:\.exe)?|wget(?:\.exe)?)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Download();

    [GeneratedRegex(@"\b(?:iex|invoke-expression)\b|\|\s*(?:iex|powershell|pwsh|cmd|sh)\b|&&\s*(?:start|call|\S+\.exe)|;\s*start(?:-process)?\b|\bstart-process\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Execute();

    [GeneratedRegex(@"(?:^|\s)-(?:e|ec|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex EncodedCommand();

    [GeneratedRegex(@"\bfrombase64string\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex FromBase64();

    [GeneratedRegex(@"\bmshta(?:\.exe)?\b[^\r\n]*(?:https?:|javascript:|vbscript:)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Mshta();

    [GeneratedRegex(@"\bbitsadmin(?:\.exe)?\b[^\r\n]*/(?:transfer|addfile)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Bitsadmin();

    [GeneratedRegex(@"\bcertutil(?:\.exe)?\b[^\r\n]*-urlcache", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Certutil();

    [GeneratedRegex(@"https?://[^\s""'|;)]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Url();

    /// <summary>Найденные признаки (пусто — команда не скачивает и не выполняет код).</summary>
    public static IReadOnlyList<string> Analyze(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return [];
        }

        var hits = new List<string>();
        var download = Download().Match(command);
        var execute = Execute().Match(command);
        if (download.Success && execute.Success)
        {
            hits.Add($"скачивание и выполнение ({download.Value} + {execute.Value.Trim()})");
        }
        else if (execute.Success && Url().IsMatch(command))
        {
            hits.Add($"выполнение кода из сети ({execute.Value.Trim()})");
        }

        if (EncodedCommand().IsMatch(command))
        {
            hits.Add("закодированная команда (-enc)");
        }

        if (FromBase64().IsMatch(command))
        {
            hits.Add("FromBase64String");
        }

        if (Mshta().IsMatch(command))
        {
            hits.Add("mshta со сценарием из сети");
        }

        if (Bitsadmin().IsMatch(command))
        {
            hits.Add("bitsadmin /transfer");
        }

        if (Certutil().IsMatch(command))
        {
            hits.Add("certutil -urlcache");
        }

        return hits;
    }

    /// <summary>Адреса, с которых команда скачивает код (для отчёта и блокировки IOC).</summary>
    public static IReadOnlyList<string> Urls(string? command) =>
        string.IsNullOrWhiteSpace(command) ? [] : Url().Matches(command).Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}
