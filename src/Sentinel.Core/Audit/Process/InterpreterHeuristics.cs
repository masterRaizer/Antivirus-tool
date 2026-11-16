using System.Text.RegularExpressions;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Audit.Process;

/// <summary>
/// Эвристики подозрительных запусков интерпретаторов и LOLBin-ов: закодированные команды
/// PowerShell, скрытые окна, обход политик выполнения, загрузка/исполнение из сети,
/// base64, типичные цепочки <c>certutil</c>/<c>mshta</c>/<c>regsvr32</c>.
/// Чистая функция от (имя образа, командная строка) — полностью покрывается unit-тестами.
/// </summary>
public static partial class InterpreterHeuristics
{
    private static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "msiexec.exe", "mofcomp.exe",
    };

    private static readonly HashSet<string> PowerShells = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe",
    };

    public static bool IsInterpreter(string name) =>
        !string.IsNullOrEmpty(name) && Interpreters.Contains(name);

    /// <summary>Анализирует запуск; возвращает находки (возможно несколько) либо пустой список.</summary>
    public static IReadOnlyList<AuditFinding> Analyze(string name, string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return [];
        }

        var findings = new List<AuditFinding>();
        var args = CommandLineParser.Arguments(commandLine);
        var lower = commandLine.ToLowerInvariant();
        var isPs = !string.IsNullOrEmpty(name) && PowerShells.Contains(name);

        if (isPs)
        {
            AnalyzePowerShellSwitches(name, commandLine, args, findings);
        }

        // Содержательные индикаторы (работают для любого интерпретатора/оболочки).
        if (lower.Contains("frombase64string", StringComparison.Ordinal))
        {
            findings.Add(AuditFinding.Create("PROC-CMD-BASE64", Severity.High,
                "Декодирование base64 в командной строке",
                "Командная строка содержит FromBase64String — типичный приём запуска закодированной нагрузки.",
                Evidence.Of("name", name), Evidence.Of("cmdline", commandLine)));
        }

        if (DownloadRegex().IsMatch(lower))
        {
            findings.Add(AuditFinding.Create("PROC-CMD-DOWNLOAD", Severity.High,
                "Загрузка и исполнение из сети",
                "Командная строка содержит сетевую загрузку (DownloadString/DownloadFile/WebClient/Invoke-WebRequest/bitstransfer).",
                Evidence.Of("name", name), Evidence.Of("cmdline", commandLine)));
        }

        // IEX ищется только среди аргументов и только как отдельное слово: имя исполняемого файла (например msiexec.exe)
        // и слова, содержащие «iex» внутри, не считаются.
        // Одиночный IEX — обычный приём служебных сценариев и установщиков (Medium); в связке с загрузкой из сети или
        // декодированием base64 это «download cradle» — High.
        if (IexRegex().IsMatch(string.Join(' ', args).ToLowerInvariant()))
        {
            var cradle = DownloadRegex().IsMatch(lower) || lower.Contains("frombase64string", StringComparison.Ordinal);
            findings.Add(AuditFinding.Create("PROC-CMD-IEX", cradle ? Severity.High : Severity.Medium,
                cradle ? "Исполнение загруженного или декодированного кода" : "Динамическое исполнение выражения",
                cradle
                    ? "Командная строка исполняет через Invoke-Expression (IEX) код, загруженный из сети или декодированный из base64."
                    : "Командная строка содержит Invoke-Expression (IEX) — исполнение кода из строки (часто встречается в служебных сценариях).",
                Evidence.Of("name", name), Evidence.Of("cmdline", commandLine)));
        }

        if (CertutilRegex().IsMatch(lower))
        {
            findings.Add(AuditFinding.Create("PROC-CMD-CERTUTIL", Severity.High,
                "Злоупотребление certutil",
                "certutil используется для скачивания (urlcache) или декодирования файла — характерно для доставки нагрузки.",
                Evidence.Of("name", name), Evidence.Of("cmdline", commandLine)));
        }

        var url = UrlRegex().Match(commandLine);
        if (url.Success)
        {
            findings.Add(AuditFinding.Create("PROC-CMD-URL", Severity.Medium,
                "URL в командной строке",
                "В аргументах запуска присутствует сетевой URL.",
                Evidence.Of("name", name), Evidence.Of("url", url.Value)));
        }
        else
        {
            var ip = IpPortRegex().Match(commandLine);
            if (ip.Success)
            {
                findings.Add(AuditFinding.Create("PROC-CMD-IPPORT", Severity.Medium,
                    "Строка подключения IP:порт",
                    "В аргументах запуска присутствует адрес вида IP:порт — возможный C2-коннект.",
                    Evidence.Of("name", name), Evidence.Of("endpoint", ip.Value)));
            }
        }

        return findings;
    }

    private static void AnalyzePowerShellSwitches(string name, string commandLine, IReadOnlyList<string> args, List<AuditFinding> findings)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var opt = NormalizeOption(args[i]);
            if (opt is null)
            {
                continue;
            }

            if (IsParam(opt, "encodedcommand"))
            {
                findings.Add(AuditFinding.Create("PROC-PS-ENCODED", Severity.High,
                    "PowerShell: закодированная команда",
                    "Запуск PowerShell с -EncodedCommand (нагрузка передана в base64, чтобы скрыть содержимое).",
                    Evidence.Of("name", name), Evidence.Of("switch", args[i]), Evidence.Of("cmdline", commandLine)));
            }
            else if (IsParam(opt, "windowstyle"))
            {
                var value = i + 1 < args.Count ? args[i + 1] : string.Empty;
                if (value.Contains("hidden", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(AuditFinding.Create("PROC-PS-HIDDEN", Severity.Medium,
                        "PowerShell: скрытое окно",
                        "Запуск с -WindowStyle Hidden скрывает окно консоли от пользователя.",
                        Evidence.Of("name", name), Evidence.Of("cmdline", commandLine)));
                }
            }
            else if (opt is "w" && i + 1 < args.Count && args[i + 1].Contains("hidden", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(AuditFinding.Create("PROC-PS-HIDDEN", Severity.Medium,
                    "PowerShell: скрытое окно",
                    "Запуск с -w Hidden скрывает окно консоли от пользователя.",
                    Evidence.Of("name", name), Evidence.Of("cmdline", commandLine)));
            }
            else if (IsParam(opt, "executionpolicy"))
            {
                var value = i + 1 < args.Count ? args[i + 1] : string.Empty;
                if (value.Contains("bypass", StringComparison.OrdinalIgnoreCase) || value.Contains("unrestricted", StringComparison.OrdinalIgnoreCase))
                {
                    // Штатно используется установщиками и средствами разработки — сам по себе слабый сигнал.
                    findings.Add(AuditFinding.Create("PROC-PS-BYPASS", Severity.Low,
                        "PowerShell: обход политики выполнения",
                        "Запуск с -ExecutionPolicy Bypass/Unrestricted снимает ограничения на запуск скриптов.",
                        Evidence.Of("name", name), Evidence.Of("cmdline", commandLine)));
                }
            }
        }
    }

    /// <summary>Нормализует параметр: убирает ведущий <c>-</c> или <c>/</c> и приводит к нижнему регистру.</summary>
    internal static string? NormalizeOption(string arg)
    {
        if (string.IsNullOrEmpty(arg) || (arg[0] != '-' && arg[0] != '/'))
        {
            return null;
        }

        var opt = arg[1..].ToLowerInvariant();
        var colon = opt.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            opt = opt[..colon];
        }

        return opt.Length == 0 ? null : opt;
    }

    /// <summary>Является ли <paramref name="opt"/> допустимым сокращением полного имени параметра.</summary>
    internal static bool IsParam(string opt, string canonical) =>
        opt.Length > 0 && canonical.StartsWith(opt, StringComparison.Ordinal);

    [GeneratedRegex(@"downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|\bwebclient\b|start-bitstransfer|\biwr\b|\bcurl\b|\bwget\b", RegexOptions.IgnoreCase)]
    private static partial Regex DownloadRegex();

    [GeneratedRegex(@"(?<![a-zA-Z0-9_-])iex(?![a-zA-Z0-9_-])|invoke-expression", RegexOptions.IgnoreCase)]
    private static partial Regex IexRegex();

    [GeneratedRegex(@"certutil.*(urlcache|-decode|/decode|-urlcache)", RegexOptions.IgnoreCase)]
    private static partial Regex CertutilRegex();

    [GeneratedRegex(@"(?:https?|ftp)://[^\s""']+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b")]
    private static partial Regex IpPortRegex();
}
