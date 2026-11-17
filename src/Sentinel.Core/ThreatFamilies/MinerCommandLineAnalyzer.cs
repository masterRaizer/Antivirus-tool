using System.Text.RegularExpressions;
using Sentinel.Core.Audit;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.ThreatFamilies;

/// <summary>
/// Признаки майнера в командной строке процесса (или в аргументах задачи/автозапуска): ключи <c>--algorithm</c>,
/// <c>--pool</c>, <c>--wallet</c>, <c>-o stratum+tcp://</c>, известные алгоритмы и пулы. Один ключ — не повод для тревоги
/// (у многих программ есть «--pool»), находка выдаётся при сочетании признаков или однозначном индикаторе семейства.
/// </summary>
public static partial class MinerCommandLineAnalyzer
{
    public const string FindingId = "PROC-MINER-CMDLINE";

    [GeneratedRegex(@"(?:^|\s)(?:--algorithm(?:-gpu|-cpu)?|--algo|-a)[\s=]+[a-z0-9_\-/]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex AlgorithmArg();

    [GeneratedRegex(@"(?:^|\s)(?:--pool|--url|-o)[\s=]+\S*(?:://|:\d{2,5}\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex PoolArg();

    [GeneratedRegex(@"(?:^|\s)(?:--wallet|--user|-u)[\s=]+[A-Za-z0-9._\-]{16,}(?:\s|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex WalletArg();

    [GeneratedRegex(@"stratum\d?\+(?:tcp|ssl|tls)://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Stratum();

    [GeneratedRegex(@"\b(?:pearlhash|kawpow|ethash|etchash|autolykos2?|kheavyhash|randomx|rx/0|cryptonight|octopus|firopow|blake3|karlsenhash|nexapow|zelhash|equihash)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex Algorithm();

    [GeneratedRegex(@"\b(?:kryptex|nanopool|2miners|f2pool|herominers|unmineable|moneroocean|supportxmr|hashvault|minexmr|ethermine|nicehash|woolypooly|zergpool)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex PoolDomain();

    [GeneratedRegex(@":(?:3333|4444|5555|7048|14444)\b", RegexOptions.CultureInvariant, 1000)]
    private static partial Regex PoolPort();

    /// <summary>Находка по командной строке или <c>null</c>.</summary>
    public static AuditFinding? Analyze(string? commandLine, int pid = 0, string? processName = null)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        var signals = new List<string>();
        if (Stratum().IsMatch(commandLine))
        {
            signals.Add("stratum");
        }

        if (AlgorithmArg().IsMatch(commandLine) && Algorithm().IsMatch(commandLine))
        {
            signals.Add("алгоритм майнинга");
        }

        if (PoolArg().IsMatch(commandLine))
        {
            signals.Add("пул");
        }

        if (WalletArg().IsMatch(commandLine))
        {
            signals.Add("кошелёк");
        }

        if (PoolDomain().IsMatch(commandLine))
        {
            signals.Add("домен пула");
        }

        if (PoolPort().IsMatch(commandLine))
        {
            signals.Add("порт пула");
        }

        var family = ThreatFamilyCatalog.MatchText(commandLine);
        if (family is null && signals.Count < 2)
        {
            return null;
        }

        var severity = family is not null ? Severity.Critical : signals.Count >= 3 ? Severity.High : Severity.Medium;
        var familyNote = family is null ? string.Empty : $" Совпадает с индикатором семейства «{family.Family.Name}» ({family.Indicator}).";
        return AuditFinding.Create(FindingId, severity,
            "Командная строка майнера",
            $"Аргументы процесса '{processName ?? "?"}' содержат признаки майнинга ({string.Join(", ", signals.DefaultIfEmpty("индикатор семейства"))}).{familyNote}",
            Evidence.Of("pid", pid),
            Evidence.Of("signals", string.Join(", ", signals)),
            Evidence.Of("family", family?.Family.Id),
            Evidence.Of("commandLine", commandLine));
    }
}
