using System.Text.Json;
using Sentinel.Core.Remediation;
using Sentinel.Core.Runtime;
using Sentinel.Core.Settings;
using Sentinel.Core.ThreatFamilies;

namespace Sentinel.Cli;

internal static partial class Program
{
    /// <summary>
    /// <c>family-scan</c> — аудит и корреляция семейств, снимок улик, план; <c>family-clean --confirm</c> — нейтрализация по
    /// плейбуку (процессы → закрепление → исключения и правила → карантин → IOC → проверка через 45 с). Без <c>--confirm</c>
    /// ничего не изменяется.
    /// </summary>
    private static int FamilyScan(CliOptions opts, bool clean)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Поиск семейств доступен только в Windows (реестр, планировщик, журнал Защитника, таблица TCP).");
            return ExitError;
        }

        var (_, analyzer) = CreateAnalyzer(opts, printRuleErrors: !opts.Json);
        var data = DataDirectory(opts);
        var allowed = AllowedExclusionStore.ForDataDirectory(data);
        Func<string, bool> isUserAllowed = path =>
        {
            try
            {
                return allowed.Load().IsPathAllowed(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                return false;
            }
        };

        var scanner = ThreatFamilyScanner.CreateDefault(analyzer, isUserAllowed);
        if (!opts.Json)
        {
            Console.WriteLine("Поиск семейств: автозапуск, задачи, службы, WMI, исключения и политики Защитника, брандмауэр, процессы и соединения…");
        }

        var scan = scanner.Scan();
        var execute = clean && opts.Confirm;
        if (clean && !opts.Confirm && !opts.Json)
        {
            Console.WriteLine("Без --confirm выполняется только план: система не изменяется.");
        }

        var whitelist = analyzer.Whitelist ?? DefaultWhitelist();
        using var quarantine = CreateQuarantine(opts, whitelist);
        var engine = execute ? RemediationEngine.CreateDefault(whitelist, RemediationOptions.CreateDefault(data)) : null;
        var playbook = new ThreatFamilyPlaybook(engine, execute ? quarantine : null, new ThreatFamilyPlaybookOptions
        {
            DataDirectory = data,
            AuditOnly = !execute,
            Confirmed = execute,
            BlockIoc = opts.BlockIoc,
        }, scanner.CreateProbe());
        var result = playbook.ExecuteAsync(scan.Detections).GetAwaiter().GetResult();

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                detections = scan.Detections.Select(d => new
                {
                    d.Key,
                    severity = d.Severity.ToString(),
                    d.Verdict,
                    family = d.Family?.Id,
                    d.ChainConfirmed,
                    d.Signals,
                }),
                plan = result.Plan,
                actions = result.Actions,
                verification = result.Verification,
                evidence = new { json = result.EvidenceJsonPath, html = result.EvidenceHtmlPath },
                message = result.UserMessage,
            }, JsonOptions));
        }
        else
        {
            Console.WriteLine();
            if (scan.Detections.Count > 0 && !execute)
            {
                Console.WriteLine("План нейтрализации (порядок важен):");
                foreach (var step in result.Plan)
                {
                    Console.WriteLine($"  {(int)step.Kind}. {step.Target} — {step.Description}");
                }

                Console.WriteLine();
            }

            Console.WriteLine(result.UserMessage);
        }

        return scan.Detections.Count == 0 ? ExitOk
            : result.Verification is { Clean: false } ? ExitError
            : ExitDetected;
    }
}
