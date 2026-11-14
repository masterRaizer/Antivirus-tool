using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.Analysis;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Detection;
using Sentinel.Core.Hashing;
using Sentinel.Core.Pe;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Cli;

internal static class Program
{
    private const int ExitOk = 0;
    private const int ExitDetected = 1;
    private const int ExitError = 2;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return args.Length == 0 ? ExitError : ExitOk;
        }

        var opts = CliOptions.Parse(args.Skip(1).ToArray());
        if (opts.Error is not null)
        {
            Console.Error.WriteLine($"Ошибка: {opts.Error}");
            return ExitError;
        }

        try
        {
            return args[0] switch
            {
                "scan" => Scan(opts),
                "hash" => Hash(opts),
                "pe" => Pe(opts),
                "rules" => Rules(opts),
                "selftest" => SelfTest(opts),
                "audit-processes" => AuditProcesses(opts),
                "audit-startup" => AuditStartup(opts),
                "audit-config" => AuditConfig(opts),
                _ => Unknown(args[0]),
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"Ошибка: {ex.Message}");
            return ExitError;
        }
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"Неизвестная команда '{command}'.");
        PrintUsage();
        return ExitError;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Sentinel — системный аудитор и сканер безопасности

            Использование:
              sentinel scan <путь> [--rules <каталог>] [--json] [--no-recurse] [--max-size <МБ>]
              sentinel hash <файл>                 SHA-256 и энтропия Шеннона
              sentinel pe <файл> [--json]          разбор PE-заголовков
              sentinel rules [--rules <каталог>]   загрузка и валидация правил
              sentinel selftest [--rules <каталог>] самопроверка на синтетических артефактах (EICAR, PE-заглушки)
              sentinel audit-processes [--rules <каталог>] [--json] [--no-file-scan]
                                                   аудит активных процессов (только Windows)
              sentinel audit-startup [--rules <каталог>] [--json] [--no-file-scan]
                                                   аудит автозагрузки и персистентности (только Windows)
              sentinel audit-config [--json]       аудит целостности конфигурации безопасности
                                                   (исключения защиты, брандмауэр, корневые сертификаты, прокси; только Windows)

            Коды возврата: 0 — чисто, 1 — обнаружены угрозы/подозрения, 2 — ошибка.
            """);
    }

    private static string ResolveRulesDirectory(CliOptions opts)
    {
        if (opts.RulesDir is not null)
        {
            return Path.GetFullPath(opts.RulesDir);
        }

        var nearBinary = Path.Combine(AppContext.BaseDirectory, "rules");
        return Directory.Exists(nearBinary) ? nearBinary : Path.GetFullPath("rules");
    }

    private static (RuleSet Rules, FileAnalyzer Analyzer) CreateAnalyzer(CliOptions opts, bool printRuleErrors = true)
    {
        var ruleDir = ResolveRulesDirectory(opts);
        var rules = RuleLoader.LoadDirectory(ruleDir);
        if (printRuleErrors)
        {
            foreach (var e in rules.Errors)
            {
                Console.Error.WriteLine($"[правила] {e}");
            }
        }

        var verifier = SignatureVerifierFactory.CreateDefault();
        var whitelist = new SystemWhitelist(verifier, WhitelistOptions.CreateDefault());
        var analyzer = new FileAnalyzer(new SignatureEngine(rules), verifier, whitelist,
            new FileAnalyzerOptions { MaxScanBytes = opts.MaxSizeMb * 1024L * 1024 });
        return (rules, analyzer);
    }

    private static int Scan(CliOptions opts)
    {
        if (opts.Target is null)
        {
            Console.Error.WriteLine("Не указан путь для проверки.");
            return ExitError;
        }

        var (rules, analyzer) = CreateAnalyzer(opts);
        IEnumerable<string> files;
        if (File.Exists(opts.Target))
        {
            files = [opts.Target];
        }
        else if (Directory.Exists(opts.Target))
        {
            files = EnumerateFilesSafe(opts.Target, opts.Recurse);
        }
        else
        {
            Console.Error.WriteLine($"Путь не найден: {opts.Target}");
            return ExitError;
        }

        if (!opts.Json)
        {
            Console.WriteLine($"Правил загружено: {rules.Rules.Count} (ошибок: {rules.Errors.Count})");
        }

        var results = new List<FileScanResult>();
        foreach (var file in files)
        {
            var r = analyzer.Analyze(file);
            results.Add(r);
            if (!opts.Json)
            {
                PrintResult(r);
            }
        }

        var flagged = results.Count(r => r.Verdict is Verdict.Malicious or Verdict.Suspicious);
        var errors = results.Count(r => r.Verdict == Verdict.Error);
        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { scanned = results.Count, flagged, errors, results }, JsonOptions));
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine($"Проверено файлов: {results.Count}; угроз/подозрений: {flagged}; ошибок: {errors}");
        }

        return flagged > 0 ? ExitDetected : ExitOk;
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, bool recurse)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = recurse,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint, // не следуем по junction/symlink — защита от циклов
            ReturnSpecialDirectories = false,
        };
        return Directory.EnumerateFiles(root, "*", options);
    }

    private static void PrintResult(FileScanResult r)
    {
        var mark = r.Verdict switch
        {
            Verdict.Malicious => "УГРОЗА  ",
            Verdict.Suspicious => "ПОДОЗР. ",
            Verdict.Trusted => "ДОВЕРЕН ",
            Verdict.Error => "ОШИБКА  ",
            _ => "чисто   ",
        };
        Console.WriteLine($"[{mark}] {r.Path}");
        if (r.Error is not null)
        {
            Console.WriteLine($"           {r.Error}");
        }

        foreach (var d in r.Detections)
        {
            Console.WriteLine($"           {d.Severity,-8} {d.Name} [{d.Source}{(d.RuleId is null ? "" : ": " + d.RuleId)}] — {d.Description}");
        }
    }

    private static int Hash(CliOptions opts)
    {
        if (opts.Target is null || !File.Exists(opts.Target))
        {
            Console.Error.WriteLine("Укажите существующий файл.");
            return ExitError;
        }

        var sha = FileHasher.ComputeSha256(opts.Target);
        var entropy = EntropyCalculator.CalculateFile(opts.Target);
        Console.WriteLine($"SHA-256 : {sha}");
        Console.WriteLine($"Энтропия: {entropy.ToString("F4", CultureInfo.InvariantCulture)} бит/байт{(entropy >= EntropyCalculator.HighEntropyThreshold ? " (высокая — возможна упаковка/шифрование)" : "")}");
        return ExitOk;
    }

    private static int Pe(CliOptions opts)
    {
        if (opts.Target is null || !File.Exists(opts.Target))
        {
            Console.Error.WriteLine("Укажите существующий файл.");
            return ExitError;
        }

        var result = PeParser.ParseFile(opts.Target);
        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
            return result.IsPe ? ExitOk : ExitError;
        }

        if (!result.IsPe || result.Info is null)
        {
            Console.WriteLine($"Не PE-файл: {result.Error}");
            return ExitError;
        }

        var i = result.Info;
        Console.WriteLine($"Архитектура : {i.Machine} ({(i.Is64Bit ? "PE32+" : "PE32")}){(i.IsDll ? ", DLL" : "")}{(i.IsDriver ? ", драйвер" : "")}");
        Console.WriteLine($"Подсистема  : {i.Subsystem}");
        Console.WriteLine($"Метка времени: {i.TimeDateStamp:u}");
        Console.WriteLine($"Точка входа : 0x{i.EntryPointRva:X} ({i.EntryPointSection?.Name ?? "вне секций"})");
        Console.WriteLine($"ImageBase   : 0x{i.ImageBase:X}");
        Console.WriteLine($"Authenticode: {(i.HasAuthenticodeDirectory ? "каталог подписи присутствует" : "нет встроенной подписи")}");
        Console.WriteLine("Секции:");
        foreach (var s in i.Sections)
        {
            Console.WriteLine($"  {s.Name,-8} VA=0x{s.VirtualAddress:X8} VSize=0x{s.VirtualSize:X} Raw=0x{s.SizeOfRawData:X} H={s.Entropy:F2} {(s.IsExecutable ? "X" : "-")}{(s.IsWritable ? "W" : "-")}");
        }

        foreach (var a in i.Anomalies)
        {
            Console.WriteLine($"  ! {a}");
        }

        return ExitOk;
    }

    private static int Rules(CliOptions opts)
    {
        var dir = ResolveRulesDirectory(opts);
        var rules = RuleLoader.LoadDirectory(dir);
        Console.WriteLine($"Каталог правил: {dir}");
        foreach (var r in rules.Rules)
        {
            Console.WriteLine($"  {r.Id,-18} {r.Severity,-8} {r.Category,-8} {r.Name} ({Path.GetFileName(r.SourceFile)})");
        }

        foreach (var e in rules.Errors)
        {
            Console.WriteLine($"  ОШИБКА: {e}");
        }

        Console.WriteLine($"Итого: {rules.Rules.Count} правил, {rules.Errors.Count} ошибок.");
        return rules.Errors.Count == 0 ? ExitOk : ExitError;
    }

    /// <summary>
    /// Самопроверка: во временном каталоге создаются безопасные артефакты, проверяется
    /// корректность вердиктов, затем каталог удаляется.
    /// </summary>
    private static int SelfTest(CliOptions opts)
    {
        var (rules, analyzer) = CreateAnalyzer(opts);
        var dir = Directory.CreateTempSubdirectory("sentinel-selftest-");
        var failures = 0;
        try
        {
            var cases = new (string Name, byte[] Content, Func<FileScanResult, bool> Check, string Expect)[]
            {
                ("eicar.com", Eicar.CreateTestFileBytes(),
                    r => r.Verdict == Verdict.Malicious && r.Detections.Any(d => d.Name == Eicar.DetectionName), "Malicious/EICAR"),
                ("eicar-padded.txt", [.. Eicar.CreateTestFileBytes(), .. "\r\n  "u8.ToArray()],
                    r => r.Verdict == Verdict.Malicious, "Malicious/EICAR"),
                ("eicar-embedded.bin", [.. "prefix"u8.ToArray(), .. Eicar.CreateTestFileBytes()],
                    r => r.Detections.All(d => d.Name != Eicar.DetectionName), "не EICAR (нарушена спецификация)"),
                ("clean.txt", "Hello, Sentinel!"u8.ToArray(), r => r.Verdict == Verdict.Clean, "Clean"),
                ("stub-low.exe", SyntheticArtifacts.BuildPe(), r => r.Verdict == Verdict.Clean && r.Pe!.IsPe, "Clean/PE"),
                ("stub-packed.exe", SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x4000 }),
                    r => r.Verdict == Verdict.Suspicious && r.Detections.Any(d => d.Source == DetectionSource.Heuristic), "Suspicious/Packed"),
                ("miner-config.json", SyntheticArtifacts.MinerConfigSample(),
                    r => rules.Rules.All(x => x.Id != "SNT-MINER-0001") || r.Detections.Any(d => d.RuleId == "SNT-MINER-0001"), "SNT-MINER-0001"),
            };

            foreach (var (name, content, check, expect) in cases)
            {
                var path = Path.Combine(dir.FullName, name);
                File.WriteAllBytes(path, content);
                var result = analyzer.Analyze(path);
                var ok = check(result);
                if (!ok)
                {
                    failures++;
                }

                Console.WriteLine($"[{(ok ? "OK  " : "FAIL")}] {name,-20} вердикт={result.Verdict,-10} ожидалось: {expect}");
            }
        }
        finally
        {
            dir.Delete(recursive: true);
        }

        Console.WriteLine(failures == 0 ? "Самопроверка пройдена." : $"Самопроверка: {failures} ошибок.");
        return failures == 0 ? ExitOk : ExitError;
    }

    private static int AuditProcesses(CliOptions opts)
    {
        if (!ProcessProviderFactory.IsSupported)
        {
            Console.Error.WriteLine("Аудит процессов доступен только в Windows (используются Win32 API).");
            return ExitError;
        }

        var (_, analyzer) = CreateAnalyzer(opts, printRuleErrors: !opts.Json);
        var provider = ProcessProviderFactory.CreateDefault();
        var auditor = new ProcessAuditor(
            new ProcessAuditorOptions { AnalyzeExecutable = !opts.NoFileScan },
            opts.NoFileScan ? null : analyzer);

        var processes = provider.GetProcesses();
        var report = auditor.Audit(processes);

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                processes = report.ProcessCount,
                flagged = report.FlaggedCount,
                entries = report.Flagged.Select(e => new
                {
                    e.Process.Pid,
                    e.Process.ParentPid,
                    e.Process.Name,
                    e.Process.ExecutablePath,
                    e.Process.CommandLine,
                    e.Process.CpuPercent,
                    verdict = e.FileScan?.Verdict,
                    findings = e.Findings,
                }),
            }, JsonOptions));
        }
        else
        {
            Console.WriteLine($"Процессов проверено: {report.ProcessCount}; с находками: {report.FlaggedCount}");
            foreach (var e in report.Flagged.OrderByDescending(x => x.Findings.Max(f => f.Severity)))
            {
                Console.WriteLine();
                Console.WriteLine($"PID {e.Process.Pid,-6} {e.Process.Name}  ({e.Process.ExecutablePath ?? "путь неизвестен"})");
                foreach (var f in e.Findings.OrderByDescending(f => f.Severity))
                {
                    Console.WriteLine($"  [{f.Severity,-8}] {f.Id,-18} {f.Title}");
                    Console.WriteLine($"             {f.Description}");
                }
            }
        }

        return report.FlaggedCount > 0 ? ExitDetected : ExitOk;
    }

    private static int AuditStartup(CliOptions opts)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Аудит автозагрузки доступен только в Windows (реестр, планировщик, WMI).");
            return ExitError;
        }

        var (_, analyzer) = CreateAnalyzer(opts, printRuleErrors: !opts.Json);
        var auditor = new PersistenceAuditor(
            PersistenceAuditorOptions.CreateDefault(),
            RegistryProviderFactory.CreateDefault(),
            new WindowsTaskSchedulerProvider(),
            new WindowsWmiSubscriptionProvider(),
            opts.NoFileScan ? null : analyzer);

        var report = auditor.Audit();

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                total = report.Count,
                flagged = report.FlaggedCount,
                entries = report.Flagged.Select(e => new
                {
                    kind = e.Kind.ToString(),
                    e.Location,
                    e.Name,
                    e.Command,
                    e.ResolvedTarget,
                    severity = e.MaxSeverity.ToString(),
                    verdict = e.FileScan?.Verdict,
                    findings = e.Findings,
                }),
            }, JsonOptions));
        }
        else
        {
            Console.WriteLine($"Точек автозапуска проверено: {report.Count}; с находками: {report.FlaggedCount}");
            foreach (var e in report.Flagged.OrderByDescending(x => x.MaxSeverity))
            {
                Console.WriteLine();
                Console.WriteLine($"[{e.Kind}] {e.Name}  ({e.Location})");
                if (!string.IsNullOrEmpty(e.Command))
                {
                    Console.WriteLine($"   команда: {e.Command}");
                }

                foreach (var f in e.Findings.OrderByDescending(f => f.Severity))
                {
                    Console.WriteLine($"   [{f.Severity,-8}] {f.Id,-24} {f.Title}");
                    Console.WriteLine($"              {f.Description}");
                }
            }
        }

        return report.FlaggedCount > 0 ? ExitDetected : ExitOk;
    }

    private static int AuditConfig(CliOptions opts)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Аудит конфигурации доступен только в Windows (реестр, хранилище сертификатов).");
            return ExitError;
        }

        var auditor = new ConfigIntegrityAuditor(
            ConfigIntegrityAuditorOptions.CreateDefault(),
            RegistryProviderFactory.CreateDefault(),
            new WindowsRootCertificateProvider());

        var report = auditor.Audit();

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                total = report.Count,
                findings = report.Findings.Select(f => new
                {
                    area = f.Area.ToString(),
                    severity = f.Severity.ToString(),
                    f.Finding.Id,
                    f.Finding.Title,
                    f.Finding.Description,
                    f.Finding.Evidence,
                }),
            }, JsonOptions));
        }
        else
        {
            Console.WriteLine($"Находок по конфигурации: {report.Count}");
            foreach (var group in report.Findings.GroupBy(f => f.Area))
            {
                Console.WriteLine();
                Console.WriteLine($"=== {group.Key} ===");
                foreach (var f in group.OrderByDescending(x => x.Severity))
                {
                    Console.WriteLine($"  [{f.Severity,-8}] {f.Finding.Id,-20} {f.Finding.Title}");
                    Console.WriteLine($"             {f.Finding.Description}");
                }
            }
        }

        return report.Count > 0 ? ExitDetected : ExitOk;
    }
}

internal sealed class CliOptions
{
    public string? Target { get; private set; }
    public string? RulesDir { get; private set; }
    public bool Json { get; private set; }
    public bool Recurse { get; private set; } = true;
    public int MaxSizeMb { get; private set; } = 64;
    public bool NoFileScan { get; private set; }
    public string? Error { get; private set; }

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--rules" when i + 1 < args.Length:
                    o.RulesDir = args[++i];
                    break;
                case "--json":
                    o.Json = true;
                    break;
                case "--no-recurse":
                    o.Recurse = false;
                    break;
                case "--no-file-scan":
                    o.NoFileScan = true;
                    break;
                case "--max-size" when i + 1 < args.Length:
                    if (!int.TryParse(args[++i], NumberStyles.None, CultureInfo.InvariantCulture, out var mb) || mb is < 1 or > 4096)
                    {
                        o.Error = "--max-size: ожидается число МБ от 1 до 4096.";
                    }
                    else
                    {
                        o.MaxSizeMb = mb;
                    }

                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                    {
                        o.Error = $"Неизвестный или неполный параметр '{args[i]}'.";
                    }
                    else if (o.Target is null)
                    {
                        o.Target = args[i];
                    }
                    else
                    {
                        o.Error = $"Лишний аргумент '{args[i]}'.";
                    }

                    break;
            }
        }

        return o;
    }
}
