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
using Sentinel.Core.Remediation;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;
using Sentinel.Core.ThreatIntel;
using Sentinel.Core.Scanning.Pool;
using Sentinel.Core.Runtime;
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
        // Рабочий процесс пула: общение только через Named Pipe, в консоль ничего не пишется.
        if (args.Length > 0 && args[0] == "--scan-worker")
        {
            return RunScanWorker(args);
        }

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

        if (opts.DryRun && !opts.Remediate)
        {
            Console.Error.WriteLine("Ошибка: --dry-run используется только вместе с --remediate.");
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
                "audit-memory" => AuditMemory(opts),
                "audit-startup" => AuditStartup(opts),
                "audit-config" => AuditConfig(opts),
                "quarantine" => Quarantine(opts),
                "rollback" => Rollback(opts),
                "service-status" => ServiceStatus(opts),
                "threatdb" => ThreatDb(opts),
                "scan-usb" => ScanUsb(opts),
                "behavioral-status" => BehavioralStatus(opts),
                _ => Unknown(args[0]),
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Text.Json.JsonException)
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
              sentinel scan-usb [путь]        проверка съёмных носителей USB-щитом
              sentinel behavioral-status     состояние поведенческого щита
              sentinel scan <путь> [--rules <каталог>] [--json] [--no-recurse] [--max-size <МБ>] [действия] [отчёт]
              sentinel hash <файл>                 SHA-256 и энтропия Шеннона
              sentinel pe <файл> [--json]          разбор PE-заголовков
              sentinel rules [--rules <каталог>]   загрузка и валидация правил
              sentinel selftest [--rules <каталог>] самопроверка на синтетических артефактах (EICAR, PE-заглушки)
              sentinel audit-processes [--rules <каталог>] [--json] [--no-file-scan] [действия] [отчёт]
                                                   аудит активных процессов (только Windows)
              sentinel audit-memory [PID] [--rules <каталог>] [--json]
                                                   потоковый аудит памяти процессов: RWX-регионы, PE-образы без файла,
                                                   сигнатуры в памяти; без PID — все процессы (только Windows)
              sentinel audit-startup [--rules <каталог>] [--json] [--no-file-scan] [действия] [отчёт]
                                                   аудит автозагрузки и персистентности (только Windows)
              sentinel audit-config [--rules <каталог>] [--json] [действия] [отчёт]
                                                   аудит конфигурации безопасности (исключения защиты, брандмауэр,
                                                   корневые сертификаты, прокси) с приоритетной глубокой проверкой
                                                   файлов и процессов под исключениями Defender (только Windows)
              sentinel quarantine list [--json]    записи карантина
              sentinel quarantine restore <id> [--overwrite]
                                                   вернуть файл на исходное место (с проверкой SHA-256)
              sentinel rollback list [--json]      резервные копии изменённых параметров
              sentinel rollback undo <id>          отменить изменение конфигурации/автозагрузки
              sentinel service-status [--pipe <имя>] [--json]
                                                   состояние фоновой службы Sentinel.Service (по именованному каналу)

            Действия:
              --remediate            нейтрализация: завершение деревьев процессов (находки High+), изоляция файлов
                                     в карантин (детекты Medium+), откат автозагрузки и удаление исключений Defender
              --dry-run              вместе с --remediate: только показать, что было бы сделано, без изменений
              --data-dir <каталог>   каталог данных (карантин и манифест отката); по умолчанию %ProgramData%\Sentinel
              --allowed-exclusions <файл>
                                     белый список пользователя (пути и процессы, которые не изолируются, и исключения
                                     Defender, которые не удаляются); по умолчанию <каталог данных>\allowed_exclusions.json

            Отчёт:
              --report-html <путь>   самодостаточный HTML-отчёт (тёмная тема, фильтры)
              --report-json <путь>   структурированный JSON-отчёт

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
        var services = SentinelServices.Create(DataDirectory(opts), ResolveRulesDirectory(opts), opts.AllowedExclusions, opts.MaxSizeMb * 1024L * 1024);
        if (printRuleErrors)
        {
            foreach (var e in services.Rules.Errors)
            {
                Console.Error.WriteLine($"[правила] {e}");
            }
        }

        return (services.Rules, services.Analyzer);
    }

    /// <summary><c>--scan-worker --pipe &lt;имя&gt; --parent-pid &lt;pid&gt; [--rules каталог] [--data-dir каталог] [--allowed-exclusions файл]</c>.</summary>
    private static int RunScanWorker(string[] args)
    {
        string? pipe = null, rules = null, data = null, allowed = null;
        var parent = 0;
        for (var i = 1; i < args.Length - 1; i++)
        {
            switch (args[i])
            {
                case "--pipe": pipe = args[++i]; break;
                case "--parent-pid": parent = int.Parse(args[++i], CultureInfo.InvariantCulture); break;
                case "--rules": rules = args[++i]; break;
                case "--data-dir": data = args[++i]; break;
                case "--allowed-exclusions": allowed = args[++i]; break;
            }
        }

        if (string.IsNullOrEmpty(pipe) || parent <= 0)
        {
            return ExitError;
        }

        try
        {
            // Фоновая проверка не должна мешать работе пользователя.
            System.Diagnostics.Process.GetCurrentProcess().PriorityClass = System.Diagnostics.ProcessPriorityClass.BelowNormal;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or PlatformNotSupportedException or InvalidOperationException)
        {
            // приоритет — оптимизация
        }

        using var services = SentinelServices.Create(data ?? SentinelRuntimeOptions.DefaultDataDirectory(), rules ?? SentinelRuntimeOptions.DefaultRulesDirectory(), allowed);
        return ScanWorkerHost.RunAsync(pipe, parent, path => services.Analyzer.Analyze(path)).GetAwaiter().GetResult();
    }

    /// <summary><c>threatdb build --out файл [--signature-base каталог] [--eset каталог]</c>, <c>threatdb info</c>, <c>threatdb lookup &lt;sha256&gt;</c>.</summary>
    /// <summary><c>scan-usb [путь|диск]</c> — проверка съёмных носителей или указанного пути USB-щитом.</summary>
    private static int ScanUsb(CliOptions opts)
    {
        var (_, analyzer) = CreateAnalyzer(opts);
        var shield = new Sentinel.Core.Protection.RemovableMediaShield(path =>
        {
            var r = analyzer.Analyze(path);
            return r.Verdict is Verdict.Malicious or Verdict.Suspicious && r.Detections.Count > 0
                ? r.Detections.Max(d => d.Severity)
                : (Severity?)null;
        });

        string[] roots;
        if (opts.Target is { Length: > 0 } target)
        {
            roots = [target];
        }
        else if (OperatingSystem.IsWindows())
        {
            roots = System.IO.DriveInfo.GetDrives()
                .Where(d => d is { DriveType: System.IO.DriveType.Removable, IsReady: true })
                .Select(d => d.RootDirectory.FullName).ToArray();
        }
        else
        {
            roots = [];
        }

        if (roots.Length == 0)
        {
            Console.WriteLine("Съёмные носители не обнаружены. Укажите путь: sentinel scan-usb <папка|диск>");
            return ExitOk;
        }

        var findings = new List<Sentinel.Core.Protection.UsbFinding>();
        foreach (var root in roots)
        {
            Console.WriteLine($"Проверка: {root}");
            findings.AddRange(shield.ScanDirectory(root));
        }

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(findings.Select(f => new { f.Kind, Severity = f.Severity.ToString(), f.Path, f.Description }), JsonOptions));
        }
        else if (findings.Count == 0)
        {
            Console.WriteLine("Угроз на носителях не найдено.");
        }
        else
        {
            foreach (var f in findings)
            {
                Console.WriteLine($"  [{f.Severity}] {f.Kind}: {f.Path}");
                Console.WriteLine($"      {f.Description}");
            }
        }

        return findings.Any(f => f.Severity >= Severity.High) ? ExitDetected : ExitOk;
    }

    /// <summary><c>behavioral-status</c> — состояние поведенческого щита и файлов-приманок (по конфигурации каталога данных).</summary>
    private static int BehavioralStatus(CliOptions opts)
    {
        var store = Sentinel.Core.ThreatIntel.SentinelConfigStore.ForDataDirectory(DataDirectory(opts));
        Sentinel.Core.ThreatIntel.SentinelConfig config;
        try
        {
            config = store.Load();
        }
        catch (System.Text.Json.JsonException ex)
        {
            Console.Error.WriteLine($"Повреждён {store.Path}: {ex.Message}");
            return ExitError;
        }

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                config.EnableRansomwareShield,
                config.EnableCanaryFiles,
                config.EnableUsbShield,
                config.BehavioralShadowMode,
            }, JsonOptions));
            return ExitOk;
        }

        Console.WriteLine("Поведенческий щит Sentinel:");
        Console.WriteLine($"  Анти-шифровальщик : {OnOff(config.EnableRansomwareShield)}");
        Console.WriteLine($"  Файлы-приманки    : {OnOff(config.EnableCanaryFiles)}");
        Console.WriteLine($"  USB-щит           : {OnOff(config.EnableUsbShield)}");
        Console.WriteLine($"  Теневой режим     : {OnOff(config.BehavioralShadowMode)}");
        Console.WriteLine($"  Каталог данных    : {DataDirectory(opts)}");
        return ExitOk;

        static string OnOff(bool value) => value ? "включён" : "выключен";
    }

    private static int ThreatDb(CliOptions opts)
    {
        switch (opts.Target)
        {
            case "build":
            {
                if (opts.Output is null)
                {
                    Console.Error.WriteLine("Укажите файл: sentinel threatdb build --out data/threat_hashes.bin --signature-base <каталог> --eset <каталог>");
                    return ExitError;
                }

                var entries = new List<ThreatHashEntry>(ThreatDatabaseSources.Eicar());
                if (opts.SignatureBaseDir is not null)
                {
                    entries.AddRange(ThreatDatabaseSources.FromSignatureBase(opts.SignatureBaseDir));
                }

                if (opts.EsetDir is not null)
                {
                    entries.AddRange(ThreatDatabaseSources.FromEset(opts.EsetDir));
                }

                var timestamp = opts.Timestamp ?? DateTimeOffset.UtcNow;
                var count = ThreatHashDatabaseBuilder.BuildToFile(entries, timestamp, opts.Output);
                using var db = ThreatHashDatabase.Open(opts.Output);
                Console.WriteLine($"База собрана: {opts.Output} — {count} SHA-256, семейств: {db.FamilyCount}, метка {timestamp:u}.");
                return ExitOk;
            }

            case "info":
            {
                using var engine = new ThreatIntelligenceEngine(DataDirectory(opts), ThreatIntelligenceEngine.DefaultBundledPath());
                Console.WriteLine($"Активная база: {engine.ActivePath ?? "нет"}; записей: {engine.Count}; метка: {engine.TimestampUtc:u}");
                return engine.Count > 0 ? ExitOk : ExitError;
            }

            case "lookup" when opts.Argument is not null:
            {
                using var engine = new ThreatIntelligenceEngine(DataDirectory(opts), ThreatIntelligenceEngine.DefaultBundledPath());
                if (engine.TryGetFamily(opts.Argument, out var family))
                {
                    Console.WriteLine($"Найден: {family}");
                    return ExitDetected;
                }

                Console.WriteLine("Не найден в базе угроз.");
                return ExitOk;
            }

            case "update":
            {
                using var engine = new ThreatIntelligenceEngine(DataDirectory(opts), ThreatIntelligenceEngine.DefaultBundledPath());
                using var updater = new ThreatFeedUpdater(DataDirectory(opts), SentinelConfigStore.ForDataDirectory(DataDirectory(opts)), engine, SentinelServices.Http);
                var status = updater.UpdateAsync().GetAwaiter().GetResult();
                foreach (var source in status.Sources)
                {
                    Console.WriteLine($"  [{source.Status}] {source.Name}: хешей {source.Hashes}, сетевых {source.NetworkIndicators}. {source.Message}");
                }

                Console.WriteLine(status.LastStatus);
                return status.LastSuccessUtc is null ? ExitError : ExitOk;
            }

            default:
                Console.Error.WriteLine("Использование: sentinel threatdb build|info|update|lookup <sha256>");
                return ExitError;
        }
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

        var session = new Session("scan", opts);
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
        session.Report.AddFileScan("Файлы", results);
        if (opts.Remediate)
        {
            // Для файлового сканирования достаточно карантина — он работает на любой ОС.
            using var response = session.CreateResponse(analyzer.Whitelist, requireEngine: false);
            response.Coordinator.HandleFilesAsync(results).GetAwaiter().GetResult();
        }

        var report = session.Finish();
        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { scanned = results.Count, flagged, errors, results, actions = ActionSummary(report, opts) }, JsonOptions));
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine($"Проверено файлов: {results.Count}; угроз/подозрений: {flagged}; ошибок: {errors}");
            PrintActions(report, opts);
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
                ("stub-packed.exe", SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, WritableText = true, TextSize = 0x4000 }),
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

        var session = new Session("audit-processes", opts);
        var processes = provider.GetProcesses();
        var report = auditor.Audit(processes);
        session.Report.AddProcessAudit(report);
        if (opts.Remediate)
        {
            using var response = session.CreateResponse(analyzer.Whitelist, requireEngine: true);
            response.Coordinator.HandleProcessesAsync(report).GetAwaiter().GetResult();
        }

        var final = session.Finish();

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                actions = ActionSummary(final, opts),
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

            PrintActions(final, opts);
        }

        return report.FlaggedCount > 0 ? ExitDetected : ExitOk;
    }

    /// <summary>
    /// <c>audit-memory [PID]</c> — аудит целостности памяти одного или всех процессов. Защищённые процессы ОС и Sentinel
    /// отсекаются <c>CriticalProcessGuard</c> до открытия дескриптора. Только чтение: нейтрализация — через службу.
    /// </summary>
    private static int AuditMemory(CliOptions opts)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Аудит памяти процессов доступен только в Windows (VirtualQueryEx/ReadProcessMemory).");
            return ExitError;
        }

        int? pid = null;
        if (opts.Target is not null)
        {
            if (!int.TryParse(opts.Target, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed <= 0)
            {
                Console.Error.WriteLine($"Ошибка: '{opts.Target}' — не идентификатор процесса.");
                return ExitError;
            }

            pid = parsed;
        }

        var (rules, _) = CreateAnalyzer(opts, printRuleErrors: !opts.Json);
        var scanner = new Sentinel.Core.Auditors.Memory.MemoryIntegrityScanner(
            new Sentinel.Core.Auditors.Memory.WindowsMemoryReader(), new SignatureEngine(rules));
        var processes = new WindowsProcessProvider(TimeSpan.Zero).GetProcesses()
            .Where(p => pid is null || p.Pid == pid)
            .ToArray();
        if (pid is not null && processes.Length == 0)
        {
            Console.Error.WriteLine($"Процесс PID {pid} не найден.");
            return ExitError;
        }

        var results = processes
            .Select(p => (Process: p, Result: scanner.Scan(p.Pid, p.Name, p.ExecutablePath)))
            .ToArray();
        var flagged = results.Where(r => r.Result.HasAnomalies).ToArray();
        // Код выхода 1 — только угрозы: PE/сигнатура в памяти или Medium+. Одиночный RWX-патч образа (Low) — сведения.
        var threats = flagged.Count(r => r.Result.IsThreat);

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                processes = results.Length,
                skipped = results.Count(r => r.Result.Skipped),
                flagged = flagged.Length,
                threats,
                entries = results.Where(r => pid is not null || r.Result.HasAnomalies).Select(r => new
                {
                    r.Process.Pid,
                    r.Process.Name,
                    r.Process.ExecutablePath,
                    r.Result.SkipReason,
                    r.Result.RegionsTotal,
                    r.Result.RegionsInspected,
                    r.Result.PrivateWriteExecuteRegions,
                    r.Result.BytesRead,
                    r.Result.BudgetExhausted,
                    r.Result.SuppressedRuntimePatches,
                    r.Result.IsThreat,
                    score = r.Result.Score.Value,
                    anomalies = r.Result.Anomalies.Select(a => new { a.Id, a.Address, a.Severity, a.Detail, protect = $"0x{a.Protect:X}", type = $"0x{a.Type:X}" }),
                }),
            }, JsonOptions));
        }
        else
        {
            Console.WriteLine($"Процессов: {results.Length}; пропущено предохранителем: {results.Count(r => r.Result.Skipped)}; "
                + $"с аномалиями памяти: {flagged.Length}; из них угроз: {threats}");
            foreach (var (process, result) in pid is null ? flagged : results)
            {
                Console.WriteLine();
                Console.WriteLine($"PID {process.Pid,-6} {process.Name}  ({process.ExecutablePath ?? "путь неизвестен"})");
                if (result.Skipped)
                {
                    Console.WriteLine($"  пропущен: {result.SkipReason}");
                    continue;
                }

                Console.WriteLine($"  регионов: {result.RegionsTotal}, прочитано: {result.RegionsInspected} ({result.BytesRead / 1024} КБ), "
                    + $"приватных RWX: {result.PrivateWriteExecuteRegions}, балл: {result.Score.Value}{(result.BudgetExhausted ? ", бюджет чтения исчерпан" : string.Empty)}"
                    + (result.SuppressedRuntimePatches > 0 ? $", штатных RWX-страниц CLR: {result.SuppressedRuntimePatches}" : string.Empty));
                foreach (var a in result.Anomalies.OrderByDescending(a => a.Severity))
                {
                    Console.WriteLine($"  [{a.Severity,-8}] {a.Id,-20} {a.Address}  {a.Detail}");
                }
            }
        }

        return threats > 0 ? ExitDetected : ExitOk;
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

        var session = new Session("audit-startup", opts);
        var report = auditor.Audit();
        session.Report.AddPersistenceAudit(report);
        if (opts.Remediate)
        {
            using var response = session.CreateResponse(analyzer.Whitelist, requireEngine: true);
            response.Coordinator.HandlePersistenceAsync(report).GetAwaiter().GetResult();
        }

        var final = session.Finish();

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                actions = ActionSummary(final, opts),
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

            PrintActions(final, opts);
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
            new WindowsRootCertificateProvider(),
            new WindowsDefenderExclusionSource());

        var session = new Session("audit-config", opts);
        var report = auditor.Audit();
        session.Report.AddConfigAudit(report);

        // Связная проверка: всё, что исключено из встроенной защиты, проверяется в первую очередь и глубоко.
        var (_, analyzer) = CreateAnalyzer(opts, printRuleErrors: !opts.Json);
        ExclusionScanReport? exclusionScan = null;
        if (report.DefenderExclusions.Count > 0)
        {
            var scanner = new ExclusionPriorityScanner(analyzer, new ProcessAuditor(new ProcessAuditorOptions(), analyzer));
            exclusionScan = scanner.Scan(report.DefenderExclusions, ProcessProviderFactory.CreateDefault(TimeSpan.Zero).GetProcesses());
            session.Report.AddExclusionScan(exclusionScan);
            foreach (var p in exclusionScan.ExcludedProcesses)
            {
                session.Report.AddProcessFinding(p, "Процессы под исключениями Defender");
            }
        }

        if (opts.Remediate)
        {
            using var response = session.CreateResponse(analyzer.Whitelist, requireEngine: true);
            response.Coordinator.HandleConfigAsync(report, exclusionScan).GetAwaiter().GetResult();
        }

        var final = session.Finish();

        if (opts.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                actions = ActionSummary(final, opts),
                excluded = exclusionScan?.Entries.Select(e => new
                {
                    exclusion = e.Exclusion.ToString(),
                    filesScanned = e.Files.Count,
                    flagged = e.FlaggedFiles.Select(f => new { f.Path, f.Sha256, verdict = f.Verdict.ToString() }),
                    processes = e.Processes.Select(p => p.Process.Pid),
                    e.Truncated,
                    e.Note,
                }),
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

            if (exclusionScan is not null)
            {
                Console.WriteLine();
                Console.WriteLine("=== Приоритетная проверка областей под исключениями Defender ===");
                foreach (var e in exclusionScan.Entries)
                {
                    Console.WriteLine($"  {e.Exclusion}: файлов проверено {e.Files.Count}, угроз/подозрений {e.FlaggedFiles.Count()}, процессов {e.Processes.Count}"
                        + (e.Truncated ? " (обход усечён)" : string.Empty));
                    if (e.Note is not null)
                    {
                        Console.WriteLine($"      {e.Note}");
                    }

                    foreach (var file in e.FlaggedFiles)
                    {
                        PrintResult(file);
                    }
                }
            }

            PrintActions(final, opts);
        }

        return report.Count > 0 ? ExitDetected : ExitOk;
    }

    // ---- Карантин и откат ------------------------------------------------------

    private static string DataDirectory(CliOptions opts) =>
        opts.DataDir is not null
            ? Path.GetFullPath(opts.DataDir)
            : Path.GetDirectoryName(QuarantineOptions.CreateDefault().QuarantineDirectory)!;

    private static QuarantineManager CreateQuarantine(CliOptions opts, Sentinel.Core.Trust.IWhitelistProvider whitelist) =>
        new(whitelist, new QuarantineOptions { QuarantineDirectory = Path.Combine(DataDirectory(opts), "Quarantine") });

    private static SystemWhitelist DefaultWhitelist() =>
        new(SignatureVerifierFactory.CreateDefault(), WhitelistOptions.CreateDefault());

    private static int Quarantine(CliOptions opts)
    {
        using var manager = CreateQuarantine(opts, DefaultWhitelist());
        switch (opts.Target)
        {
            case "list":
            {
                var records = manager.ListAsync().GetAwaiter().GetResult();
                if (opts.Json)
                {
                    // Ключ преобразования в вывод не попадает — он нужен только самому карантину.
                    Console.WriteLine(JsonSerializer.Serialize(records.Select(r => new
                    {
                        r.Id, r.State, r.OriginalPath, r.Sha256, r.Size, r.QuarantinedAtUtc, r.RestoredAtUtc, r.Reason,
                    }), JsonOptions));
                    return ExitOk;
                }

                Console.WriteLine($"Каталог карантина: {manager.QuarantineDirectory}");
                if (records.Count == 0)
                {
                    Console.WriteLine("Карантин пуст.");
                    return ExitOk;
                }

                foreach (var r in records)
                {
                    Console.WriteLine();
                    Console.WriteLine($"{r.Id}  [{(r.State == QuarantineState.Quarantined ? "в карантине" : "восстановлен")}]  {r.QuarantinedAtUtc:u}");
                    Console.WriteLine($"   путь    : {r.OriginalPath}");
                    Console.WriteLine($"   SHA-256 : {r.Sha256}  ({r.Size} байт)");
                    Console.WriteLine($"   причина : {r.Reason}");
                }

                return ExitOk;
            }

            case "restore":
            {
                if (opts.Argument is null)
                {
                    Console.Error.WriteLine("Укажите идентификатор записи: sentinel quarantine restore <id>");
                    return ExitError;
                }

                var result = manager.RestoreAsync(opts.Argument, opts.Overwrite).GetAwaiter().GetResult();
                (result.Success ? Console.Out : Console.Error).WriteLine(result.Message);
                return result.Success ? ExitOk : ExitError;
            }

            default:
                Console.Error.WriteLine("Использование: sentinel quarantine list | sentinel quarantine restore <id>");
                return ExitError;
        }
    }

    private static int Rollback(CliOptions opts)
    {
        var options = RemediationOptions.CreateDefault(DataDirectory(opts));
        switch (opts.Target)
        {
            case "list":
            {
                var entries = new RollbackManifestStore(options.RollbackManifestPath).Load();
                if (opts.Json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(entries, JsonOptions));
                    return ExitOk;
                }

                Console.WriteLine($"Манифест отката: {options.RollbackManifestPath}");
                if (entries.Count == 0)
                {
                    Console.WriteLine("Записей нет.");
                }

                foreach (var e in entries.OrderByDescending(e => e.TimestampUtc))
                {
                    Console.WriteLine($"{e.Id}  [{(e.UndoneAtUtc is null ? "применено" : "отменено")}]  {e.TimestampUtc:u}  {e.Kind}: {e.Target}{(e.Name is null ? "" : " → " + e.Name)}");
                }

                return ExitOk;
            }

            case "undo":
            {
                if (opts.Argument is null)
                {
                    Console.Error.WriteLine("Укажите идентификатор записи: sentinel rollback undo <id>");
                    return ExitError;
                }

                if (!OperatingSystem.IsWindows())
                {
                    Console.Error.WriteLine("Отмена изменений конфигурации доступна только в Windows.");
                    return ExitError;
                }

                var action = RemediationEngine.CreateDefault(DefaultWhitelist(), options).Undo(opts.Argument);
                (action.Success ? Console.Out : Console.Error).WriteLine($"{action.Target}: {action.Message}");
                return action.Success ? ExitOk : ExitError;
            }

            default:
                Console.Error.WriteLine("Использование: sentinel rollback list | sentinel rollback undo <id>");
                return ExitError;
        }
    }

    private static int ServiceStatus(CliOptions opts)
    {
        var client = Sentinel.Core.Ipc.SentinelIpcClient
            .TryConnectAsync(opts.Pipe ?? Sentinel.Core.Ipc.IpcProtocol.DefaultPipeName, TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
        if (client is null)
        {
            Console.Error.WriteLine("Служба Sentinel не запущена или недоступна.");
            return ExitError;
        }

        try
        {
            var status = client.GetStatusAsync().GetAwaiter().GetResult();
            if (opts.Json)
            {
                Console.WriteLine(JsonSerializer.Serialize(status, JsonOptions));
                return ExitOk;
            }

            Console.WriteLine($"Служба Sentinel {status.Version} ({status.Platform}), запущена {status.StartedAtUtc:u}");
            Console.WriteLine($"  Защита в реальном времени : {(status.RealtimeEnabled ? "включена" : "приостановлена")}");
            Console.WriteLine($"  Наблюдаемых каталогов     : {status.WatchedDirectories.Count}");
            Console.WriteLine($"  Правил загружено          : {status.RulesLoaded}");
            Console.WriteLine($"  Проверено файлов/процессов: {status.FilesChecked} / {status.ProcessesChecked}");
            Console.WriteLine($"  Находок / ждут решения    : {status.ThreatsTotal} / {status.PendingDecisions}");
            Console.WriteLine($"  В карантине               : {status.Quarantined}");
            return ExitOk;
        }
        finally
        {
            client.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    // ---- Сеанс: отчёт и нейтрализация ------------------------------------------

    private static object? ActionSummary(SentinelReport report, CliOptions opts) =>
        opts.Remediate
            ? new
            {
                mode = report.Mode,
                quarantined = report.Quarantined,
                terminated = report.ProcessesTerminated,
                cleaned = report.ConfigCleaned,
                findings = report.Findings
                    .Where(f => f.ActionStatus != FindingActionStatus.Detected)
                    .Select(f => new { f.Name, f.Path, status = f.ActionStatus.ToString(), f.ActionMessage }),
            }
            : null;

    private static void PrintActions(SentinelReport report, CliOptions opts)
    {
        if (!opts.Remediate)
        {
            return;
        }

        Console.WriteLine();
        Console.WriteLine(opts.DryRun ? "=== Предпросмотр нейтрализации (изменений нет) ===" : "=== Нейтрализация ===");
        var acted = report.Findings.Where(f => f.ActionStatus != FindingActionStatus.Detected).ToArray();
        if (acted.Length == 0)
        {
            Console.WriteLine("  Действий не требуется.");
        }

        foreach (var f in acted)
        {
            Console.WriteLine($"  [{ReportGenerator.StatusLabel(f.ActionStatus)}] {f.Name}");
            if (!string.IsNullOrEmpty(f.ActionMessage))
            {
                Console.WriteLine($"      {f.ActionMessage}");
            }
        }

        if (!opts.DryRun)
        {
            Console.WriteLine($"  Изолировано: {report.Quarantined}; процессов завершено: {report.ProcessesTerminated}; параметров очищено: {report.ConfigCleaned}");
            Console.WriteLine("  Отмена: sentinel quarantine restore <id> / sentinel rollback undo <id>");
        }
    }

    /// <summary>Один запуск команды: сборщик отчёта, таймер и (по требованию) средства нейтрализации.</summary>
    private sealed class Session
    {
        private readonly CliOptions _opts;
        private readonly System.Diagnostics.Stopwatch _watch = System.Diagnostics.Stopwatch.StartNew();

        public Session(string command, CliOptions opts)
        {
            _opts = opts;
            Report = new ReportBuilder(command + (opts.Target is null ? string.Empty : " " + opts.Target)
                + (opts.Remediate ? " --remediate" : string.Empty) + (opts.DryRun ? " --dry-run" : string.Empty));
        }

        public ReportBuilder Report { get; }

        public Response CreateResponse(Sentinel.Core.Trust.IWhitelistProvider? analyzerWhitelist, bool requireEngine)
        {
            // Карантин и нейтрализация обязаны работать с белым списком: без него действия не выполняются.
            var whitelist = analyzerWhitelist ?? DefaultWhitelist();
            var quarantine = CreateQuarantine(_opts, whitelist);
            RemediationEngine? engine = null;
            if (requireEngine || OperatingSystem.IsWindows())
            {
                engine = RemediationEngine.CreateDefault(whitelist, RemediationOptions.CreateDefault(DataDirectory(_opts), _opts.DryRun));
            }

            // Пользовательский белый список: его пути, процессы и исключения Defender нейтрализации не подлежат.
            var allowedStore = _opts.AllowedExclusions is not null
                ? new AllowedExclusionStore(_opts.AllowedExclusions)
                : AllowedExclusionStore.ForDataDirectory(DataDirectory(_opts));
            var allowed = allowedStore.Load();
            if (!allowed.IsEmpty)
            {
                Console.Error.WriteLine($"Разрешённые исключения: {allowedStore.Path} (путей: {allowed.Paths.Count}, процессов: {allowed.Processes.Count})");
            }

            return new Response(quarantine, new ResponseCoordinator(quarantine, engine, Report, new ResponsePolicy { DryRun = _opts.DryRun }, allowed));
        }

        public SentinelReport Finish()
        {
            var report = Report.Build(_watch.Elapsed, !_opts.Remediate ? "audit" : _opts.DryRun ? "dry-run" : "remediate");
            if (_opts.ReportJson is not null)
            {
                ReportGenerator.WriteJson(report, _opts.ReportJson);
                Console.Error.WriteLine($"JSON-отчёт: {Path.GetFullPath(_opts.ReportJson)}");
            }

            if (_opts.ReportHtml is not null)
            {
                ReportGenerator.WriteHtml(report, _opts.ReportHtml);
                Console.Error.WriteLine($"HTML-отчёт: {Path.GetFullPath(_opts.ReportHtml)}");
            }

            return report;
        }
    }

    private sealed record Response(QuarantineManager Quarantine, ResponseCoordinator Coordinator) : IDisposable
    {
        public void Dispose() => Quarantine.Dispose();
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
    public bool Remediate { get; private set; }
    public bool DryRun { get; private set; }
    public bool Overwrite { get; private set; }
    public string? ReportHtml { get; private set; }
    public string? ReportJson { get; private set; }
    public string? DataDir { get; private set; }
    public string? AllowedExclusions { get; private set; }
    public string? Pipe { get; private set; }
    public string? Output { get; private set; }
    public string? SignatureBaseDir { get; private set; }
    public string? EsetDir { get; private set; }
    public DateTimeOffset? Timestamp { get; private set; }

    /// <summary>Второй позиционный аргумент (идентификатор для <c>quarantine restore</c> / <c>rollback undo</c>).</summary>
    public string? Argument { get; private set; }
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
                case "--remediate":
                    o.Remediate = true;
                    break;
                case "--dry-run":
                    o.DryRun = true;
                    break;
                case "--overwrite":
                    o.Overwrite = true;
                    break;
                case "--report-html" when i + 1 < args.Length:
                    o.ReportHtml = args[++i];
                    break;
                case "--report-json" when i + 1 < args.Length:
                    o.ReportJson = args[++i];
                    break;
                case "--data-dir" when i + 1 < args.Length:
                    o.DataDir = args[++i];
                    break;
                case "--pipe" when i + 1 < args.Length:
                    o.Pipe = args[++i];
                    break;
                case "--out" when i + 1 < args.Length:
                    o.Output = args[++i];
                    break;
                case "--signature-base" when i + 1 < args.Length:
                    o.SignatureBaseDir = args[++i];
                    break;
                case "--eset" when i + 1 < args.Length:
                    o.EsetDir = args[++i];
                    break;
                case "--timestamp" when i + 1 < args.Length:
                    if (DateTimeOffset.TryParse(args[++i], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var ts))
                    {
                        o.Timestamp = ts;
                    }
                    else
                    {
                        o.Error = "--timestamp: ожидается дата ISO 8601.";
                    }

                    break;
                case "--allowed-exclusions" when i + 1 < args.Length:
                    o.AllowedExclusions = args[++i];
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
                    else if (o.Argument is null)
                    {
                        o.Argument = args[i];
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
