using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Persistence.Tasks;
using Sentinel.Core.Audit.Persistence.Wmi;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Audit.Persistence;

/// <summary>
/// Аудитор точек автозапуска и персистентности. Собирает записи из реестра (Run/RunOnce,
/// Winlogon, IFEO, службы), планировщика задач, подписок WMI, папок автозагрузки и файла hosts,
/// применяет эвристики и (опционально) анализирует целевые файлы через <see cref="FileAnalyzer"/>.
/// Все источники инъектируются, поэтому логика полностью покрывается unit-тестами на Linux.
/// </summary>
public sealed class PersistenceAuditor
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string RunKeyWow = @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKeyWow = @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string WinlogonKey = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string IfeoKey = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    private readonly PersistenceAuditorOptions _options;
    private readonly IRegistryProvider? _registry;
    private readonly ITaskSchedulerProvider? _tasks;
    private readonly IWmiSubscriptionProvider? _wmi;
    private readonly FileAnalyzer? _analyzer;

    public PersistenceAuditor(
        PersistenceAuditorOptions? options = null,
        IRegistryProvider? registry = null,
        ITaskSchedulerProvider? tasks = null,
        IWmiSubscriptionProvider? wmi = null,
        FileAnalyzer? analyzer = null)
    {
        _options = options ?? new PersistenceAuditorOptions();
        _registry = registry;
        _tasks = tasks;
        _wmi = wmi;
        _analyzer = analyzer;
    }

    public PersistenceAuditReport Audit()
    {
        var entries = new List<PersistenceEntry>();

        if (_registry is not null)
        {
            AuditRunKeys(entries);
            AuditWinlogon(entries);
            AuditIfeo(entries);
            AuditServices(entries);
        }

        if (_tasks is not null)
        {
            AuditScheduledTasks(entries);
        }

        if (_wmi is not null)
        {
            AuditWmi(entries);
        }

        AuditStartupFolders(entries);
        AuditHostsFile(entries);

        return new PersistenceAuditReport(entries);
    }

    // ---- Реестр: Run / RunOnce -------------------------------------------------

    private void AuditRunKeys(List<PersistenceEntry> entries)
    {
        (RegistryKeyPath Key, PersistenceKind Kind)[] locations =
        [
            (new(RegistryHive.CurrentUser, RunKey), PersistenceKind.RegistryRun),
            (new(RegistryHive.CurrentUser, RunOnceKey), PersistenceKind.RegistryRunOnce),
            (new(RegistryHive.LocalMachine, RunKey), PersistenceKind.RegistryRun),
            (new(RegistryHive.LocalMachine, RunOnceKey), PersistenceKind.RegistryRunOnce),
            (new(RegistryHive.LocalMachine, RunKeyWow), PersistenceKind.RegistryRun),
            (new(RegistryHive.LocalMachine, RunOnceKeyWow), PersistenceKind.RegistryRunOnce),
        ];

        foreach (var (key, kind) in locations)
        {
            foreach (var value in _registry!.GetValues(key))
            {
                var findings = new List<AuditFinding>();
                var scan = AnalyzeTargetFile(value.Value, findings, key.ToString());
                entries.Add(new PersistenceEntry
                {
                    Kind = kind,
                    Location = key.ToString(),
                    Name = value.Name,
                    Command = value.Value,
                    ResolvedTarget = ResolveTarget(value.Value),
                    Findings = findings,
                    FileScan = scan,
                });
            }
        }
    }

    // ---- Реестр: Winlogon Shell / Userinit -------------------------------------

    private void AuditWinlogon(List<PersistenceEntry> entries)
    {
        (RegistryHive Hive, string Scope)[] hives =
        [
            (RegistryHive.LocalMachine, "HKLM"),
            (RegistryHive.CurrentUser, "HKCU"),
        ];

        foreach (var (hive, _) in hives)
        {
            var key = new RegistryKeyPath(hive, WinlogonKey);
            var shell = _registry!.GetValue(key, "Shell");
            if (shell?.Value is { Length: > 0 } shellValue)
            {
                var findings = new List<AuditFinding>();
                if (!ShellMatchesDefault(shellValue))
                {
                    findings.Add(AuditFinding.Create("PERS-WINLOGON-SHELL", Severity.High,
                        "Подмена оболочки Winlogon",
                        $"Winlogon\\Shell = '{shellValue}' отличается от штатного '{_options.DefaultShell}' — автозапуск при входе в систему.",
                        Evidence.Of("key", key.ToString()), Evidence.Of("value", shellValue)));
                }

                AnalyzeTargetInto(shellValue, findings, key.ToString());
                entries.Add(new PersistenceEntry
                {
                    Kind = PersistenceKind.WinlogonShell,
                    Location = key.ToString(),
                    Name = "Shell",
                    Command = shellValue,
                    ResolvedTarget = ResolveTarget(shellValue),
                    Findings = findings,
                });
            }

            var userinit = _registry.GetValue(key, "Userinit");
            if (userinit?.Value is { Length: > 0 } userinitValue)
            {
                var findings = new List<AuditFinding>();
                if (!UserinitLooksDefault(userinitValue))
                {
                    findings.Add(AuditFinding.Create("PERS-WINLOGON-USERINIT", Severity.High,
                        "Подмена Userinit",
                        $"Winlogon\\Userinit = '{userinitValue}' содержит нестандартные записи — распространённый механизм персистентности.",
                        Evidence.Of("key", key.ToString()), Evidence.Of("value", userinitValue)));
                }

                entries.Add(new PersistenceEntry
                {
                    Kind = PersistenceKind.WinlogonUserinit,
                    Location = key.ToString(),
                    Name = "Userinit",
                    Command = userinitValue,
                    Findings = findings,
                });
            }
        }
    }

    // ---- Реестр: IFEO Debugger -------------------------------------------------

    private void AuditIfeo(List<PersistenceEntry> entries)
    {
        (RegistryHive Hive, RegistryView View)[] variants =
        [
            (RegistryHive.LocalMachine, RegistryView.Default),
            (RegistryHive.LocalMachine, RegistryView.Registry32),
        ];

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, view) in variants)
        {
            var root = new RegistryKeyPath(hive, IfeoKey, view);
            foreach (var image in _registry!.GetSubKeyNames(root))
            {
                var sub = new RegistryKeyPath(hive, IfeoKey + "\\" + image, view);
                var debugger = _registry.GetValue(sub, "Debugger");
                if (debugger?.Value is not { Length: > 0 } debuggerValue)
                {
                    continue;
                }

                if (!seen.Add(image + "|" + debuggerValue))
                {
                    continue;
                }

                var findings = new List<AuditFinding>
                {
                    AuditFinding.Create("PERS-IFEO-DEBUGGER", Severity.High,
                        "Перехватчик IFEO (Debugger)",
                        $"Для '{image}' задан отладчик '{debuggerValue}': при каждом запуске этого образа будет выполняться указанная команда.",
                        Evidence.Of("image", image), Evidence.Of("debugger", debuggerValue)),
                };
                AnalyzeTargetInto(debuggerValue, findings, sub.ToString());

                entries.Add(new PersistenceEntry
                {
                    Kind = PersistenceKind.ImageFileExecutionOptions,
                    Location = sub.ToString(),
                    Name = image,
                    Command = debuggerValue,
                    ResolvedTarget = ResolveTarget(debuggerValue),
                    Findings = findings,
                });
            }
        }
    }

    // ---- Реестр: службы --------------------------------------------------------

    private void AuditServices(List<PersistenceEntry> entries)
    {
        var root = new RegistryKeyPath(RegistryHive.LocalMachine, ServicesKey);
        foreach (var name in _registry!.GetSubKeyNames(root))
        {
            var key = new RegistryKeyPath(RegistryHive.LocalMachine, ServicesKey + "\\" + name);
            var imagePath = _registry.GetValue(key, "ImagePath")?.Value;
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                continue;
            }

            var startValue = _registry.GetValue(key, "Start")?.Value;
            var autoStart = string.Equals(startValue, "2", StringComparison.Ordinal);
            var resolved = ResolveServiceImagePath(imagePath);

            var findings = new List<AuditFinding>();
            var scan = AnalyzeResolvedTarget(resolved, findings, key.ToString());

            if (resolved is not null && !PathClassifier.IsInTrustedDirectory(resolved, _options.TrustedBinaryDirectories)
                && PathClassifier.IsUserWritableLocation(resolved))
            {
                findings.Add(AuditFinding.Create("PERS-SERVICE-USERWRITABLE",
                    autoStart ? Severity.High : Severity.Medium,
                    "Служба из пользовательского каталога",
                    $"Бинарник службы '{name}' расположен в каталоге с правом записи пользователя: {resolved}.",
                    Evidence.Of("service", name), Evidence.Of("image", imagePath),
                    Evidence.Of("start", autoStart ? "auto" : startValue)));
            }

            if (findings.Count == 0)
            {
                // Штатные службы не засоряют отчёт — включаем только помеченные.
                continue;
            }

            entries.Add(new PersistenceEntry
            {
                Kind = PersistenceKind.Service,
                Location = key.ToString(),
                Name = name,
                Command = imagePath,
                ResolvedTarget = resolved,
                Findings = findings,
                FileScan = scan,
            });
        }
    }

    // ---- Планировщик задач -----------------------------------------------------

    private void AuditScheduledTasks(List<PersistenceEntry> entries)
    {
        foreach (var task in _tasks!.GetTasks())
        {
            foreach (var action in task.ExecActions)
            {
                var command = BuildCommand(action.Command, action.Arguments);
                var findings = new List<AuditFinding>();
                var resolved = ResolveServiceImagePath(action.Command) ?? ResolveTarget(action.Command);
                var scan = AnalyzeResolvedTarget(resolved, findings, task.Path);

                if (resolved is not null && !PathClassifier.IsInTrustedDirectory(resolved, _options.TrustedBinaryDirectories)
                    && PathClassifier.IsUserWritableLocation(resolved))
                {
                    findings.Add(AuditFinding.Create("PERS-TASK-USERWRITABLE", Severity.Medium,
                        "Задача запускает файл из пользовательского каталога",
                        $"Задача '{task.Name}' выполняет {resolved} из каталога с правом записи пользователя.",
                        Evidence.Of("task", task.Name), Evidence.Of("command", command)));
                }

                if (action.Arguments is { } args && IsSuspiciousArguments(action.Command, args))
                {
                    findings.AddRange(InterpreterHeuristics.Analyze(FileName(action.Command), command));
                }

                if (findings.Count == 0)
                {
                    continue;
                }

                entries.Add(new PersistenceEntry
                {
                    Kind = PersistenceKind.ScheduledTask,
                    Location = task.Path,
                    Name = task.Name + (task.Enabled ? string.Empty : " (отключена)"),
                    Command = command,
                    ResolvedTarget = resolved,
                    Findings = findings,
                    FileScan = scan,
                });
            }
        }
    }

    // ---- Подписки WMI ----------------------------------------------------------

    private void AuditWmi(List<PersistenceEntry> entries)
    {
        var snapshot = _wmi!.GetSubscriptions();
        foreach (var consumer in snapshot.Consumers)
        {
            var command = consumer.CommandLineTemplate ?? consumer.ExecutablePath;
            var findings = new List<AuditFinding>
            {
                AuditFinding.Create("PERS-WMI-CONSUMER", Severity.Medium,
                    "Постоянная подписка WMI",
                    $"Обнаружен потребитель событий WMI '{consumer.Name}' ({consumer.ConsumerType}) — редкий и часто вредоносный механизм персистентности.",
                    Evidence.Of("name", consumer.Name),
                    Evidence.Of("type", consumer.ConsumerType),
                    Evidence.Of("command", command),
                    Evidence.Of("script", consumer.ScriptText)),
            };

            if (!string.IsNullOrWhiteSpace(command))
            {
                findings.AddRange(InterpreterHeuristics.Analyze(FileName(ResolveTarget(command) ?? command), command));
                AnalyzeTargetInto(command, findings, "WMI:" + consumer.Name);
            }

            if (!string.IsNullOrWhiteSpace(consumer.ScriptText) &&
                (consumer.ScriptText.Contains("frombase64", StringComparison.OrdinalIgnoreCase) ||
                 consumer.ScriptText.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                 consumer.ScriptText.Contains("https://", StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(AuditFinding.Create("PERS-WMI-SCRIPT", Severity.High,
                    "Сетевой/закодированный скрипт в потребителе WMI",
                    "Тело скрипта потребителя событий WMI содержит сетевой адрес или base64 — признак доставки нагрузки.",
                    Evidence.Of("name", consumer.Name)));
            }

            entries.Add(new PersistenceEntry
            {
                Kind = PersistenceKind.WmiSubscription,
                Location = "root/subscription",
                Name = consumer.Name,
                Command = command,
                ResolvedTarget = ResolveTarget(command),
                Findings = findings,
            });
        }
    }

    // ---- Папки автозагрузки ----------------------------------------------------

    private void AuditStartupFolders(List<PersistenceEntry> entries)
    {
        foreach (var dir in _options.StartupDirectories)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            {
                continue;
            }

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                var fileName = Path.GetFileName(file);
                if (string.Equals(fileName, "desktop.ini", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var findings = new List<AuditFinding>();
                var (target, command) = ResolveStartupTarget(file);
                FileScanResult? scan;

                if (target is not null)
                {
                    scan = AnalyzeResolvedTarget(target, findings, file);
                    if (!PathClassifier.IsInTrustedDirectory(target, _options.TrustedBinaryDirectories)
                        && PathClassifier.IsUserWritableLocation(target))
                    {
                        findings.Add(AuditFinding.Create("PERS-STARTUP-USERWRITABLE", Severity.Medium,
                            "Автозагрузка указывает в пользовательский каталог",
                            $"Элемент автозагрузки '{fileName}' указывает на {target} в каталоге с правом записи пользователя.",
                            Evidence.Of("startup", file), Evidence.Of("target", target)));
                    }
                }
                else
                {
                    scan = AnalyzeResolvedTarget(file, findings, file);
                }

                entries.Add(new PersistenceEntry
                {
                    Kind = PersistenceKind.StartupFolder,
                    Location = dir,
                    Name = fileName,
                    Command = command ?? file,
                    ResolvedTarget = target,
                    Findings = findings,
                    FileScan = scan,
                });
            }
        }
    }

    // ---- hosts -----------------------------------------------------------------

    private void AuditHostsFile(List<PersistenceEntry> entries)
    {
        if (string.IsNullOrWhiteSpace(_options.HostsFilePath) || !File.Exists(_options.HostsFilePath))
        {
            return;
        }

        string content;
        try
        {
            content = File.ReadAllText(_options.HostsFilePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        foreach (var entry in HostsFileParser.Parse(content))
        {
            var findings = new List<AuditFinding>();
            var sensitive = _options.SecuritySensitiveHosts.Any(h =>
                entry.Host.Contains(h, StringComparison.OrdinalIgnoreCase));

            if (entry.IsLoopback && HostsTelemetryList.IsTelemetryHost(entry.Host))
            {
                // Блокировка телеметрии — выбор пользователя: только информация, никаких автоматических действий.
                findings.Add(AuditFinding.Create("PERS-HOSTS-TELEMETRY", Severity.Info,
                    "Блокировка телеметрии Microsoft в hosts",
                    $"Домен телеметрии '{entry.Host}' заблокирован ({entry.Address}). Это настройка приватности, запись не изменяется.",
                    Evidence.Of("host", entry.Host), Evidence.Of("address", entry.Address),
                    Evidence.Of("line", entry.LineNumber)));
            }
            else if (sensitive && entry.IsLoopback)
            {
                findings.Add(AuditFinding.Create("PERS-HOSTS-SECURITY", Severity.Medium,
                    "Блокировка домена обновлений или защиты в hosts",
                    $"Домен '{entry.Host}' (обновления/защита) заблокирован через {entry.Address} — возможная блокировка обновлений или антивируса. Решение за пользователем.",
                    Evidence.Of("host", entry.Host), Evidence.Of("address", entry.Address),
                    Evidence.Of("line", entry.LineNumber)));
            }
            else if (!entry.IsLoopback)
            {
                findings.Add(AuditFinding.Create(sensitive ? "PERS-HOSTS-SECURITY" : "PERS-HOSTS-REDIRECT", Severity.Critical,
                    sensitive ? "Перенаправление защитного домена на внешний адрес" : "Перенаправление домена на внешний адрес",
                    $"Домен '{entry.Host}' перенаправлен на внешний адрес {entry.Address} — перехват трафика.",
                    Evidence.Of("host", entry.Host), Evidence.Of("address", entry.Address),
                    Evidence.Of("line", entry.LineNumber)));
            }

            if (findings.Count == 0)
            {
                continue;
            }

            entries.Add(new PersistenceEntry
            {
                Kind = PersistenceKind.HostsFile,
                Location = _options.HostsFilePath!,
                Name = entry.Host,
                Command = $"{entry.Address} {entry.Host}",
                Findings = findings,
            });
        }
    }

    // ---- Вспомогательные методы -----------------------------------------------

    private bool ShellMatchesDefault(string shellValue) =>
        string.Equals(shellValue.Trim(), _options.DefaultShell, StringComparison.OrdinalIgnoreCase);

    private static bool UserinitLooksDefault(string value)
    {
        // Штатно: "C:\Windows\system32\userinit.exe," (одна команда, оканчивается userinit.exe[,]).
        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
        {
            return false;
        }

        foreach (var part in parts)
        {
            var file = FileName(part);
            if (!string.Equals(file, "userinit.exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSuspiciousArguments(string command, string args)
    {
        var name = FileName(command);
        return InterpreterHeuristics.IsInterpreter(name) || InterpreterHeuristics.Analyze(name, command + " " + args).Count > 0;
    }

    private static string BuildCommand(string command, string? arguments) =>
        string.IsNullOrEmpty(arguments) ? command : $"{command} {arguments}";

    private static string FileName(string path)
    {
        var trimmed = path.Trim().Trim('"');
        var idx = trimmed.LastIndexOfAny(['\\', '/']);
        return idx < 0 ? trimmed : trimmed[(idx + 1)..];
    }

    private static string? ResolveTarget(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(command);
        return CommandLineParser.ExtractExecutable(expanded);
    }

    /// <summary>
    /// Разбирает ImagePath службы/задачи: раскрывает переменные, снимает префиксы
    /// <c>\SystemRoot\</c>, <c>\??\</c>, <c>system32\</c> и выделяет путь к исполняемому файлу.
    /// </summary>
    private string? ResolveServiceImagePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(imagePath).Trim();
        var exe = CommandLineParser.ExtractExecutable(expanded);
        if (string.IsNullOrEmpty(exe))
        {
            return null;
        }

        if (exe.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            exe = exe[4..];
        }

        if (exe.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            exe = Path.Combine(_options.WindowsDirectory, exe[@"\SystemRoot\".Length..]);
        }
        else if (exe.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
        {
            exe = Path.Combine(_options.WindowsDirectory, exe);
        }

        return exe;
    }

    private static (string? Target, string? Command) ResolveStartupTarget(string file)
    {
        if (!file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            return (file, file);
        }

        byte[] bytes;
        try
        {
            using (var lnk = Hashing.FileHasher.OpenShared(file))
            {
                // Ярлык — это единицы килобайт; читаем не больше 1 МБ, чтобы подложенный огромный файл не занял память.
                var length = (int)Math.Min(lnk.Length, 1 << 20);
                bytes = new byte[length];
                lnk.ReadExactly(bytes);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (null, file);
        }

        var link = ShellLinkParser.Parse(bytes);
        if (link?.TargetPath is { Length: > 0 } target)
        {
            var command = string.IsNullOrEmpty(link.Arguments) ? target : $"{target} {link.Arguments}";
            return (target, command);
        }

        return (null, file);
    }

    private FileScanResult? AnalyzeTargetFile(string? command, List<AuditFinding> findings, string context) =>
        AnalyzeResolvedTarget(ResolveTarget(command), findings, context);

    private void AnalyzeTargetInto(string? command, List<AuditFinding> findings, string context) =>
        AnalyzeResolvedTarget(ResolveTarget(command), findings, context);

    private FileScanResult? AnalyzeResolvedTarget(string? resolved, List<AuditFinding> findings, string context)
    {
        if (!_options.AnalyzeTargets || _analyzer is null || string.IsNullOrWhiteSpace(resolved))
        {
            return null;
        }

        string full;
        try
        {
            full = Environment.ExpandEnvironmentVariables(resolved);
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (!File.Exists(full))
        {
            return null;
        }

        FileScanResult scan;
        try
        {
            scan = _analyzer.Analyze(full, null, new ScoreContext(PersistenceBound: true));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }

        foreach (var d in scan.Detections)
        {
            findings.Add(AuditFinding.Create("PERS-FILE-" + (d.RuleId ?? d.Source.ToString().ToUpperInvariant()),
                d.Severity,
                $"Детект в целевом файле автозапуска: {d.Name}",
                d.Description,
                Evidence.Of("context", context),
                Evidence.Of("path", scan.Path),
                Evidence.Of("source", d.Source.ToString())));
        }

        if (scan is { Verdict: not Verdict.Trusted, Pe.IsPe: true, Signature: { Status: not SignatureStatus.Unsupported } sig }
            && !sig.IsValid
            && !PathClassifier.IsInTrustedDirectory(scan.Path, _options.TrustedBinaryDirectories))
        {
            var userWritable = PathClassifier.IsUserWritableLocation(scan.Path);
            findings.Add(AuditFinding.Create("PERS-FILE-UNSIGNED",
                userWritable ? Severity.Medium : Severity.Low,
                "Неподписанный исполняемый файл в автозапуске",
                $"Целевой файл '{scan.Path}' не имеет действительной цифровой подписи (статус {sig.Status}).",
                Evidence.Of("context", context),
                Evidence.Of("path", scan.Path),
                Evidence.Of("status", sig.Status.ToString())));
        }

        return scan;
    }
}
