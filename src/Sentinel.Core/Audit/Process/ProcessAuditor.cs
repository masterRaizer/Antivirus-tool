using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.ThreatFamilies;
using Sentinel.Core.Trust;
using System.Runtime.InteropServices;

namespace Sentinel.Core.Audit.Process;

public sealed class ProcessAuditorOptions
{
    /// <summary>Политика штатного расположения системных процессов.</summary>
    public SystemProcessPolicy SystemPolicy { get; init; } = SystemProcessPolicy.CreateDefault();

    /// <summary>Порог «аномально высокой» загрузки CPU в процентах.</summary>
    public double HighCpuPercent { get; init; } = 90.0;

    /// <summary>Порог «аномально высокой» загрузки GPU в процентах.</summary>
    public double HighGpuPercent { get; init; } = 90.0;

    /// <summary>Анализировать исполняемый файл процесса через <see cref="FileAnalyzer"/>, если он задан.</summary>
    public bool AnalyzeExecutable { get; init; } = true;

    /// <summary>
    /// Потоковый аудит памяти процесса (RWX-регионы, PE-образы без файла, сигнатуры в памяти); <c>null</c> — память не читается.
    /// Защищённые процессы сканер отсекает сам через <c>CriticalProcessGuard</c> до открытия дескриптора.
    /// </summary>
    public Auditors.Memory.MemoryIntegrityScanner? MemoryScanner { get; init; }

    /// <summary>Таблица TCP-соединений (известные узлы семейств, порты пулов, прослушивание); <c>null</c> — сеть не проверяется.</summary>
    public INetworkConnectionProvider? NetworkConnections { get; init; }

    /// <summary>Время создания файла (UTC) — для связки «загрузчик создал и запустил майнер». <c>null</c> — время неизвестно.</summary>
    public Func<string, DateTime?> FileCreationTimeUtc { get; init; } = DefaultCreationTime;

    private static DateTime? DefaultCreationTime(string path)
    {
        try
        {
            return File.Exists(path) ? File.GetCreationTimeUtc(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }
}

/// <summary>
/// Аудитор активных процессов. Сам по себе платформонезависим: принимает снимки процессов
/// (<see cref="ProcessSnapshot"/>) от любого поставщика и применяет к ним эвристики и
/// (опционально) анализ исполняемого файла. Благодаря этому тестируется в Linux на моках.
/// </summary>
public sealed class ProcessAuditor
{
    private readonly ProcessAuditorOptions _options;
    private readonly FileAnalyzer? _fileAnalyzer;

    public ProcessAuditor(ProcessAuditorOptions? options = null, FileAnalyzer? fileAnalyzer = null)
    {
        _options = options ?? new ProcessAuditorOptions();
        _fileAnalyzer = fileAnalyzer;
    }

    public ProcessAuditReport Audit(IEnumerable<ProcessSnapshot> processes) => Audit(processes, []);

    /// <summary>
    /// Аудит с учётом исключений встроенной защиты Windows. Процессы, попавшие под
    /// <c>ExclusionProcess</c> или запущенные из <c>ExclusionPath</c>, проверяются первыми,
    /// получают находку <c>PROC-DEFENDER-EXCLUDED</c>, а их образ — глубокую проверку файла.
    /// </summary>
    public ProcessAuditReport Audit(IEnumerable<ProcessSnapshot> processes, IReadOnlyList<DefenderExclusion> exclusions)
    {
        ArgumentNullException.ThrowIfNull(processes);
        ArgumentNullException.ThrowIfNull(exclusions);

        var all = processes as IReadOnlyList<ProcessSnapshot> ?? processes.ToList();
        var context = new AuditContext(all, ReadConnections());
        var prioritized = new List<ProcessAuditEntry>();
        var regular = new List<ProcessSnapshot>();
        foreach (var p in all)
        {
            var matched = MatchExclusions(p, exclusions);
            if (matched.Count > 0)
            {
                prioritized.Add(AuditOne(p, matched, context));
            }
            else
            {
                regular.Add(p);
            }
        }

        var entries = new List<ProcessAuditEntry>(prioritized);
        foreach (var p in regular)
        {
            entries.Add(AuditOne(p, [], context));
        }

        return new ProcessAuditReport(entries);
    }

    /// <summary>
    /// Проверка одного процесса с контекстом всего снимка (родитель для связки «загрузчик → майнер» и прослушивания от explorer)
    /// и заранее прочитанной таблицей TCP — для покадровой проверки в сканировании с прогрессом.
    /// </summary>
    public ProcessAuditEntry AuditInContext(ProcessSnapshot process, IReadOnlyList<ProcessSnapshot> snapshot, IReadOnlyList<NetworkConnection> connections)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(connections);
        return AuditOne(process, [], new AuditContext(snapshot, connections));
    }

    /// <summary>Таблица TCP из <see cref="ProcessAuditorOptions.NetworkConnections"/> (пусто — источник не задан или недоступен).</summary>
    public IReadOnlyList<NetworkConnection> ReadNetworkConnections() => ReadConnections();

    /// <summary>Исключения, под которые попадает процесс (по образу или по каталогу запуска).</summary>
    public static IReadOnlyList<DefenderExclusion> MatchExclusions(ProcessSnapshot process, IReadOnlyList<DefenderExclusion> exclusions)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(exclusions);
        var matched = new List<DefenderExclusion>();
        foreach (var e in exclusions)
        {
            var hit = e.Kind switch
            {
                DefenderExclusionKind.Process => e.CoversProcess(process.Name, process.ExecutablePath),
                DefenderExclusionKind.Path => e.CoversFile(process.ExecutablePath),
                _ => false,
            };
            if (hit)
            {
                matched.Add(e);
            }
        }

        return matched;
    }

    /// <summary>Снимок всех процессов (поиск родителя) и соединения, сгруппированные по PID.</summary>
    private sealed class AuditContext(IReadOnlyList<ProcessSnapshot> processes, IReadOnlyList<NetworkConnection> connections)
    {
        private readonly Dictionary<int, ProcessSnapshot> _byPid = processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        private readonly ILookup<int, NetworkConnection> _connections = connections.ToLookup(c => c.Pid);

        public ProcessSnapshot? Parent(ProcessSnapshot child)
        {
            if (child.ParentPid <= 0 || !_byPid.TryGetValue(child.ParentPid, out var parent) || parent.Pid == child.Pid)
            {
                return null;
            }

            // Повторно выданный PID: «родитель» запущен позже потомка — это другой процесс.
            return parent.StartTimeUtc is { } ps && child.StartTimeUtc is { } cs && ps > cs ? null : parent;
        }

        public IEnumerable<NetworkConnection> ConnectionsOf(int pid) => _connections[pid];
    }

    private IReadOnlyList<NetworkConnection> ReadConnections()
    {
        if (_options.NetworkConnections is null)
        {
            return [];
        }

        try
        {
            return _options.NetworkConnections.GetConnections();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or ExternalException)
        {
            return [];
        }
    }

    private ProcessAuditEntry AuditOne(ProcessSnapshot p, IReadOnlyList<DefenderExclusion> matched, AuditContext context)
    {
        var findings = new List<AuditFinding>();
        var priority = matched.Count > 0
            ? new PriorityScanContext(string.Join("; ", matched.Select(m => m.ToString())))
            : null;

        if (priority is not null)
        {
            var interpreter = InterpreterHeuristics.IsInterpreter(p.Name);
            var userWritable = p.ExecutablePath is not null && PathClassifier.IsUserWritableLocation(p.ExecutablePath);
            findings.Add(AuditFinding.Create("PROC-DEFENDER-EXCLUDED",
                interpreter || userWritable ? Severity.High : Severity.Medium,
                "Процесс скрыт от встроенной защиты исключением",
                $"Процесс '{p.Name}' подпадает под исключение встроенной защиты Windows ({priority.Reason})"
                    + (interpreter ? " и является интерпретатором — его действия и открываемые файлы не проверяются." : ".")
                    + " Образ процесса проверен в приоритетном глубоком режиме.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", p.Name),
                Evidence.Of("path", p.ExecutablePath),
                Evidence.Of("exclusions", priority.Reason)));
        }

        CheckSystemImpersonation(p, findings);
        CheckHomoglyphs(p, findings);

        if (InterpreterHeuristics.IsInterpreter(p.Name))
        {
            findings.AddRange(InterpreterHeuristics.Analyze(p.Name, p.CommandLine));
        }

        CheckResourceUsage(p, findings);
        if (MinerCommandLineAnalyzer.Analyze(p.CommandLine, p.Pid, p.Name) is { } miner)
        {
            findings.Add(miner);
        }

        FileScanResult? scan = null;
        if (_options.AnalyzeExecutable && _fileAnalyzer is not null && !string.IsNullOrWhiteSpace(p.ExecutablePath))
        {
            scan = AnalyzeFileSafely(p.ExecutablePath, priority);
            if (scan is not null)
            {
                AppendFileFindings(p, scan, findings);
            }
        }

        CheckDeceptiveName(p, scan, findings);
        CheckFamilyIndicators(p, scan, findings);
        CheckNetwork(p, scan, context, findings);
        CheckDropperChild(p, context, findings);

        Auditors.Memory.MemoryScanResult? memory = null;
        if (_options.MemoryScanner is { } memoryScanner && p.Pid > 0)
        {
            memory = memoryScanner.Scan(p.Pid, p.Name, p.ExecutablePath);
            findings.AddRange(memory.ToFindings(p.Name, p.ExecutablePath));
        }

        return new ProcessAuditEntry(p, findings, scan) { MatchedExclusions = matched, MemoryScan = memory };
    }

    private void CheckSystemImpersonation(ProcessSnapshot p, List<AuditFinding> findings)
    {
        var inAllowed = _options.SystemPolicy.IsInAllowedLocation(p.Name, p.ExecutablePath);
        if (inAllowed == false)
        {
            var allowed = string.Join(", ", _options.SystemPolicy.AllowedDirectories(p.Name));
            findings.Add(AuditFinding.Create("PROC-IMPERSONATION", Severity.High,
                "Системное имя вне штатного каталога",
                $"Процесс с именем системного компонента '{p.Name}' запущен вне допустимых каталогов — признак маскировки.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("path", p.ExecutablePath),
                Evidence.Of("allowed", allowed)));
        }
    }

    private static void CheckHomoglyphs(ProcessSnapshot p, List<AuditFinding> findings)
    {
        var name = p.Name;
        if (string.IsNullOrEmpty(name))
        {
            return;
        }

        var fold = ConfusableFolder.Fold(name);

        // Скелет совпал с известным системным именем, но само имя отличается — явная подмена символов.
        if (fold.Changed && KnownSkeletons.Contains(fold.Skeleton) && !KnownSkeletons.Contains(fold.Lowered))
        {
            findings.Add(AuditFinding.Create("PROC-HOMOGLYPH", Severity.Critical,
                "Подмена символов в имени процесса",
                $"Имя процесса '{name}' визуально имитирует системный процесс '{fold.Skeleton}' за счёт обманчивых символов.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", name),
                Evidence.Of("skeleton", fold.Skeleton),
                Evidence.Of("path", p.ExecutablePath)));
            return;
        }

        if (ConfusableFolder.ContainsNonLatinLetters(name))
        {
            findings.Add(AuditFinding.Create("PROC-NONLATIN", Severity.Medium,
                "Не-латинские символы в имени процесса",
                $"Имя процесса '{name}' содержит не-латинские буквы — нетипично для исполняемых файлов Windows.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", name),
                Evidence.Of("path", p.ExecutablePath)));
        }
    }

    // ---- Семейства майнеров/загрузчиков (CAAService, techias) ------------------

    /// <summary>Имя «под Windows» с подменой символов или неподписанный файл, называющий себя компонентом Microsoft.</summary>
    private static void CheckDeceptiveName(ProcessSnapshot p, FileScanResult? scan, List<AuditFinding> findings)
    {
        if (findings.Any(f => f.Id == "PROC-HOMOGLYPH"))
        {
            return;
        }

        var fileName = p.ExecutablePath is { Length: > 0 } path ? Path.GetFileName(path.Replace('\\', '/')) : p.Name;
        var userWritable = p.ExecutablePath is not null && PathClassifier.IsUserWritableLocation(p.ExecutablePath);
        if (DeceptiveNameAnalyzer.Analyze(fileName) is { } deceptive && !DeceptiveNameAnalyzer.IsMicrosoftSigned(scan?.Signature))
        {
            findings.Add(AuditFinding.Create("PROC-DECEPTIVE-NAME", userWritable ? Severity.High : Severity.Medium,
                "Обманчивое имя исполняемого файла",
                $"Имя '{fileName}': {deceptive.Describe()}. Так маскируют вредоносные файлы под компоненты Windows.",
                Evidence.Of("pid", p.Pid), Evidence.Of("name", fileName), Evidence.Of("imitates", deceptive.Imitates),
                Evidence.Of("path", p.ExecutablePath)));
        }

        if (scan is { Pe.IsPe: true, Signature: { Status: not SignatureStatus.Unsupported } sig }
            && DeceptiveNameAnalyzer.ClaimsMicrosoftName(fileName) && !DeceptiveNameAnalyzer.IsMicrosoftSigned(sig))
        {
            findings.Add(AuditFinding.Create("PROC-FAKE-MICROSOFT", userWritable ? Severity.High : Severity.Medium,
                "Файл называет себя компонентом Microsoft без подписи Microsoft",
                $"'{fileName}' назван как компонент Microsoft/Windows, но подписи Microsoft нет (статус {sig.Status}, подписант: {sig.SignerSubject ?? "нет"}).",
                Evidence.Of("pid", p.Pid), Evidence.Of("path", p.ExecutablePath), Evidence.Of("signature", sig.Status.ToString())));
        }
    }

    private static void CheckFamilyIndicators(ProcessSnapshot p, FileScanResult? scan, List<AuditFinding> findings)
    {
        var match = ThreatFamilyCatalog.MatchHash(scan?.Sha256);
        if (match is not null)
        {
            findings.Add(AuditFinding.Create("PROC-FAMILY-IOC", Severity.Critical,
                $"Известный файл семейства: {match.Family.Name}",
                $"SHA-256 исполняемого файла процесса совпадает с IOC семейства «{match.Family.Name}» ({match.Role}).",
                Evidence.Of("pid", p.Pid), Evidence.Of("path", p.ExecutablePath), Evidence.Of("sha256", match.Indicator),
                Evidence.Of("family", match.Family.Id)));
        }
    }

    private static void CheckNetwork(ProcessSnapshot p, FileScanResult? scan, AuditContext context, List<AuditFinding> findings)
    {
        var userWritable = p.ExecutablePath is not null && PathClassifier.IsUserWritableLocation(p.ExecutablePath);
        var reported = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in context.ConnectionsOf(p.Pid))
        {
            if (c.State == TcpConnectionState.Listen)
            {
                CheckListener(p, scan, context, c, findings, reported);
                continue;
            }

            if (ThreatFamilyCatalog.MatchIp(c.RemoteAddress) is { } ioc && reported.Add("ioc|" + ioc.Indicator))
            {
                findings.Add(AuditFinding.Create("PROC-NET-IOC", Severity.Critical,
                    "Соединение с узлом известного семейства",
                    $"Процесс '{p.Name}' соединён с {c.RemoteAddress}:{c.RemotePort} — узел семейства «{ioc.Family.Name}».",
                    Evidence.Of("pid", p.Pid), Evidence.Of("remote", $"{c.RemoteAddress}:{c.RemotePort}"),
                    Evidence.Of("family", ioc.Family.Id), Evidence.Of("path", p.ExecutablePath)));
            }
            else if (c.State == TcpConnectionState.Established && ThreatFamilyCatalog.PoolPorts.Contains(c.RemotePort)
                && !IsLoopback(c.RemoteAddress) && reported.Add("pool|" + c.RemotePort))
            {
                findings.Add(AuditFinding.Create("PROC-NET-POOLPORT", userWritable ? Severity.High : Severity.Medium,
                    "Соединение на порт майнинг-пула",
                    $"Процесс '{p.Name}' соединён с {c.RemoteAddress}:{c.RemotePort} — типичный порт stratum-пула.",
                    Evidence.Of("pid", p.Pid), Evidence.Of("remote", $"{c.RemoteAddress}:{c.RemotePort}"),
                    Evidence.Of("path", p.ExecutablePath)));
            }
        }
    }

    /// <summary>
    /// Неподписанный процесс из ProgramData, запущенный проводником (Run-автозапуск), слушает внешний порт — признак бэкдора
    /// загрузчика (CAAService слушает TCP 24424). Прослушивание только на loopback не учитывается.
    /// </summary>
    private static void CheckListener(ProcessSnapshot p, FileScanResult? scan, AuditContext context, NetworkConnection c,
        List<AuditFinding> findings, HashSet<string> reported)
    {
        if (IsLoopback(c.LocalAddress) || p.ExecutablePath is null)
        {
            return;
        }

        var knownBackdoor = ThreatFamilyCatalog.All.FirstOrDefault(f => f.BackdoorPort == c.LocalPort);
        var inProgramData = PathClassifier.Normalize(p.ExecutablePath).Contains("\\programdata\\", StringComparison.Ordinal);
        var unsigned = scan?.Signature is { Status: not SignatureStatus.Unsupported and not SignatureStatus.Valid };
        var fromExplorer = string.Equals(context.Parent(p)?.Name, "explorer.exe", StringComparison.OrdinalIgnoreCase);
        if (!(inProgramData && (unsigned || knownBackdoor is not null) && (fromExplorer || knownBackdoor is not null)))
        {
            return;
        }

        if (!reported.Add("listen|" + c.LocalPort))
        {
            return;
        }

        findings.Add(AuditFinding.Create("PROC-BACKDOOR-LISTEN", knownBackdoor is not null ? Severity.Critical : Severity.High,
            "Неподписанный процесс из ProgramData слушает порт",
            $"'{p.Name}' из {p.ExecutablePath} (родитель: {context.Parent(p)?.Name ?? "неизвестен"}) принимает входящие соединения на TCP {c.LocalPort}"
                + (knownBackdoor is null ? "." : $" — порт бэкдора семейства «{knownBackdoor.Name}»."),
            Evidence.Of("pid", p.Pid), Evidence.Of("port", c.LocalPort), Evidence.Of("path", p.ExecutablePath),
            Evidence.Of("parent", context.Parent(p)?.Name), Evidence.Of("signature", scan?.Signature?.Status.ToString())));
    }

    /// <summary>
    /// Связка «загрузчик → майнер»: процесс из каталога с правом записи запущен родителем из того же каталога ProgramData,
    /// и его exe создан уже после старта родителя (родитель распаковал и запустил файл).
    /// </summary>
    private void CheckDropperChild(ProcessSnapshot p, AuditContext context, List<AuditFinding> findings)
    {
        var parent = context.Parent(p);
        if (parent?.ExecutablePath is not { } parentPath || p.ExecutablePath is not { } childPath
            || !PathClassifier.IsUserWritableLocation(childPath) || !PathClassifier.IsUserWritableLocation(parentPath))
        {
            return;
        }

        var parentRoot = ProgramDataRoot(parentPath);
        if (parentRoot is null || !string.Equals(parentRoot, ProgramDataRoot(childPath), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var created = _options.FileCreationTimeUtc(childPath);
        if (created is null || parent.StartTimeUtc is null || created < parent.StartTimeUtc)
        {
            return;
        }

        var miner = findings.Any(f => f.Id is MinerCommandLineAnalyzer.FindingId or "PROC-NET-POOLPORT" or "PROC-NET-IOC");
        findings.Add(AuditFinding.Create("PROC-DROPPER-CHILD", miner ? Severity.High : Severity.Medium,
            "Процесс запущен из файла, только что созданного родителем",
            $"'{p.Name}' запущен процессом '{parent.Name}' (PID {parent.Pid}) из того же каталога {parentRoot}, а файл создан после старта родителя"
                + " — загрузчик пересоздаёт и запускает нагрузку. При нейтрализации родитель-загрузчик останавливается первым.",
            Evidence.Of("pid", p.Pid), Evidence.Of("parentPid", parent.Pid), Evidence.Of("parentPath", parentPath),
            Evidence.Of("path", childPath), Evidence.Of("created", created.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture))));
    }

    /// <summary><c>C:\ProgramData\CAAService</c> для любого файла внутри этого каталога (в исходном написании); <c>null</c> — путь не в ProgramData.</summary>
    internal static string? ProgramDataRoot(string path)
    {
        // Индексы ищутся в нормализованной строке той же длины, а срез берётся из исходной — регистр и разделители сохраняются.
        var norm = PathClassifier.Normalize(path);
        const string marker = "\\programdata\\";
        var idx = norm.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0 || norm.Length != path.Length)
        {
            return null;
        }

        var start = idx + marker.Length;
        var end = norm.IndexOf('\\', start);
        return end < 0 ? null : path[..end];
    }

    private static bool IsLoopback(string address) =>
        address.StartsWith("127.", StringComparison.Ordinal) || address is "::1" || address.StartsWith("::ffff:127.", StringComparison.OrdinalIgnoreCase);

    private void CheckResourceUsage(ProcessSnapshot p, List<AuditFinding> findings)
    {
        if (p.CpuKnown && p.CpuPercent >= _options.HighCpuPercent)
        {
            findings.Add(AuditFinding.Create("PROC-HIGH-CPU", Severity.Low,
                "Аномально высокая загрузка CPU",
                $"Процесс потребляет {p.CpuPercent:F1}% CPU (порог {_options.HighCpuPercent:F0}%) — возможен майнер или зависший цикл.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", p.Name),
                Evidence.Of("cpu", $"{p.CpuPercent:F1}%")));
        }

        if (p.GpuKnown && p.GpuPercent >= _options.HighGpuPercent)
        {
            findings.Add(AuditFinding.Create("PROC-HIGH-GPU", Severity.Low,
                "Аномально высокая загрузка GPU",
                $"Процесс потребляет {p.GpuPercent:F1}% GPU (порог {_options.HighGpuPercent:F0}%) — характерно для GPU-майнеров.",
                Evidence.Of("pid", p.Pid),
                Evidence.Of("name", p.Name),
                Evidence.Of("gpu", $"{p.GpuPercent:F1}%")));
        }
    }

    private static void AppendFileFindings(ProcessSnapshot p, FileScanResult scan, List<AuditFinding> findings)
    {
        if (scan.Verdict is Verdict.Trusted or Verdict.Clean)
        {
            return;
        }

        foreach (var d in scan.Detections)
        {
            findings.Add(AuditFinding.Create("PROC-FILE-" + (d.RuleId ?? d.Source.ToString().ToUpperInvariant()),
                d.Severity,
                $"Детект в исполняемом файле процесса: {d.Name}",
                d.Description,
                Evidence.Of("pid", p.Pid),
                Evidence.Of("path", scan.Path),
                Evidence.Of("source", d.Source.ToString()),
                Evidence.Of("verdict", scan.Verdict.ToString())));
        }
    }

    private FileScanResult? AnalyzeFileSafely(string path, PriorityScanContext? priority)
    {
        try
        {
            return _fileAnalyzer!.Analyze(path, priority);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Скелеты известных системных имён для сопоставления при подмене символов.</summary>
    private static readonly HashSet<string> KnownSkeletons = BuildKnownSkeletons();

    private static HashSet<string> BuildKnownSkeletons()
    {
        string[] names =
        [
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
            "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "taskhostw.exe",
            "spoolsv.exe", "conhost.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
            "runtimebroker.exe", "searchindexer.exe", "dllhost.exe", "explorer.exe",
        ];
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var n in names)
        {
            set.Add(ConfusableFolder.Fold(n).Skeleton);
        }

        return set;
    }
}
