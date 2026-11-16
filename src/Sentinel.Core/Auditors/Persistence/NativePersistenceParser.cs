using Sentinel.Core.Audit;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Auditors.Persistence;

/// <summary>Итог нативного аудита персистентности: находки и пропущенные шаги.</summary>
public sealed record NativePersistenceReport(IReadOnlyList<AuditFinding> Findings, IReadOnlyList<SkippedAuditStep> Skipped);

/// <summary>
/// Нативный (без PowerShell и WMI) анализ служб, задач планировщика и реестровой персистентности.
/// Чистая логика поверх сырых записей — полностью тестируется на Linux; источники данных инъектируются.
/// </summary>
public static class NativePersistenceParser
{
    private static readonly string[] ProfileMarkers =
        [@"\temp\", @"\appdata\", @"\users\public\", @"\downloads\", @"\programdata\"];

    private static readonly string[] SafeBootAllowList = ["sentinelservice", "sentineldrv"];

    private static readonly string[] SuspiciousComServers =
        [@"\temp\", @"\appdata\", @"\users\public\", "scrobj.dll", "mshtml.dll"];

    /// <summary>Разбирает службы, задачи и реестровые ветки в находки. Сверка задач — через <see cref="ScheduledTaskReconciler"/>.</summary>
    public static IReadOnlyList<AuditFinding> Analyze(
        IReadOnlyList<RawServiceRecord> services,
        IReadOnlyList<RawScheduledTaskRecord> tasks,
        IReadOnlyList<string> taskCacheNames,
        IReadOnlyList<RawRegistryPersistenceItem> registryItems,
        string windowsRoot)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(tasks);
        ArgumentNullException.ThrowIfNull(taskCacheNames);
        ArgumentNullException.ThrowIfNull(registryItems);
        var findings = new List<AuditFinding>();

        foreach (var service in services)
        {
            findings.AddRange(AnalyzeService(service, windowsRoot ?? @"C:\Windows"));
        }

        foreach (var task in tasks)
        {
            findings.AddRange(AnalyzeTask(task));
        }

        foreach (var reconciliation in ScheduledTaskReconciler.Reconcile(tasks, taskCacheNames))
        {
            findings.Add(FromReconciliation(reconciliation));
        }

        foreach (var item in registryItems)
        {
            findings.AddRange(AnalyzeRegistryItem(item));
        }

        return findings;
    }

    public static IEnumerable<AuditFinding> AnalyzeService(RawServiceRecord service, string windowsRoot)
    {
        ArgumentNullException.ThrowIfNull(service);
        ArgumentNullException.ThrowIfNull(windowsRoot);

        var unquoted = UnquotedServicePathDetector.Detect(service, windowsRoot);
        if (unquoted is not null)
        {
            yield return AuditFinding.Create("PERS-SVC-UNQUOTED", Severity.Medium,
                "Незакавыченный путь службы (Unquoted Service Path)",
                unquoted.Recommendation,
                Evidence.Of("service", service.Name),
                Evidence.Of("imagePath", service.ImagePath),
                Evidence.Of("hijack", string.Join("; ", unquoted.HijackPaths)),
                Evidence.Of("score", 45));
        }

        if (service.ServiceDll is { Length: > 0 } dll && InUserProfile(dll))
        {
            yield return AuditFinding.Create("PERS-SVC-SERVICEDLL", Severity.High,
                "ServiceDll службы указывает в пользовательский каталог",
                $"Служба '{service.Name}' загружает DLL '{dll}' из каталога с правом записи пользователя — подмена внутри группы svchost.exe.",
                Evidence.Of("service", service.Name), Evidence.Of("serviceDll", dll), Evidence.Of("score", 65));
        }

        if (service.FailureCommand is { Length: > 0 } failure)
        {
            yield return AuditFinding.Create("PERS-SVC-FAILURECMD", Severity.High,
                "Команда при сбое службы",
                $"Для службы '{service.Name}' задана команда восстановления при сбое: {failure}. Это нештатный механизм выполнения кода.",
                Evidence.Of("service", service.Name), Evidence.Of("failureCommand", failure), Evidence.Of("score", 55));
        }

        if (service.IsAutoStart && service.ImagePath is { Length: > 0 } image && InUserProfile(image))
        {
            yield return AuditFinding.Create("PERS-SVC-USERPATH", Severity.High,
                "Автозапускаемая служба из пользовательского каталога",
                $"Служба '{service.Name}' запускается из каталога с правом записи пользователя: {image}.",
                Evidence.Of("service", service.Name), Evidence.Of("imagePath", image), Evidence.Of("score", 60));
        }
    }

    public static IEnumerable<AuditFinding> AnalyzeTask(RawScheduledTaskRecord task)
    {
        ArgumentNullException.ThrowIfNull(task);
        foreach (var com in task.ComHandlers)
        {
            var target = com.ResolvedServerPath;
            var suspicious = target is { Length: > 0 }
                && SuspiciousComServers.Any(m => target.Contains(m, StringComparison.OrdinalIgnoreCase));
            if (suspicious || (target is { Length: > 0 } && InUserProfile(target)))
            {
                yield return AuditFinding.Create("PERS-TASK-COMHANDLER", Severity.High,
                    "Задача с COM-обработчиком из подозрительного сервера",
                    $"Задача '{task.Name}' использует ComHandler {com.ClassId}, разрешённый в {target}.",
                    Evidence.Of("task", task.Name), Evidence.Of("clsid", com.ClassId),
                    Evidence.Of("server", target), Evidence.Of("score", 60));
            }
        }

        foreach (var exec in task.ExecActions)
        {
            foreach (var heuristic in InterpreterHeuristics.Analyze(FileName(exec.Command), BuildCommand(exec)))
            {
                yield return heuristic;
            }

            if (InUserProfile(exec.Command))
            {
                yield return AuditFinding.Create("PERS-TASK-USERPATH", Severity.Medium,
                    "Задача запускает файл из пользовательского каталога",
                    $"Задача '{task.Name}' выполняет {exec.Command} из каталога с правом записи пользователя.",
                    Evidence.Of("task", task.Name), Evidence.Of("command", exec.Command), Evidence.Of("score", 40));
            }
        }
    }

    public static IEnumerable<AuditFinding> AnalyzeRegistryItem(RawRegistryPersistenceItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        switch (item.Area)
        {
            case "IFEO-Debugger":
                yield return AuditFinding.Create("PERS-IFEO-DEBUGGER", Severity.High,
                    "Подмена отладчика через Image File Execution Options",
                    $"Для '{item.Name}' задан Debugger = '{item.Value}'. При запуске '{item.Name}' вместо него стартует указанная команда.",
                    Evidence.Of("location", item.Location), Evidence.Of("image", item.Name),
                    Evidence.Of("debugger", item.Value), Evidence.Of("score", 70));
                break;
            case "IFEO-SilentProcessExit":
                yield return AuditFinding.Create("PERS-IFEO-SILENTEXIT", Severity.High,
                    "SilentProcessExit — запуск монитора при завершении процесса",
                    $"Для '{item.Name}' настроен MonitorProcess/SilentProcessExit: '{item.Value}'.",
                    Evidence.Of("location", item.Location), Evidence.Of("image", item.Name),
                    Evidence.Of("monitor", item.Value), Evidence.Of("score", 60));
                break;
            case "SafeBoot":
                if (!SafeBootAllowList.Contains(item.Name.Trim().ToLowerInvariant()))
                {
                    yield return AuditFinding.Create("PERS-SAFEBOOT", Severity.High,
                        "Нештатная запись в SafeBoot",
                        $"В ветке SafeBoot зарегистрирована запись '{item.Name}' ({item.Location}). Вредонос может продолжать работать в Безопасном режиме.",
                        Evidence.Of("location", item.Location), Evidence.Of("name", item.Name), Evidence.Of("score", 55));
                }

                break;
            case "AppInit_DLLs":
                yield return AuditFinding.Create("PERS-APPINIT", Severity.High,
                    "Загрузка DLL через AppInit_DLLs",
                    $"AppInit_DLLs активен и содержит '{item.Value}' — DLL загружается во все процессы с user32.dll.",
                    Evidence.Of("location", item.Location), Evidence.Of("dlls", item.Value), Evidence.Of("score", 65));
                break;
            case "Winlogon":
                yield return AuditFinding.Create("PERS-WINLOGON", Severity.High,
                    $"Нештатное значение Winlogon {item.Name}",
                    $"Значение Winlogon '{item.Name}' = '{item.Value}' отклоняется от эталона — классическая точка персистентности.",
                    Evidence.Of("location", item.Location), Evidence.Of("name", item.Name),
                    Evidence.Of("value", item.Value), Evidence.Of("score", 60));
                break;
            default:
                yield return AuditFinding.Create("PERS-REGISTRY", Severity.Medium,
                    $"Запись автозагрузки: {item.Area}",
                    $"'{item.Name}' = '{item.Value}' ({item.Location}).",
                    Evidence.Of("location", item.Location), Evidence.Of("name", item.Name),
                    Evidence.Of("value", item.Value), Evidence.Of("score", 35));
                break;
        }
    }

    private static AuditFinding FromReconciliation(TaskReconciliationFinding finding) => finding.Kind switch
    {
        TaskReconciliationKind.GhostTask => AuditFinding.Create("PERS-TASK-GHOST", Severity.High,
            "Скрытая задача планировщика (Ghost Task)", finding.Detail,
            Evidence.Of("task", finding.TaskName), Evidence.Of("score", 65)),
        TaskReconciliationKind.OrphanXml => AuditFinding.Create("PERS-TASK-ORPHAN", Severity.High,
            "Задача в обход планировщика (Orphan XML)", finding.Detail,
            Evidence.Of("task", finding.TaskName), Evidence.Of("score", 60)),
        _ => AuditFinding.Create("PERS-TASK-HIDDEN", Severity.Medium,
            "Скрытая нестандартная задача", finding.Detail,
            Evidence.Of("task", finding.TaskName), Evidence.Of("score", 45)),
    };

    private static bool InUserProfile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Replace('/', '\\').ToLowerInvariant();
        return ProfileMarkers.Any(m => normalized.Contains(m, StringComparison.Ordinal));
    }

    private static string FileName(string command)
    {
        var (exe, _) = CommandLineSplitter.Split(command);
        var normalized = exe.Replace('/', '\\');
        var slash = normalized.LastIndexOf('\\');
        return slash < 0 ? normalized : normalized[(slash + 1)..];
    }

    private static string BuildCommand(RawExecAction exec) =>
        string.IsNullOrEmpty(exec.Arguments) ? exec.Command : $"{exec.Command} {exec.Arguments}";
}
