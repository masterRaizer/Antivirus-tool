using System.Text;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Remediation;

/// <summary>
/// Контроллер нейтрализации и отката: завершение дерева процессов, возврат нештатных точек
/// автозагрузки к эталонным значениям и удаление нелегитимных исключений Windows Defender.
/// Каждое изменение сначала сохраняется в манифест отката (<see cref="RollbackManifestStore"/>),
/// а затем применяется; <see cref="Undo"/> возвращает прежнее состояние. Все платформенные операции
/// выполняются через инъектируемые провайдеры, поэтому логика тестируется на Linux.
/// </summary>
public sealed class RemediationEngine
{
    private const string DebuggerValue = "Debugger";
    private const string ServiceStartValue = "Start";
    private const string ServiceDisabled = "4";

    private readonly IWhitelistProvider _whitelist;
    private readonly RemediationOptions _options;
    private readonly IProcessProvider? _processes;
    private readonly IProcessTerminator? _terminator;
    private readonly IRegistryEditor? _registry;
    private readonly IScheduledTaskEditor? _tasks;
    private readonly IDefenderPreferenceProvider? _defender;
    private readonly RollbackManifestStore _manifest;
    private readonly TimeProvider _time;
    private readonly IProcessContainment _containment;
    private readonly IFirewallRuleEditor? _firewall;

    public RemediationEngine(
        IWhitelistProvider whitelist,
        RemediationOptions options,
        IProcessProvider? processes = null,
        IProcessTerminator? terminator = null,
        IRegistryEditor? registry = null,
        IScheduledTaskEditor? tasks = null,
        IDefenderPreferenceProvider? defender = null,
        TimeProvider? timeProvider = null,
        IProcessContainment? containment = null,
        IFirewallRuleEditor? firewall = null)
    {
        ArgumentNullException.ThrowIfNull(whitelist);
        ArgumentNullException.ThrowIfNull(options);
        _whitelist = whitelist;
        _options = options;
        _processes = processes;
        _terminator = terminator;
        _registry = registry;
        _tasks = tasks;
        _defender = defender;
        _manifest = new RollbackManifestStore(options.RollbackManifestPath);
        _time = timeProvider ?? TimeProvider.System;
        _containment = containment ?? NullProcessContainment.Instance;
        _firewall = firewall;
    }

    /// <summary>Изоляция потоков перед завершением (на Windows — <see cref="WindowsProcessContainment"/>).</summary>
    public IProcessContainment Containment => _containment;

    public bool DryRun => _options.DryRun;

    public string RollbackManifestPath => _manifest.Path;

    /// <summary>Записи манифеста отката (включая уже отменённые).</summary>
    public IReadOnlyList<RollbackEntry> ListRollbackEntries() => _manifest.Load();

    /// <summary>Движок с реальными провайдерами Windows (Win32, реестр, schtasks, WMI).</summary>
    public static RemediationEngine CreateDefault(IWhitelistProvider whitelist, RemediationOptions options)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Нейтрализация реализована только для Windows.");
        }

        return new RemediationEngine(
            whitelist,
            options,
            new WindowsProcessProvider(TimeSpan.Zero),
            new WindowsProcessTerminator(),
            RegistryProviderFactory.CreateEditor(),
            new WindowsScheduledTaskEditor(),
            new WindowsDefenderPreferenceProvider(),
            containment: new WindowsProcessContainment(),
            firewall: new WindowsFirewallRuleEditor());
    }

    // ---- Процессы --------------------------------------------------------------

    /// <summary>
    /// Нейтрализует процесс <paramref name="pid"/> и всех его потомков в строгом порядке:
    /// (1) <see cref="Protection.CriticalProcessGuard"/> и самозащита/белый список доверенных системных файлов;
    /// (2) <see cref="Behavioral.FalsePositiveGuard"/> (список разрешённого, кэш чистых, подпись, теневой режим) — если задан
    /// в <see cref="RemediationOptions.FalsePositiveGuard"/>; (3) приостановка потоков всего допустимого дерева через
    /// <see cref="IProcessContainment"/> — сторожевые потоки не успеют перезапустить корень; (4) завершение, корень первым,
    /// с ожиданием выхода. Не завершённые процессы возобновляются (<see cref="ProcessSuspensionScope"/>), в том числе при исключении.
    /// </summary>
    /// <param name="guardContext">Балл, хеш и подпись для <see cref="Behavioral.FalsePositiveGuard"/>; путь берётся из снимка процесса.</param>
    /// <param name="userConfirmed">Действие подтверждено пользователем: спорный вердикт («спросить») не блокирует, «защищено» — блокирует всегда.</param>
    public ProcessTreeResult TerminateProcessTree(int pid, Behavioral.GuardContext? guardContext = null, bool userConfirmed = false)
    {
        if (_processes is null || _terminator is null)
        {
            return new ProcessTreeResult(pid, RemediationStatus.Failed, "Провайдер процессов не настроен.", []);
        }

        if (pid <= 4)
        {
            return new ProcessTreeResult(pid, RemediationStatus.Blocked, $"PID {pid} — ядро системы; завершение запрещено.", []);
        }

        if (pid == _options.CurrentProcessId)
        {
            return new ProcessTreeResult(pid, RemediationStatus.Blocked, "Sentinel не завершает собственный процесс.", []);
        }

        var snapshot = _processes.GetProcesses();
        var root = snapshot.FirstOrDefault(p => p.Pid == pid);
        if (root is null)
        {
            return new ProcessTreeResult(pid, RemediationStatus.Skipped, $"Процесс PID {pid} не найден (уже завершён).", []);
        }

        // (1) CriticalProcessGuard, самозащита и белый список; (2) FalsePositiveGuard.
        var rootGuard = CriticalGuard(root) ?? Guard(root) ?? FalsePositive(root, guardContext, userConfirmed);
        if (rootGuard is not null)
        {
            return new ProcessTreeResult(pid, RemediationStatus.Blocked, rootGuard,
                [new ProcessTerminationResult(root, RemediationStatus.Blocked, rootGuard)]);
        }

        var plan = CollectTree(root, snapshot)
            .Select(p => (Process: p, Denied: p.Pid == root.Pid ? null : CriticalGuard(p) ?? Guard(p)))
            .ToList();

        var results = new List<ProcessTerminationResult>();
        if (_options.DryRun)
        {
            results.AddRange(plan.Select(x => x.Denied is null
                ? new ProcessTerminationResult(x.Process, RemediationStatus.WouldDo, "Будет приостановлен и завершён.")
                : new ProcessTerminationResult(x.Process, RemediationStatus.Blocked, x.Denied)));
            return Summarize(pid, results, null);
        }

        var scope = new ProcessSuspensionScope(_containment);
        try
        {
            // (3) Сначала замораживается всё допустимое дерево, затем (4) завершение — корень первым.
            foreach (var (process, denied) in plan)
            {
                if (denied is null)
                {
                    scope.Suspend(process.Pid, process.Name, process.ExecutablePath);
                }
            }

            foreach (var (process, denied) in plan)
            {
                if (denied is not null)
                {
                    results.Add(new ProcessTerminationResult(process, RemediationStatus.Blocked, denied));
                    continue;
                }

                var outcome = _terminator.Terminate(process.Pid);
                if (outcome.Success)
                {
                    scope.MarkTerminated(process.Pid);
                    results.Add(new ProcessTerminationResult(process, RemediationStatus.Done, "Завершён."));
                }
                else
                {
                    results.Add(new ProcessTerminationResult(process, RemediationStatus.Failed, outcome.Error ?? "Не удалось завершить."));
                }
            }
        }
        finally
        {
            scope.Dispose(); // не завершённые (или при исключении — все) процессы возобновляются
        }

        return Summarize(pid, results, scope);
    }

    private ProcessTreeResult Summarize(int pid, List<ProcessTerminationResult> results, ProcessSuspensionScope? scope)
    {
        var rootResult = results[0];
        var failed = results.Count(r => r.Status == RemediationStatus.Failed);
        var blocked = results.Count(r => r.Status == RemediationStatus.Blocked);
        var status = rootResult.Status == RemediationStatus.Failed ? RemediationStatus.Failed : rootResult.Status;
        var message = _options.DryRun
            ? $"Будет завершено процессов: {results.Count - blocked}" + (blocked > 0 ? $"; защищено: {blocked}" : string.Empty)
            : $"Завершено процессов: {results.Count(r => r.Status == RemediationStatus.Done)} из {results.Count}"
                + (failed > 0 ? $"; ошибок: {failed}" : string.Empty)
                + (blocked > 0 ? $"; защищено: {blocked}" : string.Empty);
        if (scope is { SuspendedThreadCount: > 0 })
        {
            message += $". Перед завершением приостановлено потоков: {scope.SuspendedThreadCount} в {scope.SuspendedProcessIds.Count} процесс(ах)"
                + (scope.ResumedProcessIds.Count > 0 ? $"; возобновлено незавершённых: {scope.ResumedProcessIds.Count}" : string.Empty);
        }

        return new ProcessTreeResult(pid, status, message, results)
        {
            SuspendedThreadCount = scope?.SuspendedThreadCount ?? 0,
            SuspendedProcessIds = scope?.SuspendedProcessIds.ToArray() ?? [],
            ResumedProcessIds = scope?.ResumedProcessIds.ToArray() ?? [],
        };
    }

    private static string? CriticalGuard(ProcessSnapshot process) =>
        Protection.CriticalProcessGuard.IsProtectedProcess(process.Pid, process.Name, process.ExecutablePath)
            ? $"'{process.Name}' — защищён CriticalProcessGuard (системный процесс в системном каталоге или Sentinel)."
            : null;

    private string? FalsePositive(ProcessSnapshot root, Behavioral.GuardContext? context, bool userConfirmed)
    {
        if (_options.FalsePositiveGuard is not { } factory)
        {
            return null;
        }

        var effective = (context ?? new Behavioral.GuardContext { Score = 100 }) with { Path = root.ExecutablePath ?? context?.Path };
        var verdict = factory().Evaluate(effective);
        return verdict.Decision switch
        {
            Behavioral.GuardDecision.Protected => $"FalsePositiveGuard: {verdict.Reason}",
            Behavioral.GuardDecision.Act => null,
            _ when userConfirmed => null,
            _ => $"FalsePositiveGuard: автоматическое завершение запрещено ({verdict.Reason})",
        };
    }

    /// <summary>Причина, по которой процесс нельзя завершать, либо <c>null</c>.</summary>
    private string? Guard(ProcessSnapshot process)
    {
        if (process.Pid <= 4)
        {
            return $"PID {process.Pid} — ядро системы.";
        }

        if (process.Pid == _options.CurrentProcessId)
        {
            return "Собственный процесс Sentinel.";
        }

        if (Scanning.SelfProtection.IsProtectedImageName(process.Name) || Scanning.SelfProtection.IsOwnImageName(process.Name)
            || Scanning.SelfProtection.IsProtectedFile(process.ExecutablePath))
        {
            return $"'{process.Name}' — критический процесс Windows или компонент Sentinel (самозащита).";
        }

        if (string.IsNullOrWhiteSpace(process.ExecutablePath))
        {
            // Путь недоступен обычно у защищённых системных процессов: по одному имени их не трогаем.
            return _options.SystemPolicy.IsKnownSystemName(process.Name)
                ? $"Системный процесс '{process.Name}' с недоступным путём — завершение запрещено."
                : null;
        }

        WhitelistDecision decision;
        try
        {
            decision = _whitelist.Evaluate(process.ExecutablePath);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return $"Не удалось проверить '{process.ExecutablePath}' по белому списку: {ex.Message}";
        }

        return decision.IsWhitelisted
            ? $"'{process.ExecutablePath}' — доверенный системный файл ({decision.Reason})."
            : null;
    }

    /// <summary>Корень и все его потомки в порядке обхода в ширину.</summary>
    private static List<ProcessSnapshot> CollectTree(ProcessSnapshot root, IReadOnlyList<ProcessSnapshot> snapshot)
    {
        var children = snapshot
            .Where(p => p.Pid != p.ParentPid)
            .ToLookup(p => p.ParentPid);
        var result = new List<ProcessSnapshot> { root };
        var visited = new HashSet<int> { root.Pid };
        var queue = new Queue<ProcessSnapshot>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var parent = queue.Dequeue();
            foreach (var child in children[parent.Pid])
            {
                // Потомок не может быть старше родителя: иначе это совпадение с повторно выданным PID.
                if (child.StartTimeUtc is { } childStart && parent.StartTimeUtc is { } parentStart && childStart < parentStart)
                {
                    continue;
                }

                if (visited.Add(child.Pid))
                {
                    result.Add(child);
                    queue.Enqueue(child);
                }
            }
        }

        return result;
    }

    // ---- Автозагрузка ----------------------------------------------------------

    /// <summary>
    /// Откатывает нештатные точки автозапуска. Записи без находок не трогаются.
    /// Записи одного файла hosts объединяются в одно изменение с одной резервной копией.
    /// </summary>
    public IReadOnlyList<RemediationAction> RollbackPersistence(IEnumerable<PersistenceEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var actions = new List<RemediationAction>();
        var hosts = new List<PersistenceEntry>();
        foreach (var entry in entries)
        {
            if (!entry.HasFindings)
            {
                actions.Add(Action(entry, RemediationStatus.Skipped, "Запись без находок — штатная, изменения не требуются."));
            }
            else if (OwnPersistence(entry) is { } own)
            {
                actions.Add(Action(entry, RemediationStatus.Blocked, own));
            }
            else if (entry.Kind == PersistenceKind.HostsFile)
            {
                hosts.Add(entry);
            }
            else
            {
                actions.Add(Safely(entry, () => RollbackOne(entry)));
            }
        }

        foreach (var group in hosts.GroupBy(h => h.Location, StringComparer.OrdinalIgnoreCase))
        {
            var items = group.ToArray();
            actions.Add(Safely(items[0], () => RollbackHosts(group.Key, items)));
        }

        return actions;
    }

    public RemediationAction RollbackPersistence(PersistenceEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return RollbackPersistence([entry])[0];
    }

    /// <summary>Самозащита: службы и файлы Sentinel не отключаются и не «откатываются» ни при каких находках.</summary>
    private static string? OwnPersistence(PersistenceEntry entry)
    {
        if (entry.Kind == PersistenceKind.Service && Scanning.SelfProtection.IsOwnServiceName(entry.Name))
        {
            return $"Служба '{entry.Name}' — компонент Sentinel (самозащита): изменение и отключение запрещены.";
        }

        return entry.ResolvedTarget is { Length: > 0 } target && Scanning.SelfProtection.IsProtectedFile(target)
            ? $"Цель '{target}' — файл Sentinel или критический файл Windows (самозащита): изменение автозагрузки запрещено."
            : null;
    }

    private static RemediationAction Safely(PersistenceEntry entry, Func<RemediationAction> action)
    {
        try
        {
            return action();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or NotSupportedException or FormatException or InvalidOperationException)
        {
            return Action(entry, RemediationStatus.Failed, ex.Message);
        }
    }

    private RemediationAction RollbackOne(PersistenceEntry entry)
    {
        switch (entry.Kind)
        {
            case PersistenceKind.RegistryRun:
            case PersistenceKind.RegistryRunOnce:
                return ChangeRegistry(entry, entry.Name, baseline: null, RegistryValueKind.Sz);

            case PersistenceKind.WinlogonShell:
                // Эталон: в HKLM — оболочка по умолчанию, в HKCU значение отсутствует.
                return ChangeRegistry(entry, "Shell", IsCurrentUser(entry) ? null : _options.DefaultShell, RegistryValueKind.Sz);

            case PersistenceKind.WinlogonUserinit:
                return ChangeRegistry(entry, "Userinit", IsCurrentUser(entry) ? null : _options.DefaultUserinit, RegistryValueKind.Sz);

            case PersistenceKind.ImageFileExecutionOptions:
                return ChangeRegistry(entry, DebuggerValue, baseline: null, RegistryValueKind.Sz);

            case PersistenceKind.Service:
                if (IsWhitelisted(entry.ResolvedTarget, out var why))
                {
                    return Action(entry, RemediationStatus.Blocked, $"Служба использует доверенный системный файл ({why}); отключение запрещено.");
                }

                // Служба не удаляется, а отключается (Start = 4): действие полностью обратимо.
                return ChangeRegistry(entry, ServiceStartValue, ServiceDisabled, RegistryValueKind.Dword);

            case PersistenceKind.ScheduledTask:
                return RollbackTask(entry);

            default:
                return Action(entry, RemediationStatus.Skipped,
                    $"Автоматический откат точек типа {entry.Kind} не выполняется; файл-цель изолируется карантином.");
        }
    }

    private static bool IsCurrentUser(PersistenceEntry entry) =>
        RegistryKeyPath.TryParse(entry.Location, out var key) && key!.Hive == RegistryHive.CurrentUser;

    private bool IsWhitelisted(string? path, out string reason)
    {
        reason = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var decision = _whitelist.Evaluate(path);
            reason = decision.Reason;
            return decision.IsWhitelisted;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>Приводит значение реестра к эталону (<paramref name="baseline"/> = null — удалить) с резервной копией.</summary>
    private RemediationAction ChangeRegistry(PersistenceEntry entry, string valueName, string? baseline, RegistryValueKind baselineKind)
    {
        if (_registry is null)
        {
            return Action(entry, RemediationStatus.Failed, "Редактор реестра не настроен.");
        }

        if (!RegistryKeyPath.TryParse(entry.Location, out var key) || key is null)
        {
            return Action(entry, RemediationStatus.Failed, $"Не удалось разобрать расположение '{entry.Location}'.");
        }

        var previous = _registry.GetValue(key, valueName);
        if (previous is null && baseline is null)
        {
            return Action(entry, RemediationStatus.Skipped, $"Значение '{valueName}' уже отсутствует.");
        }

        if (previous is not null && baseline is not null
            && string.Equals(previous.Value?.Trim(), baseline, StringComparison.OrdinalIgnoreCase))
        {
            return Action(entry, RemediationStatus.Skipped, $"Значение '{valueName}' уже соответствует эталону.");
        }

        var description = baseline is null
            ? $"{key}: значение '{valueName}' удалено (было: '{previous?.Value}')"
            : $"{key}: '{valueName}' = '{baseline}' (было: '{previous?.Value ?? "<отсутствует>"}')";
        if (_options.DryRun)
        {
            return Action(entry, RemediationStatus.WouldDo, "Будет изменено — " + description);
        }

        // Резервная копия записывается до изменения: сбой между шагами не оставит систему без пути назад.
        var backup = NewEntry(RollbackKind.RegistryValue, key.ToString(), valueName, Reason(entry)) with
        {
            PreviousExisted = previous is not null,
            PreviousValue = previous?.Value,
            PreviousValueKind = previous?.Kind,
            NewValue = baseline,
        };
        _manifest.Append(backup);

        if (baseline is null)
        {
            _registry.DeleteValue(key, valueName);
        }
        else
        {
            _registry.SetValue(key, valueName, baseline, baselineKind);
        }

        return Action(entry, RemediationStatus.Done, description) with { RollbackId = backup.Id };
    }

    private RemediationAction RollbackTask(PersistenceEntry entry)
    {
        if (_tasks is null)
        {
            return Action(entry, RemediationStatus.Failed, "Редактор планировщика не настроен.");
        }

        var taskPath = entry.Location;
        var xml = _tasks.ExportXml(taskPath);
        if (xml is null)
        {
            return Action(entry, RemediationStatus.Failed,
                $"Не удалось получить определение задачи '{taskPath}' для резервной копии — задача не удалена.");
        }

        if (_options.DryRun)
        {
            return Action(entry, RemediationStatus.WouldDo, $"Будет удалена задача планировщика '{taskPath}'.");
        }

        var backup = NewEntry(RollbackKind.ScheduledTask, taskPath, null, Reason(entry)) with
        {
            PreviousExisted = true,
            PreviousValue = xml,
        };
        _manifest.Append(backup);

        var result = _tasks.Delete(taskPath);
        if (!result.Success)
        {
            _manifest.Replace(backup with { UndoneAtUtc = _time.GetUtcNow().UtcDateTime });
            return Action(entry, RemediationStatus.Failed, result.Error ?? "Не удалось удалить задачу.");
        }

        return Action(entry, RemediationStatus.Done, $"Задача планировщика '{taskPath}' удалена.") with { RollbackId = backup.Id };
    }

    private RemediationAction RollbackHosts(string hostsPath, PersistenceEntry[] entries)
    {
        var target = entries[0];
        if (!File.Exists(hostsPath))
        {
            return Action(target, RemediationStatus.Failed, $"Файл hosts не найден: {hostsPath}");
        }

        var original = File.ReadAllText(hostsPath);
        var remove = entries
            .Select(e => e.Command?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .Where(parts => parts is { Length: 2 })
            .Select(parts => (Address: parts![0], Host: parts[1]))
            .ToArray();
        var (cleaned, removed) = HostsCleaner.Remove(original, remove);
        var label = $"{hostsPath}: {string.Join(", ", remove.Select(r => r.Host))}";
        if (removed == 0)
        {
            return new RemediationAction(RemediationActionKind.RollbackPersistence, label, RemediationStatus.Skipped,
                "Указанные записи в hosts уже отсутствуют.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.RollbackPersistence, label, RemediationStatus.WouldDo,
                $"Будет удалено записей hosts: {removed}.");
        }

        var backup = NewEntry(RollbackKind.HostsFile, hostsPath, null,
            string.Join("; ", entries.SelectMany(e => e.Findings).Select(f => f.Id).Distinct())) with
        {
            PreviousExisted = true,
            PreviousValue = original,
            NewValue = cleaned,
        };
        _manifest.Append(backup);
        WriteHosts(hostsPath, cleaned);

        return new RemediationAction(RemediationActionKind.RollbackPersistence, label, RemediationStatus.Done,
            $"Удалено записей hosts: {removed}.") { RollbackId = backup.Id };
    }

    /// <summary>Запись hosts с временным снятием атрибута ReadOnly (вредоносы часто его выставляют).</summary>
    private static void WriteHosts(string path, string content)
    {
        var attributes = File.GetAttributes(path);
        var readOnly = attributes.HasFlag(FileAttributes.ReadOnly);
        if (readOnly)
        {
            File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
        }

        try
        {
            File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        finally
        {
            if (readOnly)
            {
                File.SetAttributes(path, attributes);
            }
        }
    }

    // ---- Исключения Defender ---------------------------------------------------

    /// <summary>
    /// Удаляет исключение встроенной защиты. Локальные исключения удаляются методом
    /// <c>MSFT_MpPreference.Remove</c>; исключения, навязанные через ветку политик, — удалением
    /// значения реестра (WMI-метод на них не действует). Удалённая запись сохраняется в манифест отката.
    /// </summary>
    public RemediationAction RemoveDefenderExclusion(DefenderExclusion exclusion, string reason)
    {
        ArgumentNullException.ThrowIfNull(exclusion);
        ArgumentException.ThrowIfNullOrEmpty(reason);
        var label = exclusion.ToString();

        try
        {
            return exclusion.FromPolicy
                ? RemovePolicyExclusion(exclusion, reason, label)
                : RemovePreferenceExclusion(exclusion, reason, label);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or NotSupportedException or InvalidOperationException)
        {
            return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.Failed, ex.Message);
        }
    }

    public IReadOnlyList<RemediationAction> RemoveDefenderExclusions(IEnumerable<DefenderExclusion> exclusions, string reason)
    {
        ArgumentNullException.ThrowIfNull(exclusions);
        return exclusions.Select(e => RemoveDefenderExclusion(e, reason)).ToArray();
    }

    private RemediationAction RemovePreferenceExclusion(DefenderExclusion exclusion, string reason, string label)
    {
        if (_defender is null)
        {
            return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.Failed,
                "Провайдер настроек Defender не настроен.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.WouldDo,
                $"Будет удалено исключение через MSFT_MpPreference.Remove({exclusion.PreferenceProperty}).");
        }

        var backup = NewEntry(RollbackKind.DefenderExclusion, exclusion.PreferenceProperty, exclusion.Value, reason) with
        {
            PreviousExisted = true,
            PreviousValue = exclusion.Value,
        };
        _manifest.Append(backup);

        var result = _defender.RemoveExclusion(exclusion.Kind, exclusion.Value);
        if (!result.Success)
        {
            _manifest.Replace(backup with { UndoneAtUtc = _time.GetUtcNow().UtcDateTime });
            return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.Failed,
                result.Error ?? "MSFT_MpPreference.Remove завершился ошибкой.");
        }

        return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.Done,
            $"Исключение удалено (MSFT_MpPreference.Remove, {exclusion.PreferenceProperty}).") { RollbackId = backup.Id };
    }

    private RemediationAction RemovePolicyExclusion(DefenderExclusion exclusion, string reason, string label)
    {
        if (_registry is null || !RegistryKeyPath.TryParse(exclusion.SourceKey, out var key) || key is null)
        {
            return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.Failed,
                "Исключение задано политикой, а редактор реестра не настроен или ключ не распознан.");
        }

        var previous = _registry.GetValue(key, exclusion.Value);
        if (previous is null)
        {
            return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.Skipped,
                "Исключение уже отсутствует.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.WouldDo,
                $"Будет удалено значение политики в {key}.");
        }

        var backup = NewEntry(RollbackKind.RegistryValue, key.ToString(), exclusion.Value, reason) with
        {
            PreviousExisted = true,
            PreviousValue = previous.Value,
            PreviousValueKind = previous.Kind,
        };
        _manifest.Append(backup);
        _registry.DeleteValue(key, exclusion.Value);
        return new RemediationAction(RemediationActionKind.RemoveDefenderExclusion, label, RemediationStatus.Done,
            $"Исключение, заданное политикой, удалено из {key}.") { RollbackId = backup.Id };
    }

    // ---- Брандмауэр, hosts и каталоги (плейбук семейств) -------------------------

    /// <summary>
    /// Удаляет поддельное разрешающее правило брандмауэра (имя системного правила, программа вредоноса) с резервной копией строки
    /// правила. Настоящие системные правила (имя ссылкой на ресурс <c>@FirewallAPI.dll,…</c>) не удаляются никогда.
    /// </summary>
    public RemediationAction RemoveFirewallRule(FirewallRule rule, string reason)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var label = $"Правило брандмауэра «{rule.DisplayName ?? rule.Name}» ({rule.AppPath})";
        if ((rule.DisplayName ?? rule.Name).StartsWith('@'))
        {
            return new RemediationAction(RemediationActionKind.RemoveFirewallRule, label, RemediationStatus.Blocked,
                "Встроенное правило Windows (имя из ресурса) не удаляется.");
        }

        if (rule.AppPath is { Length: > 0 } app && (Scanning.SelfProtection.IsProtectedFile(app) || IsWhitelisted(app, out _)))
        {
            return new RemediationAction(RemediationActionKind.RemoveFirewallRule, label, RemediationStatus.Blocked,
                "Правило относится к доверенному системному файлу или к Sentinel — удаление запрещено.");
        }

        if (_firewall is null)
        {
            return new RemediationAction(RemediationActionKind.RemoveFirewallRule, label, RemediationStatus.Failed, "Редактор правил брандмауэра не настроен.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.RemoveFirewallRule, label, RemediationStatus.WouldDo, "Будет удалено.");
        }

        var backup = NewEntry(RollbackKind.FirewallRule, rule.DisplayName ?? rule.Name, rule.Name, reason) with
        {
            PreviousExisted = true,
            PreviousValue = rule.RawValue ?? string.Empty,
        };
        _manifest.Append(backup);
        var result = _firewall.RemoveRule(rule.Name);
        if (!result.Success)
        {
            _manifest.Replace(backup with { UndoneAtUtc = _time.GetUtcNow().UtcDateTime });
            return new RemediationAction(RemediationActionKind.RemoveFirewallRule, label, RemediationStatus.Failed, result.Error ?? "Не удалось удалить правило.");
        }

        return new RemediationAction(RemediationActionKind.RemoveFirewallRule, label, RemediationStatus.Done, "Правило удалено.") { RollbackId = backup.Id };
    }

    /// <summary>Запрещает исходящие соединения на адреса IOC отдельным правилом Sentinel (отмена удаляет правило).</summary>
    public RemediationAction BlockRemoteAddresses(string ruleId, IReadOnlyList<string> addresses, string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(ruleId);
        ArgumentNullException.ThrowIfNull(addresses);
        var valid = addresses.Where(a => System.Net.IPAddress.TryParse(a, out var ip) && !System.Net.IPAddress.IsLoopback(ip))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var label = $"Блокировка исходящих: {string.Join(", ", valid)}";
        if (valid.Length == 0)
        {
            return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.Skipped, "Нет корректных IP-адресов для блокировки.");
        }

        if (_firewall is null)
        {
            return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.Failed, "Редактор правил брандмауэра не настроен.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.WouldDo, $"Будет добавлено правило «{ruleId}».");
        }

        var backup = NewEntry(RollbackKind.FirewallBlockRule, ruleId, ruleId, reason) with { PreviousExisted = false, NewValue = string.Join(",", valid) };
        _manifest.Append(backup);
        var result = _firewall.AddOutboundBlockRule(ruleId, valid);
        if (!result.Success)
        {
            _manifest.Replace(backup with { UndoneAtUtc = _time.GetUtcNow().UtcDateTime });
            return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.Failed, result.Error ?? "Не удалось добавить правило.");
        }

        return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.Done, $"Добавлено правило «{ruleId}».") { RollbackId = backup.Id };
    }

    /// <summary>Добавляет в hosts записи <c>0.0.0.0 домен</c> для доменов IOC (копия прежнего hosts — в манифесте).</summary>
    public RemediationAction BlockDomainsInHosts(string hostsPath, IReadOnlyList<string> domains, string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(hostsPath);
        ArgumentNullException.ThrowIfNull(domains);
        var valid = domains.Select(d => d.Trim().ToLowerInvariant())
            .Where(d => d.Length is > 3 and < 254 && d.Contains('.', StringComparison.Ordinal) && d.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-'))
            .Distinct(StringComparer.Ordinal).ToArray();
        var label = $"{hostsPath}: {string.Join(", ", valid)}";
        if (valid.Length == 0)
        {
            return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.Skipped, "Нет доменов для блокировки.");
        }

        var original = File.Exists(hostsPath) ? File.ReadAllText(hostsPath) : string.Empty;
        var present = HostsFileParser.Parse(original).Select(e => e.Host).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var missing = valid.Where(d => !present.Contains(d)).ToArray();
        if (missing.Length == 0)
        {
            return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.Skipped, "Домены уже заблокированы в hosts.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.WouldDo, $"Будет добавлено записей hosts: {missing.Length}.");
        }

        var backup = NewEntry(RollbackKind.HostsFile, hostsPath, null, reason) with { PreviousExisted = File.Exists(hostsPath), PreviousValue = original };
        _manifest.Append(backup);
        var newline = original.Contains("\r\n", StringComparison.Ordinal) || original.Length == 0 ? "\r\n" : "\n";
        var sb = new StringBuilder(original);
        if (original.Length > 0 && !original.EndsWith('\n'))
        {
            sb.Append(newline);
        }

        sb.Append("# Sentinel: блокировка доменов вредоносного семейства").Append(newline);
        foreach (var domain in missing)
        {
            sb.Append("0.0.0.0 ").Append(domain).Append(newline);
        }

        WriteHosts(hostsPath, sb.ToString());
        return new RemediationAction(RemediationActionKind.BlockIoc, label, RemediationStatus.Done, $"В hosts добавлено записей: {missing.Length}.") { RollbackId = backup.Id };
    }

    /// <summary>Удаляет каталог вредоноса, если в нём не осталось файлов (после карантина); пустые подкаталоги удаляются вместе с ним.</summary>
    public RemediationAction RemoveEmptyDirectory(string path, string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var label = $"Каталог {path}";
        if (!Directory.Exists(path))
        {
            return new RemediationAction(RemediationActionKind.RemoveDirectory, label, RemediationStatus.Skipped, "Каталог уже отсутствует.");
        }

        if (Scanning.SelfProtection.IsProtectedFile(Path.Combine(path, "x")) || (new DirectoryInfo(path).Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return new RemediationAction(RemediationActionKind.RemoveDirectory, label, RemediationStatus.Blocked,
                "Каталог защищён (системный, Sentinel или точка повторной обработки) — не удаляется.");
        }

        var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = false };
        if (Directory.EnumerateFiles(path, "*", options).Any())
        {
            return new RemediationAction(RemediationActionKind.RemoveDirectory, label, RemediationStatus.Skipped,
                "В каталоге остались файлы — он не удаляется.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.RemoveDirectory, label, RemediationStatus.WouldDo, "Будет удалён пустой каталог.");
        }

        var backup = NewEntry(RollbackKind.EmptyDirectory, path, null, reason) with { PreviousExisted = true };
        _manifest.Append(backup);
        Directory.Delete(path, recursive: true);
        return new RemediationAction(RemediationActionKind.RemoveDirectory, label, RemediationStatus.Done, "Пустой каталог удалён.") { RollbackId = backup.Id };
    }

    // ---- Отмена ----------------------------------------------------------------

    /// <summary>
    /// Отменяет ранее выполненное изменение по записи манифеста отката
    /// (<paramref name="rollbackId"/> — полный идентификатор или уникальный префикс от 6 символов).
    /// </summary>
    public RemediationAction Undo(string rollbackId)
    {
        ArgumentException.ThrowIfNullOrEmpty(rollbackId);
        var id = rollbackId.Trim();
        var matches = _manifest.Load()
            .Where(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase)
                || (id.Length >= 6 && e.Id.StartsWith(id, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        if (matches.Length != 1)
        {
            return new RemediationAction(RemediationActionKind.Undo, id, RemediationStatus.Failed,
                matches.Length == 0 ? "Запись отката не найдена." : "Префикс идентификатора неоднозначен.");
        }

        var entry = matches[0];
        var label = $"{entry.Kind}: {entry.Target}{(entry.Name is null ? string.Empty : " → " + entry.Name)}";
        if (entry.UndoneAtUtc is not null)
        {
            return new RemediationAction(RemediationActionKind.Undo, label, RemediationStatus.Skipped, "Изменение уже отменено.");
        }

        if (_options.DryRun)
        {
            return new RemediationAction(RemediationActionKind.Undo, label, RemediationStatus.WouldDo, "Будет возвращено прежнее значение.");
        }

        try
        {
            var error = UndoCore(entry);
            if (error is not null)
            {
                return new RemediationAction(RemediationActionKind.Undo, label, RemediationStatus.Failed, error);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or NotSupportedException or FormatException or InvalidOperationException)
        {
            return new RemediationAction(RemediationActionKind.Undo, label, RemediationStatus.Failed, ex.Message);
        }

        _manifest.Replace(entry with { UndoneAtUtc = _time.GetUtcNow().UtcDateTime });
        return new RemediationAction(RemediationActionKind.Undo, label, RemediationStatus.Done, "Прежнее значение возвращено.") { RollbackId = entry.Id };
    }

    private string? UndoCore(RollbackEntry entry)
    {
        switch (entry.Kind)
        {
            case RollbackKind.RegistryValue:
                if (_registry is null || !RegistryKeyPath.TryParse(entry.Target, out var key) || key is null || entry.Name is null)
                {
                    return "Редактор реестра не настроен или запись манифеста повреждена.";
                }

                if (entry.PreviousExisted)
                {
                    _registry.SetValue(key, entry.Name, entry.PreviousValue, entry.PreviousValueKind ?? RegistryValueKind.Sz);
                }
                else
                {
                    _registry.DeleteValue(key, entry.Name);
                }

                return null;

            case RollbackKind.HostsFile:
                if (entry.PreviousValue is null || !File.Exists(entry.Target))
                {
                    return "Файл hosts отсутствует или в манифесте нет резервной копии.";
                }

                WriteHosts(entry.Target, entry.PreviousValue);
                return null;

            case RollbackKind.ScheduledTask:
                if (_tasks is null || entry.PreviousValue is null)
                {
                    return "Редактор планировщика не настроен или в манифесте нет XML задачи.";
                }

                var created = _tasks.Create(entry.Target, entry.PreviousValue);
                return created.Success ? null : created.Error ?? "Не удалось воссоздать задачу.";

            case RollbackKind.FirewallRule:
                if (_firewall is null || entry.Name is null || entry.PreviousValue is null)
                {
                    return "Редактор правил брандмауэра не настроен или в манифесте нет строки правила.";
                }

                var restored = _firewall.RestoreRule(entry.Name, entry.PreviousValue);
                return restored.Success ? null : restored.Error ?? "Не удалось воссоздать правило брандмауэра.";

            case RollbackKind.FirewallBlockRule:
                if (_firewall is null || entry.Name is null)
                {
                    return "Редактор правил брандмауэра не настроен.";
                }

                var removedBlock = _firewall.RemoveRule(entry.Name);
                return removedBlock.Success ? null : removedBlock.Error ?? "Не удалось удалить правило блокировки.";

            case RollbackKind.EmptyDirectory:
                Directory.CreateDirectory(entry.Target);
                return null;

            case RollbackKind.DefenderExclusion:
                if (_defender is null || entry.PreviousValue is null)
                {
                    return "Провайдер настроек Defender не настроен.";
                }

                var kind = entry.Target switch
                {
                    "ExclusionPath" => DefenderExclusionKind.Path,
                    "ExclusionProcess" => DefenderExclusionKind.Process,
                    "ExclusionExtension" => DefenderExclusionKind.Extension,
                    _ => DefenderExclusionKind.IpAddress,
                };
                var added = _defender.AddExclusion(kind, entry.PreviousValue);
                return added.Success ? null : added.Error ?? "MSFT_MpPreference.Add завершился ошибкой.";

            default:
                return $"Неизвестный тип записи отката: {entry.Kind}.";
        }
    }

    // ---- Вспомогательные методы -----------------------------------------------

    private RollbackEntry NewEntry(RollbackKind kind, string target, string? name, string reason) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        TimestampUtc = _time.GetUtcNow().UtcDateTime,
        Kind = kind,
        Target = target,
        Name = name,
        Reason = reason,
    };

    private static string Reason(PersistenceEntry entry) =>
        string.Join("; ", entry.Findings.Select(f => f.Id).Distinct());

    private static RemediationAction Action(PersistenceEntry entry, RemediationStatus status, string message) =>
        new(RemediationActionKind.RollbackPersistence, $"[{entry.Kind}] {entry.Location} → {entry.Name}", status, message);
}

/// <summary>Удаление записей из текста hosts с сохранением остального содержимого и стиля переводов строк.</summary>
public static class HostsCleaner
{
    /// <returns>Новый текст и число удалённых сопоставлений «адрес → имя».</returns>
    public static (string Content, int Removed) Remove(string content, IReadOnlyCollection<(string Address, string Host)> entries)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(entries);
        var newline = content.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var lines = content.Split('\n');
        var output = new List<string>(lines.Length);
        var removed = 0;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');
            var hash = line.IndexOf('#', StringComparison.Ordinal);
            var body = hash >= 0 ? line[..hash] : line;
            var comment = hash >= 0 ? line[hash..] : string.Empty;
            var parts = body.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                output.Add(line);
                continue;
            }

            var address = parts[0];
            var kept = new List<string>();
            foreach (var host in parts.Skip(1))
            {
                if (entries.Any(e => string.Equals(e.Address, address, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(e.Host, host, StringComparison.OrdinalIgnoreCase)))
                {
                    removed++;
                }
                else
                {
                    kept.Add(host);
                }
            }

            if (kept.Count == parts.Length - 1)
            {
                output.Add(line); // строка не затронута — сохраняем исходное форматирование
            }
            else if (kept.Count > 0)
            {
                output.Add($"{address} {string.Join(' ', kept)}{(comment.Length > 0 ? " " + comment : string.Empty)}");
            }

            // kept.Count == 0 — строка удаляется целиком.
        }

        return (string.Join(newline, output), removed);
    }
}
