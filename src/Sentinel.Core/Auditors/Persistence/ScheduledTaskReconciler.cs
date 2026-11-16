namespace Sentinel.Core.Auditors.Persistence;

/// <summary>Расхождение между XML-задачами на диске и их регистрацией в <c>TaskCache\Tree</c>.</summary>
public enum TaskReconciliationKind
{
    /// <summary>Задача есть в <c>TaskCache\Tree</c>, но XML-файл в <c>System32\Tasks</c> отсутствует или скрыт.</summary>
    GhostTask,

    /// <summary>XML-файл на диске не зарегистрирован в <c>TaskCache\Tree</c>.</summary>
    OrphanXml,

    /// <summary>Нестандартная задача помечена <c>&lt;Hidden&gt;true&lt;/Hidden&gt;</c> вне пространства <c>\Microsoft\Windows\</c>.</summary>
    HiddenNonMicrosoft,
}

public sealed record TaskReconciliationFinding(TaskReconciliationKind Kind, string TaskName, string Detail);

/// <summary>
/// Двусторонняя сверка задач планировщика: Ghost Tasks (в реестре без файла), Orphan XML (файл без регистрации)
/// и скрытые нестандартные задачи. Сопоставление имён — без учёта регистра и ведущих обратных слэшей.
/// </summary>
public static class ScheduledTaskReconciler
{
    public static IReadOnlyList<TaskReconciliationFinding> Reconcile(
        IReadOnlyList<RawScheduledTaskRecord> diskTasks,
        IReadOnlyList<string> taskCacheNames)
    {
        ArgumentNullException.ThrowIfNull(diskTasks);
        ArgumentNullException.ThrowIfNull(taskCacheNames);
        var findings = new List<TaskReconciliationFinding>();

        var onDisk = diskTasks
            .Where(t => t.PresentOnDisk)
            .ToDictionary(t => Normalize(t.Name), t => t, StringComparer.OrdinalIgnoreCase);
        var cache = new HashSet<string>(taskCacheNames.Select(Normalize), StringComparer.OrdinalIgnoreCase);

        foreach (var name in cache)
        {
            if (!onDisk.ContainsKey(name))
            {
                findings.Add(new TaskReconciliationFinding(TaskReconciliationKind.GhostTask, name,
                    "Задача зарегистрирована в TaskCache\\Tree, но XML-файл в System32\\Tasks отсутствует или скрыт — приём сокрытия задачи."));
            }
        }

        foreach (var (name, task) in onDisk)
        {
            if (!cache.Contains(name))
            {
                findings.Add(new TaskReconciliationFinding(TaskReconciliationKind.OrphanXml, name,
                    "XML-файл задачи присутствует на диске, но не зарегистрирован в TaskCache\\Tree — задача подложена в обход планировщика."));
            }

            if (task is { Hidden: true, IsMicrosoftBuiltIn: false })
            {
                findings.Add(new TaskReconciliationFinding(TaskReconciliationKind.HiddenNonMicrosoft, name,
                    "Нестандартная задача помечена Hidden — типичный приём сокрытия персистентности."));
            }
        }

        return findings;
    }

    private static string Normalize(string name) => name.Replace('/', '\\').Trim().TrimStart('\\');
}
