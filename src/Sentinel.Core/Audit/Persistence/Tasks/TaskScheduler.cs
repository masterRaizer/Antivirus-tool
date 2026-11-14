using System.Runtime.Versioning;
using System.Xml.Linq;

namespace Sentinel.Core.Audit.Persistence.Tasks;

/// <summary>Действие задачи планировщика типа Exec: исполняемый файл и аргументы.</summary>
public sealed record ScheduledTaskAction(string Command, string? Arguments);

/// <summary>Задача планировщика: имя/путь, состояние и список Exec-действий.</summary>
public sealed record ScheduledTaskInfo(
    string Name,
    string Path,
    bool Enabled,
    IReadOnlyList<ScheduledTaskAction> ExecActions,
    string? Author = null);

/// <summary>Поставщик задач планировщика Windows.</summary>
public interface ITaskSchedulerProvider
{
    IReadOnlyList<ScheduledTaskInfo> GetTasks();
}

/// <summary>
/// Разбор XML-определения задачи (MS-TSCH). Платформонезависим и тестируется на Linux.
/// Пространства имён игнорируются (сопоставление по локальному имени элемента).
/// </summary>
public static class TaskXmlParser
{
    public static ScheduledTaskInfo Parse(string name, string path, string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        var doc = XDocument.Parse(xml);
        var root = doc.Root ?? throw new System.Xml.XmlException("Пустой документ задачи.");

        var settings = Child(root, "Settings");
        var enabledText = settings is null ? null : Child(settings, "Enabled")?.Value;
        var enabled = enabledText is null || !string.Equals(enabledText.Trim(), "false", StringComparison.OrdinalIgnoreCase);

        var author = Child(Child(root, "RegistrationInfo"), "Author")?.Value?.Trim();

        var actions = new List<ScheduledTaskAction>();
        var actionsEl = Child(root, "Actions");
        if (actionsEl is not null)
        {
            foreach (var exec in Children(actionsEl, "Exec"))
            {
                var command = Child(exec, "Command")?.Value?.Trim();
                if (string.IsNullOrEmpty(command))
                {
                    continue;
                }

                var args = Child(exec, "Arguments")?.Value?.Trim();
                actions.Add(new ScheduledTaskAction(command, string.IsNullOrEmpty(args) ? null : args));
            }
        }

        return new ScheduledTaskInfo(name, path, enabled, actions, author);
    }

    private static XElement? Child(XElement? parent, string localName) =>
        parent?.Elements().FirstOrDefault(e => string.Equals(e.Name.LocalName, localName, StringComparison.Ordinal));

    private static IEnumerable<XElement> Children(XElement parent, string localName) =>
        parent.Elements().Where(e => string.Equals(e.Name.LocalName, localName, StringComparison.Ordinal));
}

/// <summary>
/// Чтение задач из каталога <c>%windir%\System32\Tasks</c> (XML-файлы). Реальный механизм,
/// не требующий COM: имя задачи — относительный путь внутри каталога.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsTaskSchedulerProvider : ITaskSchedulerProvider
{
    private readonly string _tasksRoot;

    public WindowsTaskSchedulerProvider(string? tasksRoot = null)
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _tasksRoot = tasksRoot ?? System.IO.Path.Combine(string.IsNullOrEmpty(win) ? @"C:\Windows" : win, "System32", "Tasks");
    }

    public IReadOnlyList<ScheduledTaskInfo> GetTasks()
    {
        if (!Directory.Exists(_tasksRoot))
        {
            return [];
        }

        var tasks = new List<ScheduledTaskInfo>();
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
        };

        foreach (var file in Directory.EnumerateFiles(_tasksRoot, "*", options))
        {
            string xml;
            try
            {
                xml = File.ReadAllText(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            var name = System.IO.Path.GetRelativePath(_tasksRoot, file).Replace(System.IO.Path.DirectorySeparatorChar, '\\');
            ScheduledTaskInfo info;
            try
            {
                info = TaskXmlParser.Parse(name, "\\" + name, xml);
            }
            catch (System.Xml.XmlException)
            {
                continue;
            }

            tasks.Add(info);
        }

        return tasks;
    }
}
