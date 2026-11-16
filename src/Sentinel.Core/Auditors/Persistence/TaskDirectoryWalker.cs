namespace Sentinel.Core.Auditors.Persistence;

/// <summary>
/// Кросс-платформенный обход каталога задач планировщика. Точки повторного разбора (symlink/junction/mount point)
/// строго пропускаются (<see cref="FileAttributes.ReparsePoint"/>), что исключает выход за пределы каталога и зацикливание.
/// Возвращает относительное имя задачи (в стиле Windows, через <c>\</c>) и полный путь к XML-файлу.
/// </summary>
public static class TaskDirectoryWalker
{
    public static IEnumerable<(string Name, string FullPath)> Enumerate(string tasksRoot)
    {
        ArgumentException.ThrowIfNullOrEmpty(tasksRoot);
        if (!Directory.Exists(tasksRoot))
        {
            yield break;
        }

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false,
        };

        foreach (var file in Directory.EnumerateFiles(tasksRoot, "*", options))
        {
            var name = Path.GetRelativePath(tasksRoot, file).Replace(Path.DirectorySeparatorChar, '\\');
            yield return (name, file);
        }
    }
}
