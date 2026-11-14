namespace Sentinel.Core.Tests;

/// <summary>Изолированный временный каталог, удаляемый после теста.</summary>
internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = Directory.CreateTempSubdirectory("sentinel-tests-").FullName;
    }

    public string Path { get; }

    public string Write(string name, byte[] content)
    {
        var full = System.IO.Path.Combine(Path, name);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content);
        return full;
    }

    public string WriteText(string name, string content) => Write(name, System.Text.Encoding.UTF8.GetBytes(content));

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

internal static class RepoPaths
{
    public static string RulesDirectory
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(System.IO.Path.Combine(dir.FullName, "Sentinel.sln")))
            {
                dir = dir.Parent;
            }

            return dir is null
                ? throw new InvalidOperationException("Не найден корень репозитория (Sentinel.sln).")
                : System.IO.Path.Combine(dir.FullName, "rules");
        }
    }
}
