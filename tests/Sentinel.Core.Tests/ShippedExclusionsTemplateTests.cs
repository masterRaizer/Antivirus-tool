using Sentinel.Core.Settings;

namespace Sentinel.Core.Tests;

/// <summary>Шаблон <c>allowed_exclusions.json</c> из корня репозитория, который попадает в dist\ и в MSI, должен читаться хранилищем.</summary>
public sealed class ShippedExclusionsTemplateTests
{
    private static string FindTemplate()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "allowed_exclusions.json");
            if (File.Exists(candidate) && File.Exists(Path.Combine(dir.FullName, "Sentinel.sln")))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("allowed_exclusions.json не найден в корне репозитория.");
    }

    [Fact]
    public void Template_LoadsWithDefaultInstallDirectories()
    {
        var allowed = new AllowedExclusionStore(FindTemplate()).Load();

        Assert.Contains(@"C:\Program Files\Sentinel", allowed.Paths);
        Assert.Contains(@"%LocalAppData%\Sentinel", allowed.Paths);
        Assert.Empty(allowed.Processes);
    }
}
