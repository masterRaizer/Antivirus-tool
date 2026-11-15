using Sentinel.Core.Runtime;
using Sentinel.Core.Scanning;

namespace Sentinel.Core.Tests;

public class ScanEnumerationTests
{
    private static string[] Names(IEnumerable<string> paths, string root) =>
        paths.Select(p => Path.GetRelativePath(root, p).Replace('\\', '/')).OrderBy(p => p, StringComparer.Ordinal).ToArray();

    [Fact]
    public void Quick_TakesOnlyExecutableScriptAndLibraryFormats_AndSkipsBrowserCaches()
    {
        using var tmp = new TempDir();
        tmp.WriteText("a.exe", "x");
        tmp.WriteText("b.DLL", "x");
        tmp.WriteText("c.ps1", "x");
        tmp.WriteText("link.lnk", "x");
        foreach (var junk in new[] { "d.txt", "e.log", "f.json", "g.png", "h.mp4", "i.html", "j.url", "k.dat" })
        {
            tmp.WriteText(junk, "x");
        }

        tmp.WriteText(Path.Combine("Chrome", "Cache", "cached.exe"), "x");
        tmp.WriteText(Path.Combine("App", "GPUCache", "data.dll"), "x");
        tmp.WriteText(Path.Combine("App", "Code Cache", "js.js"), "x");
        tmp.WriteText(Path.Combine("App", "bin", "tool.exe"), "x");

        var found = Names(ScanFileEnumerator.Enumerate([new ScanRoot(tmp.Path)], EnumerationMode.Quick), tmp.Path);

        Assert.Equal(["App/bin/tool.exe", "a.exe", "b.DLL", "c.ps1", "link.lnk"], found);
    }

    [Fact]
    public void Full_TakesEveryFile()
    {
        using var tmp = new TempDir();
        tmp.WriteText("a.exe", "x");
        tmp.WriteText("b.txt", "x");
        tmp.WriteText(Path.Combine("Cache", "c.dat"), "x");

        Assert.Equal(3, ScanFileEnumerator.Enumerate([new ScanRoot(tmp.Path)], EnumerationMode.Full).Count());
    }

    [Fact]
    public void ReparsePoints_AreNotFollowed_SoLoopsAndDuplicatesDoNotAppear()
    {
        using var tmp = new TempDir();
        var real = Path.Combine(tmp.Path, "real");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "tool.exe"), "x");
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(tmp.Path, "All Users"), real);
            Directory.CreateSymbolicLink(Path.Combine(real, "loop"), tmp.Path); // петля назад к корню
            File.CreateSymbolicLink(Path.Combine(tmp.Path, "alias.exe"), Path.Combine(real, "tool.exe"));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return; // создание ссылок недоступно в этой среде
        }

        var found = Names(ScanFileEnumerator.Enumerate([new ScanRoot(tmp.Path)], EnumerationMode.Full), tmp.Path);

        Assert.Equal(["real/tool.exe"], found);
    }

    [Fact]
    public void ExcludedDirectories_AreSkipped()
    {
        using var tmp = new TempDir();
        tmp.WriteText(Path.Combine("Sentinel", "Quarantine", "q.bin"), "x");
        tmp.WriteText("keep.exe", "x");

        var found = Names(ScanFileEnumerator.Enumerate([new ScanRoot(tmp.Path)], EnumerationMode.Full, [Path.Combine(tmp.Path, "Sentinel")]), tmp.Path);

        Assert.Equal(["keep.exe"], found);
    }

    [Fact]
    public void MaxDepth_LimitsRecursion()
    {
        using var tmp = new TempDir();
        tmp.WriteText("top.exe", "x");
        tmp.WriteText(Path.Combine("a", "one.exe"), "x");
        tmp.WriteText(Path.Combine("a", "b", "two.exe"), "x");

        Assert.Equal(["a/one.exe", "top.exe"], Names(ScanFileEnumerator.Enumerate([new ScanRoot(tmp.Path, 1)], EnumerationMode.Quick), tmp.Path));
    }

    [Theory]
    [InlineData("csrss.exe", true)]
    [InlineData("LSASS.EXE", true)]
    [InlineData("smss.exe", true)]
    [InlineData("wininit.exe", true)]
    [InlineData("services.exe", true)]
    [InlineData("explorer.exe", true)]
    [InlineData("notepad.exe", false)]
    public void SelfProtection_ProtectedImageNames(string name, bool expected) => Assert.Equal(expected, SelfProtection.IsProtectedImageName(name));

    [Fact]
    public void SelfProtection_OwnDirectoriesAndKernelFiles()
    {
        Assert.True(SelfProtection.IsProtectedFile(@"C:\Program Files\Sentinel\Sentinel.Service.exe"));
        Assert.True(SelfProtection.IsProtectedFile(@"C:\ProgramData\Sentinel\Quarantine\x.bin"));
        Assert.True(SelfProtection.IsProtectedFile(@"C:\Windows\System32\ntoskrnl.exe"));
        Assert.False(SelfProtection.IsProtectedFile(@"C:\Users\Bob\Downloads\tool.exe"));
        Assert.True(SelfProtection.IsOwnImageName("Sentinel.Service.exe"));
    }

    [Fact]
    public void VerdictCache_SkipsUnchangedFiles_PersistsAtomically_AndInvalidatesOnChange()
    {
        using var tmp = new TempDir();
        var file = tmp.WriteText("a.exe", "hello");
        var cachePath = Path.Combine(tmp.Path, "scan_cache.bin");

        var cache = new ScanVerdictCache(cachePath, "fp1");
        Assert.False(cache.IsKnownClean(file));
        cache.MarkClean(file);
        Assert.True(cache.IsKnownClean(file));
        cache.Save();
        Assert.False(File.Exists(cachePath + ".tmp"));

        var reloaded = new ScanVerdictCache(cachePath, "fp1");
        Assert.True(reloaded.IsKnownClean(file));

        File.WriteAllText(file, "changed!");
        Assert.False(reloaded.IsKnownClean(file));

        // Новые правила или базы — весь кэш недействителен.
        Assert.False(new ScanVerdictCache(cachePath, "fp2").IsKnownClean(file));
    }

    [Fact]
    public void VerdictCache_CorruptFile_IsIgnored()
    {
        using var tmp = new TempDir();
        var path = Path.Combine(tmp.Path, "scan_cache.bin");
        File.WriteAllBytes(path, [1, 2, 3]);
        Assert.Equal(0, new ScanVerdictCache(path, "x").Count);
    }

    [Fact]
    public void Fingerprint_ChangesWhenRulesChange()
    {
        using var tmp = new TempDir();
        var rules = Path.Combine(tmp.Path, "rules");
        Directory.CreateDirectory(rules);
        File.WriteAllText(Path.Combine(rules, "a.yar"), "rule a {}");
        var before = ScanVerdictCache.ComputeFingerprint(rules);
        File.WriteAllText(Path.Combine(rules, "b.yar"), "rule b {}");
        Assert.NotEqual(before, ScanVerdictCache.ComputeFingerprint(rules));
    }
}
