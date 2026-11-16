using System.Buffers.Binary;
using System.Text;
using Sentinel.Core.Protection;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Tests;

public class RemovableMediaShieldTests
{
    private const uint HasRelativePath = 0x08;
    private const uint HasWorkingDir = 0x10;
    private const uint HasArguments = 0x20;
    private const uint HasIconLocation = 0x40;
    private const uint IsUnicode = 0x80;

    private static byte[] LinkClsid =>
        [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];

    /// <summary>Строит минимальный, но валидный по [MS-SHLLINK] Unicode-ярлык из StringData (без LinkTargetIDList/LinkInfo).</summary>
    private static byte[] BuildLnk(string relativePath, string workingDir, string arguments, string icon)
    {
        using var ms = new MemoryStream();
        var header = new byte[0x4C];
        BinaryPrimitives.WriteInt32LittleEndian(header, 0x4C);
        LinkClsid.CopyTo(header, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0x14),
            HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation | IsUnicode);
        ms.Write(header);
        WriteStringData(ms, relativePath);
        WriteStringData(ms, workingDir);
        WriteStringData(ms, arguments);
        WriteStringData(ms, icon);
        return ms.ToArray();
    }

    private static void WriteStringData(Stream s, string value)
    {
        Span<byte> count = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(count, (ushort)value.Length);
        s.Write(count);
        s.Write(Encoding.Unicode.GetBytes(value));
    }

    [Fact]
    public void ShellLinkBinaryParser_ReadsUnicodeFields()
    {
        var lnk = BuildLnk(@"..\..\Windows\System32\powershell.exe", @"C:\Temp", "-enc ZQBjAA==", @"%SystemRoot%\System32\shell32.dll");
        var details = ShellLinkBinaryParser.Parse(lnk);
        Assert.NotNull(details);
        Assert.Equal(@"..\..\Windows\System32\powershell.exe", details!.RelativePath);
        Assert.Equal("-enc ZQBjAA==", details.Arguments);
        Assert.Contains("shell32.dll", details.IconLocation!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ShellLinkBinaryParser_RejectsNonLnk() =>
        Assert.Null(ShellLinkBinaryParser.Parse([0x00, 0x01, 0x02, 0x03]));

    [Fact]
    public void Scan_WeaponizedShortcut_WithIconSpoof_IsCritical()
    {
        using var tmp = new TempDir();
        var lnk = BuildLnk(@"..\..\Windows\System32\powershell.exe", "", "-enc ZQBj", @"C:\Windows\System32\shell32.dll");
        File.WriteAllBytes(Path.Combine(tmp.Path, "My Documents.lnk"), lnk);

        var findings = new RemovableMediaShield().ScanDirectory(tmp.Path);

        var finding = Assert.Single(findings, f => f.Kind == "WeaponizedShortcut");
        Assert.Equal(Severity.Critical, finding.Severity);
    }

    [Fact]
    public void Scan_CleanShortcut_IsNotFlagged()
    {
        using var tmp = new TempDir();
        var lnk = BuildLnk(@"..\game.exe", "", "", @"..\game.exe");
        File.WriteAllBytes(Path.Combine(tmp.Path, "Game.lnk"), lnk);
        Assert.Empty(new RemovableMediaShield().ScanDirectory(tmp.Path).Where(f => f.Kind == "WeaponizedShortcut"));
    }

    [Fact]
    public void Scan_AutorunInf_WithOpenDirective_IsFlagged()
    {
        using var tmp = new TempDir();
        File.WriteAllText(Path.Combine(tmp.Path, "autorun.inf"),
            "[autorun]\r\nopen=worm.exe /silent\r\nshellexecute=worm.exe\r\nicon=worm.exe,0\r\n");
        File.WriteAllText(Path.Combine(tmp.Path, "worm.exe"), "MZ");

        var findings = new RemovableMediaShield().ScanDirectory(tmp.Path);
        var autorun = Assert.Single(findings, f => f.Kind == "Autorun");
        Assert.Contains("worm.exe", autorun.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AutorunParser_ReadsOnlyAutorunSection()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(
            "[other]\r\nopen=ignored.exe\r\n[autorun]\r\nshell\\open\\command=payload.exe\r\n; comment\r\n"));
        var info = AutorunInfParser.Read(stream);
        Assert.Equal("payload.exe", info.ShellOpenCommand);
        Assert.Null(info.Open);
        Assert.Contains("payload.exe", info.Targets);
    }

    [Theory]
    [InlineData("invoice.pdf.exe", true)]
    [InlineData("photo.jpg.scr", true)]
    [InlineData("video.mp4.com", true)]
    [InlineData("report.docx", false)]
    [InlineData("setup.exe", false)]
    [InlineData("archive.tar.gz", false)]
    public void DoubleExtension_IsDetected(string name, bool expected) =>
        Assert.Equal(expected, RemovableMediaShield.IsDoubleExtension(name));

    [Fact]
    public void Scan_DoubleExtensionFile_IsHigh()
    {
        using var tmp = new TempDir();
        File.WriteAllText(Path.Combine(tmp.Path, "resume.pdf.exe"), "MZ");
        Assert.Single(new RemovableMediaShield().ScanDirectory(tmp.Path), f => f.Kind == "DoubleExtension");
    }

    [Theory]
    [InlineData(new[] { "Photos" }, new[] { "Photos.exe", "readme.txt" }, new[] { "Photos.exe" })]
    [InlineData(new[] { "Docs" }, new[] { "Docs.pdf.exe" }, new[] { "Docs.pdf.exe" })]
    [InlineData(new[] { "Photos" }, new[] { "Photos.txt" }, new string[0])]
    [InlineData(new string[0], new[] { "Photos.exe" }, new string[0])]
    public void DetectWorm_MatchesHiddenFolderLures(string[] hidden, string[] files, string[] expected) =>
        Assert.Equal(expected, RemovableMediaShield.DetectWorm(hidden, files));

    [Fact]
    public void Scan_SkipsReparsePointDirectories()
    {
        using var tmp = new TempDir();
        var real = Path.Combine(tmp.Path, "real");
        Directory.CreateDirectory(real);
        File.WriteAllBytes(Path.Combine(real, "payload.pdf.exe"), "MZ"u8.ToArray());
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(tmp.Path, "linked"), real);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return;
        }

        var findings = new RemovableMediaShield().ScanDirectory(tmp.Path);
        Assert.Single(findings, f => f.Kind == "DoubleExtension"); // только настоящий каталог, не симлинк-дубль
    }

    [Fact]
    public void Scan_RunsInjectedBinaryAnalyzer()
    {
        using var tmp = new TempDir();
        File.WriteAllText(Path.Combine(tmp.Path, "tool.exe"), "MZ");
        var shield = new RemovableMediaShield(path => path.EndsWith("tool.exe", StringComparison.Ordinal) ? Severity.Critical : null);
        Assert.Single(shield.ScanDirectory(tmp.Path), f => f.Kind == "MaliciousBinary" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void PollingWatcher_DiffNew_ReportsOnlyFreshVolumes()
    {
        var volumes = new List<RemovableVolume> { new(@"E:\", "USB", "FAT32", 1024) };
        var watcher = new PollingRemovableDriveWatcher(() => volumes.ToArray());
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Assert.Single(watcher.DiffNew(known));          // E: новый
        Assert.Empty(watcher.DiffNew(known));            // E: уже известен
        volumes.Add(new RemovableVolume(@"F:\", "USB2", "exFAT", 2048));
        var fresh = watcher.DiffNew(known);
        Assert.Single(fresh);
        Assert.Equal(@"F:\", fresh[0].RootPath);
    }
}
