using System.Buffers.Binary;
using Sentinel.Core.Pe;
using Sentinel.Core.Testing;

namespace Sentinel.Core.Tests;

public class PeParserTests
{
    [Fact]
    public void Parses_Pe32Plus_Executable()
    {
        var result = PeParser.Parse(SyntheticArtifacts.BuildPe());

        Assert.True(result.IsPe, result.Error);
        var info = result.Info!;
        Assert.Equal(PeMachine.Amd64, info.Machine);
        Assert.True(info.Is64Bit);
        Assert.False(info.IsDll);
        Assert.Equal(PeSubsystem.WindowsCui, info.Subsystem);
        Assert.Equal(0x1_4000_0000UL, info.ImageBase);
        Assert.Equal(16, info.DataDirectories.Count);
        Assert.False(info.HasAuthenticodeDirectory);
        Assert.Equal(new[] { ".text", ".data" }, info.Sections.Select(s => s.Name));
        Assert.Equal(".text", info.EntryPointSection?.Name);
        Assert.True(info.Sections[0].IsExecutable);
        Assert.False(info.Sections[0].IsWritable);
        Assert.True(info.Sections[1].IsWritable);
        Assert.Equal(0, info.OverlaySize);
        Assert.Empty(info.Anomalies);
    }

    [Fact]
    public void Parses_Pe32_Dll()
    {
        var result = PeParser.Parse(SyntheticArtifacts.BuildPe(new() { Is64Bit = false, IsDll = true }));

        Assert.True(result.IsPe, result.Error);
        Assert.Equal(PeMachine.I386, result.Info!.Machine);
        Assert.False(result.Info.Is64Bit);
        Assert.True(result.Info.IsDll);
        Assert.Equal(0x0040_0000UL, result.Info.ImageBase);
    }

    [Fact]
    public void HighEntropyExecutableSection_IsReportedAsPacked()
    {
        var info = PeParser.Parse(SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x4000 })).Info!;

        Assert.True(info.Sections[0].Entropy > 7.5);
        Assert.Contains(info.Anomalies, a => a.Contains("высокую энтропию", StringComparison.Ordinal));
    }

    [Fact]
    public void WritableExecutableSection_AndEntryPoint_AreAnomalies()
    {
        var info = PeParser.Parse(SyntheticArtifacts.BuildPe(new() { WritableText = true })).Info!;

        Assert.Contains(info.Anomalies, a => a.Contains("W+X", StringComparison.Ordinal));
        Assert.Contains(info.Anomalies, a => a.Contains("записываемой секции", StringComparison.Ordinal));
    }

    [Fact]
    public void EntryPointOutsideSections_IsAnomaly()
    {
        var info = PeParser.Parse(SyntheticArtifacts.BuildPe(new() { EntryPointOverride = 0x00F0_0000 })).Info!;
        Assert.Null(info.EntryPointSection);
        Assert.Contains(info.Anomalies, a => a.Contains("вне секций", StringComparison.Ordinal));
    }

    [Fact]
    public void Overlay_IsMeasured()
    {
        var info = PeParser.Parse(SyntheticArtifacts.BuildPe(new() { OverlaySize = 777 })).Info!;
        Assert.Equal(777, info.OverlaySize);
        Assert.Contains(info.Anomalies, a => a.Contains("оверлей", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AuthenticodeDirectoryAtEnd_IsNotCountedAsOverlay()
    {
        var pe = SyntheticArtifacts.BuildPe(new() { OverlaySize = 512 });
        var withCert = PatchSecurityDirectory(pe, offset: (uint)(pe.Length - 512), size: 512);
        var info = PeParser.Parse(withCert).Info!;

        Assert.True(info.HasAuthenticodeDirectory);
        Assert.Equal(0, info.OverlaySize);
    }

    [Theory]
    [InlineData(new byte[0], "64")]
    [InlineData(new byte[] { 0x4D, 0x5A }, "64")]
    public void TooSmall_IsNotPe(byte[] data, string reasonFragment)
    {
        var result = PeParser.Parse(data);
        Assert.False(result.IsPe);
        Assert.Contains(reasonFragment, result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingMz_IsNotPe()
    {
        var pe = SyntheticArtifacts.BuildPe();
        pe[0] = (byte)'Z';
        Assert.Contains("MZ", PeParser.Parse(pe).Error, StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidLfanew_IsNotPe()
    {
        var pe = SyntheticArtifacts.BuildPe();
        BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C), int.MaxValue);
        Assert.Contains("e_lfanew", PeParser.Parse(pe).Error, StringComparison.Ordinal);
    }

    [Fact]
    public void BadPeSignature_IsNotPe()
    {
        var pe = SyntheticArtifacts.BuildPe();
        pe[0x41] = (byte)'X';
        Assert.False(PeParser.Parse(pe).IsPe);
    }

    [Fact]
    public void TooManySections_IsRejected()
    {
        var pe = SyntheticArtifacts.BuildPe();
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x40 + 6), 5000);
        Assert.Contains("секций", PeParser.Parse(pe).Error, StringComparison.Ordinal);
    }

    [Fact]
    public void SectionBeyondEndOfFile_IsAnomalyNotCrash()
    {
        var pe = SyntheticArtifacts.BuildPe();
        var truncated = pe.AsSpan(0, pe.Length - 0x100).ToArray();
        var result = PeParser.Parse(truncated);
        Assert.True(result.IsPe);
        Assert.Contains(result.Info!.Anomalies, a => a.Contains("за пределы файла", StringComparison.Ordinal));
    }

    [Fact]
    public void Fuzz_TruncationsAndBitFlips_NeverThrow()
    {
        var pe = SyntheticArtifacts.BuildPe(new() { OverlaySize = 64 });
        for (var len = 0; len < pe.Length; len += 7)
        {
            _ = PeParser.Parse(pe.AsSpan(0, len));
        }

        var rng = new Random(99);
        for (var i = 0; i < 2000; i++)
        {
            var copy = (byte[])pe.Clone();
            for (var j = 0; j < 4; j++)
            {
                copy[rng.Next(0, 0x400)] = (byte)rng.Next(256);
            }

            _ = PeParser.Parse(copy);
        }
    }

    [Fact]
    public void ParseFile_ReadsFromDisk()
    {
        using var tmp = new TempDir();
        var path = tmp.Write("a.exe", SyntheticArtifacts.BuildPe());
        Assert.True(PeParser.ParseFile(path).IsPe);
    }

    private static byte[] PatchSecurityDirectory(byte[] pe, uint offset, uint size)
    {
        // PE32+: data directories начинаются со смещения 112 в Optional Header; индекс 4 — Security.
        var dirOffset = 0x40 + 24 + 112 + (4 * 8);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirOffset), offset);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirOffset + 4), size);
        return pe;
    }
}
