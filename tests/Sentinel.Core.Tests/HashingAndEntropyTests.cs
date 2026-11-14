using System.Text;
using Sentinel.Core.Analysis;
using Sentinel.Core.Hashing;

namespace Sentinel.Core.Tests;

public class FileHasherTests
{
    [Fact]
    public void Sha256_OfEmptyInput_MatchesKnownVector()
    {
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", FileHasher.ComputeSha256(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Sha256_OfAbc_MatchesFips180Vector()
    {
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", FileHasher.ComputeSha256("abc"u8));
    }

    [Fact]
    public async Task Sha256_FileStreamAndAsync_AgreeOnLargeFile()
    {
        using var tmp = new TempDir();
        var data = new byte[3 * 1024 * 1024 + 17];
        new Random(42).NextBytes(data);
        var path = tmp.Write("big.bin", data);

        var expected = FileHasher.ComputeSha256(data);
        Assert.Equal(expected, FileHasher.ComputeSha256(path));
        Assert.Equal(expected, await FileHasher.ComputeSha256Async(path));
        using var ms = new MemoryStream(data);
        Assert.Equal(expected, FileHasher.ComputeSha256(ms));
    }

    [Fact]
    public void Sha256_CanReadFileOpenedForWritingByAnotherHandle()
    {
        using var tmp = new TempDir();
        var path = tmp.WriteText("locked.txt", "abc");
        using var writer = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", FileHasher.ComputeSha256(path));
    }
}

public class EntropyCalculatorTests
{
    [Fact]
    public void Empty_IsZero() => Assert.Equal(0.0, EntropyCalculator.Calculate(ReadOnlySpan<byte>.Empty));

    [Fact]
    public void SingleRepeatedByte_IsZero() => Assert.Equal(0.0, EntropyCalculator.Calculate(new byte[1000]), 10);

    [Fact]
    public void TwoEquallyLikelySymbols_IsOneBit()
    {
        var data = Enumerable.Range(0, 1000).Select(i => (byte)(i % 2)).ToArray();
        Assert.Equal(1.0, EntropyCalculator.Calculate(data), 10);
    }

    [Fact]
    public void AllByteValuesUniform_IsEightBits()
    {
        var data = Enumerable.Range(0, 256 * 4).Select(i => (byte)i).ToArray();
        Assert.Equal(8.0, EntropyCalculator.Calculate(data), 10);
    }

    [Fact]
    public void RandomData_IsAboveHighEntropyThreshold_TextIsBelow()
    {
        var random = new byte[64 * 1024];
        new Random(7).NextBytes(random);
        var text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("The quick brown fox jumps over the lazy dog. ", 500)));

        Assert.True(EntropyCalculator.Calculate(random) > 7.9);
        Assert.True(EntropyCalculator.Calculate(text) < 5.0);
    }

    [Fact]
    public void StreamAndSpan_GiveSameResult_AndMaxBytesLimitsInput()
    {
        var data = new byte[10_000];
        new Random(3).NextBytes(data);
        Array.Clear(data, 5000, 5000);

        using var ms = new MemoryStream(data);
        Assert.Equal(EntropyCalculator.Calculate(data), EntropyCalculator.Calculate(ms), 10);

        using var ms2 = new MemoryStream(data);
        Assert.Equal(EntropyCalculator.Calculate(data.AsSpan(0, 5000)), EntropyCalculator.Calculate(ms2, 5000), 10);
    }

    [Fact]
    public void Blocks_LocateEncryptedRegion()
    {
        var data = new byte[3 * 4096];
        new Random(5).NextBytes(data.AsSpan(4096, 4096));
        var blocks = EntropyCalculator.CalculateBlocks(data);

        Assert.Equal(3, blocks.Count);
        Assert.Equal(0.0, blocks[0], 10);
        Assert.True(blocks[1] > 7.9);
        Assert.Equal(0.0, blocks[2], 10);
    }
}
