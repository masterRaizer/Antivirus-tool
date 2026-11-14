using System.Text;
using Sentinel.Core.Detection;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Tests;

public class EicarTests
{
    [Fact]
    public void TestFile_Is68BytesWithKnownHash()
    {
        var bytes = Eicar.CreateTestFileBytes();
        Assert.Equal(68, bytes.Length);
        // Официальный SHA-256 файла eicar.com
        Assert.Equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", Hashing.FileHasher.ComputeSha256(bytes));
    }

    [Fact]
    public void Exact_IsDetected() => Assert.True(Eicar.IsEicar(Eicar.CreateTestFileBytes()));

    [Theory]
    [InlineData(" ")]
    [InlineData("\r\n")]
    [InlineData("\t\t  \n\x1A")]
    public void TrailingWhitespace_IsAllowed(string tail) =>
        Assert.True(Eicar.IsEicar([.. Eicar.CreateTestFileBytes(), .. Encoding.ASCII.GetBytes(tail)]));

    [Fact]
    public void TrailingNonWhitespace_IsRejected() =>
        Assert.False(Eicar.IsEicar([.. Eicar.CreateTestFileBytes(), (byte)'x']));

    [Fact]
    public void LongerThan128Bytes_IsRejected() =>
        Assert.False(Eicar.IsEicar([.. Eicar.CreateTestFileBytes(), .. Enumerable.Repeat((byte)' ', 61)]));

    [Fact]
    public void Exactly128Bytes_IsAccepted() =>
        Assert.True(Eicar.IsEicar([.. Eicar.CreateTestFileBytes(), .. Enumerable.Repeat((byte)' ', 60)]));

    [Fact]
    public void NotAtStart_IsRejected() =>
        Assert.False(Eicar.IsEicar([(byte)' ', .. Eicar.CreateTestFileBytes()]));

    [Fact]
    public void Truncated_IsRejected() =>
        Assert.False(Eicar.IsEicar(Eicar.CreateTestFileBytes().AsSpan(0, 67)));

    [Fact]
    public void File_IsDetected_AndLargeFileIsNot()
    {
        using var tmp = new TempDir();
        Assert.True(Eicar.IsEicarFile(tmp.Write("eicar.com", Eicar.CreateTestFileBytes())));
        Assert.False(Eicar.IsEicarFile(tmp.Write("big.bin", [.. Eicar.CreateTestFileBytes(), .. new byte[4096]])));
    }

    [Fact]
    public void RepositoryRule_DetectsEicar_AndRespectsSpecLimits()
    {
        var engine = new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory));
        Assert.Contains(engine.Scan(Eicar.CreateTestFileBytes()), m => m.RuleId == "SNT-TEST-0001");
        Assert.DoesNotContain(engine.Scan([(byte)'x', .. Eicar.CreateTestFileBytes()]), m => m.RuleId == "SNT-TEST-0001");
        Assert.DoesNotContain(engine.Scan([.. Eicar.CreateTestFileBytes(), .. new byte[100]]), m => m.RuleId == "SNT-TEST-0001");
    }
}
