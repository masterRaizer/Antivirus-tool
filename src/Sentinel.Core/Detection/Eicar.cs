using System.Text;

namespace Sentinel.Core.Detection;

/// <summary>
/// Стандартный антивирусный тестовый файл EICAR. По спецификации файл начинается
/// с 68-символьной строки, может дополняться только пробельными символами
/// (пробел, TAB, CR, LF, Ctrl-Z) и не превышает 128 байт.
/// Строка собирается из частей, чтобы исходный код сам не детектировался антивирусами.
/// </summary>
public static class Eicar
{
    public const int MaxFileLength = 128;
    public const string DetectionName = "EICAR-Test-File";

    private static readonly byte[] Signature = Encoding.ASCII.GetBytes(
        string.Concat(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$", "EICAR", "-STANDARD-ANTIVIRUS-TEST-", "FILE!$H+H*"));

    public static int SignatureLength => Signature.Length;

    /// <summary>Байты эталонного тестового файла EICAR (68 байт).</summary>
    public static byte[] CreateTestFileBytes() => (byte[])Signature.Clone();

    public static bool IsEicar(ReadOnlySpan<byte> content)
    {
        if (content.Length < Signature.Length || content.Length > MaxFileLength)
        {
            return false;
        }

        if (!content.StartsWith(Signature))
        {
            return false;
        }

        foreach (var b in content[Signature.Length..])
        {
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x1A))
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsEicarFile(string path)
    {
        using var stream = Hashing.FileHasher.OpenShared(path);
        if (stream.Length is < 68 or > MaxFileLength)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[MaxFileLength];
        var read = stream.ReadAtLeast(buffer, (int)stream.Length, throwOnEndOfStream: false);
        return IsEicar(buffer[..read]);
    }
}
