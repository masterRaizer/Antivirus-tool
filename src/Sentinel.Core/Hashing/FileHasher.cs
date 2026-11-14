using System.Security.Cryptography;

namespace Sentinel.Core.Hashing;

/// <summary>
/// Потоковый расчёт SHA-256. Файл читается блоками, поэтому размер файла не ограничен памятью.
/// Файл открывается с FileShare.ReadWrite | Delete, чтобы не блокировать работающие процессы.
/// </summary>
public static class FileHasher
{
    private const int BufferSize = 1 << 16;

    public static string ComputeSha256(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        using var stream = OpenShared(path);
        return ComputeSha256(stream);
    }

    public static string ComputeSha256(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    public static string ComputeSha256(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    public static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        await using var stream = OpenShared(path, useAsync: true);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    internal static FileStream OpenShared(string path, bool useAsync = false) =>
        new(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.ReadWrite | FileShare.Delete,
            BufferSize = BufferSize,
            Options = useAsync ? FileOptions.Asynchronous | FileOptions.SequentialScan : FileOptions.SequentialScan,
        });
}
