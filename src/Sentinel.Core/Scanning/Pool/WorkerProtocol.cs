using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.Scanning.Pool;

/// <summary>Сообщение между координатором пула и рабочим процессом. Передаётся только по Named Pipe (stdout не используется).</summary>
public sealed class WorkerMessage
{
    /// <summary><c>hello</c>, <c>scan</c>, <c>result</c>, <c>quit</c>.</summary>
    public string Type { get; set; } = string.Empty;

    public long Id { get; set; }

    public string? Path { get; set; }

    public FileScanResult? Result { get; set; }

    public string? Error { get; set; }

    public int ProcessId { get; set; }
}

/// <summary>Кадры «длина (int32 LE) + JSON UTF-8» поверх потока канала.</summary>
public static class WorkerProtocol
{
    public const int MaxMessageBytes = 16 * 1024 * 1024;

    private static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
    };

    public static async Task WriteAsync(Stream stream, WorkerMessage message, CancellationToken cancellationToken = default)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Следующее сообщение; <c>null</c> — собеседник закрыл канал между сообщениями.</summary>
    public static async Task<WorkerMessage?> ReadAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        var header = new byte[4];
        var read = await ReadFullAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        if (read < header.Length)
        {
            throw new IOException("Канал закрыт посреди заголовка сообщения.");
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxMessageBytes)
        {
            throw new InvalidDataException($"Недопустимая длина сообщения: {length}.");
        }

        var body = new byte[length];
        if (await ReadFullAsync(stream, body, cancellationToken).ConfigureAwait(false) < length)
        {
            throw new IOException("Канал закрыт посреди сообщения.");
        }

        return JsonSerializer.Deserialize<WorkerMessage>(body, Json) ?? throw new InvalidDataException("Пустое сообщение.");
    }

    private static async Task<int> ReadFullAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }
}
