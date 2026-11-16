using System.Buffers.Binary;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;

namespace Sentinel.Core.Ipc;

public enum IpcMessageKind
{
    Request,
    Response,
    Event,
}

/// <summary>
/// Конверт протокола. Запрос и ответ связаны полем <see cref="Id"/>; событие — рассылка сервера без ответа.
/// На канале сообщение — это 4 байта длины (little-endian) и JSON в UTF-8.
/// </summary>
public sealed record IpcMessage
{
    public IpcMessageKind Kind { get; init; }
    public required string Type { get; init; }
    public long Id { get; init; }
    public JsonElement? Payload { get; init; }
    public string? Error { get; init; }
}

/// <summary>Аргументы запросов.</summary>
public sealed record IdArgs(string Id, bool Overwrite = false);

public sealed record ToggleArgs(bool Enabled);

public sealed record ResolveThreatArgs(string Id, Realtime.ThreatDecision Decision);

public sealed record ExportReportArgs(string Id, ReportFormat Format);

public sealed record StartupArgs(bool Refresh);

public sealed record ScanRemovableArgs(string? PathOrDrive);

/// <summary>Сведения о сервере, которыми стороны обмениваются при подключении.</summary>
public sealed record HelloInfo(int ProtocolVersion, string Product);

public static class IpcProtocol
{
    public const string DefaultPipeName = "Sentinel.Service.v1";
    public const int Version = 1;

    /// <summary>Предел размера запроса клиента: служба не выделяет память по требованию чужого процесса.</summary>
    public const int MaxRequestBytes = 1 * 1024 * 1024;

    /// <summary>Предел размера сообщения сервера (отчёт HTML может быть большим).</summary>
    public const int MaxResponseBytes = 64 * 1024 * 1024;

    // Запросы.
    public const string Hello = "hello";
    public const string GetStatus = "status.get";
    public const string SetRealtime = "realtime.set";
    public const string StartScan = "scan.start";
    public const string PauseScan = "scan.pause";
    public const string ResumeScan = "scan.resume";
    public const string StopScan = "scan.stop";
    public const string GetTelemetry = "telemetry.history";
    public const string GetProcesses = "processes.get";
    public const string GetThreats = "threats.get";
    public const string ResolveThreat = "threats.resolve";
    public const string GetQuarantine = "quarantine.get";
    public const string RestoreQuarantine = "quarantine.restore";
    public const string GetRollback = "rollback.get";
    public const string UndoRollback = "rollback.undo";
    public const string GetStartup = "startup.get";
    public const string CleanStartup = "startup.clean";
    public const string GetReports = "reports.get";
    public const string ExportReport = "reports.export";
    public const string DeleteQuarantine = "quarantine.delete";
    public const string GetSettings = "settings.get";
    public const string SaveSettings = "settings.save";
    public const string UpdateDatabases = "databases.update";
    public const string GetBehavioralStatus = "behavioral.status";
    public const string ScanRemovable = "behavioral.scanusb";

    // События.
    public const string ScanProgressEvent = "event.scan";
    public const string TelemetryEvent = "event.telemetry";
    public const string ThreatRaisedEvent = "event.threat.raised";
    public const string ThreatUpdatedEvent = "event.threat.updated";
    public const string StatusEvent = "event.status";

    public static JsonSerializerOptions Json { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
    };

    public static JsonElement ToElement<T>(T value) => JsonSerializer.SerializeToElement(value, Json);

    public static T FromElement<T>(JsonElement? element, string type)
    {
        if (element is not { } e || e.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            throw new IpcProtocolException($"Сообщение '{type}' не содержит данных.");
        }

        try
        {
            return e.Deserialize<T>(Json) ?? throw new IpcProtocolException($"Сообщение '{type}' содержит пустые данные.");
        }
        catch (JsonException ex)
        {
            throw new IpcProtocolException($"Сообщение '{type}' имеет неверный формат: {ex.Message}");
        }
    }

    /// <summary>Записывает одно сообщение. Вызовы для одного потока должны быть сериализованы вызывающей стороной.</summary>
    public static async Task WriteAsync(Stream stream, IpcMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(message);
        var body = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Читает одно сообщение; <c>null</c> — собеседник закрыл канал на границе сообщения.</summary>
    public static async Task<IpcMessage?> ReadAsync(Stream stream, int maxBytes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[4];
        var read = await ReadFullAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        if (read < header.Length)
        {
            throw new IpcProtocolException("Канал закрыт посреди заголовка сообщения.");
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maxBytes)
        {
            throw new IpcProtocolException($"Недопустимый размер сообщения: {length} байт (предел {maxBytes}).");
        }

        var body = new byte[length];
        if (await ReadFullAsync(stream, body, cancellationToken).ConfigureAwait(false) < length)
        {
            throw new IpcProtocolException("Канал закрыт посреди сообщения.");
        }

        try
        {
            var message = JsonSerializer.Deserialize<IpcMessage>(body, Json);
            return message is null || string.IsNullOrEmpty(message.Type)
                ? throw new IpcProtocolException("Сообщение без типа.")
                : message;
        }
        catch (JsonException ex)
        {
            throw new IpcProtocolException($"Сообщение не является корректным JSON: {ex.Message}");
        }
    }

    private static async Task<int> ReadFullAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                break;
            }

            total += n;
        }

        return total;
    }
}

/// <summary>Нарушение протокола: соединение с таким собеседником разрывается.</summary>
public sealed class IpcProtocolException : Exception
{
    public IpcProtocolException()
    {
    }

    public IpcProtocolException(string message)
        : base(message)
    {
    }

    public IpcProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Сервер ответил ошибкой на запрос (операция не выполнена, соединение исправно).</summary>
public sealed class IpcRemoteException : Exception
{
    public IpcRemoteException()
    {
    }

    public IpcRemoteException(string message)
        : base(message)
    {
    }

    public IpcRemoteException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
