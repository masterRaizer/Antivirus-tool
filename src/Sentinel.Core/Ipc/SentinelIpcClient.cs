using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text.Json;
using Sentinel.Core.Realtime;

namespace Sentinel.Core.Ipc;

/// <summary>
/// Клиент службы: реализует <see cref="ISentinelBackend"/> запросами по именованному каналу
/// и превращает рассылку сервера в события. После разрыва соединения все ожидающие запросы
/// завершаются ошибкой, а <see cref="Disconnected"/> сообщает интерфейсу о переходе в автономный режим.
/// </summary>
public sealed class SentinelIpcClient : ISentinelBackend, IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement?>> _pending = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _reader;
    private long _nextId;
    private int _disconnected;

    /// <summary>Клиент поверх уже установленного двустороннего потока (канал или тестовая пара потоков).</summary>
    public SentinelIpcClient(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _stream = stream;
        _reader = Task.Run(ReadLoopAsync);
    }

    public event Action<ScanProgress>? ScanProgressChanged;

    public event Action<TelemetrySample>? TelemetryUpdated;

    public event Action<ThreatEvent>? ThreatRaised;

    public event Action<ThreatEvent>? ThreatUpdated;

    public event Action<ServiceStatus>? StatusChanged;

    /// <summary>Соединение потеряно (служба остановлена или канал закрыт).</summary>
    public event Action<string>? Disconnected;

    public bool IsConnected => Volatile.Read(ref _disconnected) == 0;

    /// <summary>
    /// Подключается к службе. Возвращает <c>null</c>, если служба не запущена или не ответила
    /// за <paramref name="timeout"/> — вызывающая сторона переходит в автономный режим.
    /// </summary>
    public static async Task<SentinelIpcClient?> TryConnectAsync(
        string pipeName = IpcProtocol.DefaultPipeName, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        SentinelIpcClient? client = null;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(2));
            await pipe.ConnectAsync(cts.Token).ConfigureAwait(false);
            client = new SentinelIpcClient(pipe);
            var hello = await client.RequestAsync<HelloInfo>(IpcProtocol.Hello, null, cts.Token).ConfigureAwait(false);
            if (hello.ProtocolVersion != IpcProtocol.Version)
            {
                await client.DisposeAsync().ConfigureAwait(false);
                return null;
            }

            return client;
        }
        catch (Exception ex) when (ex is OperationCanceledException or TimeoutException or IOException
            or UnauthorizedAccessException or IpcProtocolException or IpcRemoteException)
        {
            if (client is not null)
            {
                await client.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
    }

    public Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<ServiceStatus>(IpcProtocol.GetStatus, null, cancellationToken);

    public Task<OperationResult> SetRealtimeProtectionAsync(bool enabled, CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.SetRealtime, new ToggleArgs(enabled), cancellationToken);

    public Task<OperationResult> StartScanAsync(ScanRequest request, CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.StartScan, request, cancellationToken);

    public Task<OperationResult> PauseScanAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.PauseScan, null, cancellationToken);

    public Task<OperationResult> ResumeScanAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.ResumeScan, null, cancellationToken);

    public Task<OperationResult> StopScanAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.StopScan, null, cancellationToken);

    public async Task<IReadOnlyList<TelemetrySample>> GetTelemetryHistoryAsync(CancellationToken cancellationToken = default) =>
        await RequestAsync<TelemetrySample[]>(IpcProtocol.GetTelemetry, null, cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken cancellationToken = default) =>
        await RequestAsync<ProcessInfo[]>(IpcProtocol.GetProcesses, null, cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<ThreatEvent>> GetThreatsAsync(CancellationToken cancellationToken = default) =>
        await RequestAsync<ThreatEvent[]>(IpcProtocol.GetThreats, null, cancellationToken).ConfigureAwait(false);

    public Task<ThreatEvent> ResolveThreatAsync(string id, ThreatDecision decision, CancellationToken cancellationToken = default) =>
        RequestAsync<ThreatEvent>(IpcProtocol.ResolveThreat, new ResolveThreatArgs(id, decision), cancellationToken);

    public async Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync(CancellationToken cancellationToken = default) =>
        await RequestAsync<QuarantineItem[]>(IpcProtocol.GetQuarantine, null, cancellationToken).ConfigureAwait(false);

    public Task<OperationResult> RestoreQuarantineAsync(string id, bool overwrite = false, CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.RestoreQuarantine, new IdArgs(id, overwrite), cancellationToken);

    public async Task<IReadOnlyList<RollbackItem>> GetRollbackAsync(CancellationToken cancellationToken = default) =>
        await RequestAsync<RollbackItem[]>(IpcProtocol.GetRollback, null, cancellationToken).ConfigureAwait(false);

    public Task<OperationResult> UndoRollbackAsync(string id, CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.UndoRollback, new IdArgs(id), cancellationToken);

    public Task<StartupSnapshot> GetStartupAsync(bool refresh = false, CancellationToken cancellationToken = default) =>
        RequestAsync<StartupSnapshot>(IpcProtocol.GetStartup, new StartupArgs(refresh), cancellationToken);

    public Task<OperationResult> CleanStartupItemAsync(string key, CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.CleanStartup, new IdArgs(key), cancellationToken);

    public async Task<IReadOnlyList<ReportSummary>> GetReportsAsync(CancellationToken cancellationToken = default) =>
        await RequestAsync<ReportSummary[]>(IpcProtocol.GetReports, null, cancellationToken).ConfigureAwait(false);

    public Task<ReportExport> ExportReportAsync(string id, ReportFormat format, CancellationToken cancellationToken = default) =>
        RequestAsync<ReportExport>(IpcProtocol.ExportReport, new ExportReportArgs(id, format), cancellationToken);

    public Task<OperationResult> DeleteQuarantineAsync(string id, CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.DeleteQuarantine, new IdArgs(id), cancellationToken);

    public Task<SettingsSnapshot> GetSettingsAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<SettingsSnapshot>(IpcProtocol.GetSettings, null, cancellationToken);

    public Task<OperationResult> SaveSettingsAsync(SettingsUpdate update, CancellationToken cancellationToken = default) =>
        RequestAsync<OperationResult>(IpcProtocol.SaveSettings, update, cancellationToken);

    /// <summary>Запускает обновление баз в службе; ответ приходит сразу, итог — в статусе баз (<see cref="GetSettingsAsync"/>).</summary>
    public Task<ThreatIntel.DatabaseStatus> UpdateDatabasesAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<ThreatIntel.DatabaseStatus>(IpcProtocol.UpdateDatabases, null, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        await _stream.DisposeAsync().ConfigureAwait(false);
        try
        {
            await _reader.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _cts.Dispose();
        _writeLock.Dispose();
    }

    // ---- Транспорт -------------------------------------------------------------

    private async Task<T> RequestAsync<T>(string type, object? args, CancellationToken cancellationToken)
    {
        if (!IsConnected)
        {
            throw new IOException("Соединение со службой Sentinel потеряно.");
        }

        var id = Interlocked.Increment(ref _nextId);
        var completion = new TaskCompletionSource<JsonElement?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = completion;
        try
        {
            var message = new IpcMessage
            {
                Kind = IpcMessageKind.Request,
                Type = type,
                Id = id,
                Payload = args is null ? null : JsonSerializer.SerializeToElement(args, args.GetType(), IpcProtocol.Json),
            };
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await IpcProtocol.WriteAsync(_stream, message, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }

            var payload = await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return IpcProtocol.FromElement<T>(payload, type);
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    private async Task ReadLoopAsync()
    {
        var reason = "Служба закрыла соединение.";
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var message = await IpcProtocol.ReadAsync(_stream, IpcProtocol.MaxResponseBytes, _cts.Token).ConfigureAwait(false);
                if (message is null)
                {
                    break;
                }

                if (message.Kind == IpcMessageKind.Response)
                {
                    if (_pending.TryGetValue(message.Id, out var completion))
                    {
                        if (message.Error is not null)
                        {
                            completion.TrySetException(new IpcRemoteException(message.Error));
                        }
                        else
                        {
                            completion.TrySetResult(message.Payload);
                        }
                    }
                }
                else if (message.Kind == IpcMessageKind.Event)
                {
                    RaiseEvent(message);
                }
            }
        }
        catch (OperationCanceledException)
        {
            reason = "Соединение закрыто.";
        }
        catch (Exception ex) when (ex is IOException or IpcProtocolException or ObjectDisposedException)
        {
            reason = ex.Message;
        }

        Interlocked.Exchange(ref _disconnected, 1);
        foreach (var (_, completion) in _pending)
        {
            completion.TrySetException(new IOException("Соединение со службой Sentinel потеряно: " + reason));
        }

        if (!_cts.IsCancellationRequested)
        {
            Disconnected?.Invoke(reason);
        }
    }

    private void RaiseEvent(IpcMessage message)
    {
        // Событие неизвестного типа пропускается: более новая служба может знать больше клиента.
        switch (message.Type)
        {
            case IpcProtocol.ScanProgressEvent:
                ScanProgressChanged?.Invoke(IpcProtocol.FromElement<ScanProgress>(message.Payload, message.Type));
                break;
            case IpcProtocol.TelemetryEvent:
                TelemetryUpdated?.Invoke(IpcProtocol.FromElement<TelemetrySample>(message.Payload, message.Type));
                break;
            case IpcProtocol.ThreatRaisedEvent:
                ThreatRaised?.Invoke(IpcProtocol.FromElement<ThreatEvent>(message.Payload, message.Type));
                break;
            case IpcProtocol.ThreatUpdatedEvent:
                ThreatUpdated?.Invoke(IpcProtocol.FromElement<ThreatEvent>(message.Payload, message.Type));
                break;
            case IpcProtocol.StatusEvent:
                StatusChanged?.Invoke(IpcProtocol.FromElement<ServiceStatus>(message.Payload, message.Type));
                break;
        }
    }
}
