using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Channels;
using Sentinel.Core.Realtime;

namespace Sentinel.Core.Ipc;

public sealed class IpcServerOptions
{
    public string PipeName { get; init; } = IpcProtocol.DefaultPipeName;

    /// <summary>
    /// Служба работает от имени SYSTEM, а интерфейс — от имени пользователя: канал открывается
    /// пользователям, прошедшим проверку подлинности (чтение/запись), полный доступ — только у SYSTEM
    /// и администраторов. Без флага канал доступен лишь текущей учётной записи.
    /// </summary>
    public bool AllowInteractiveUsers { get; init; }

    /// <summary>Сколько исходящих сообщений может накопиться у клиента, прежде чем он будет отключён.</summary>
    public int OutboundQueueLimit { get; init; } = 2048;

    /// <summary>
    /// Определение клиента для самозащиты (<see cref="IpcClientPolicy"/>). <c>null</c> — клиент без ограничений (тесты, Linux);
    /// служба в Windows передаёт <see cref="WindowsIpcClientIdentifier.Identify"/>.
    /// </summary>
    public Func<NamedPipeServerStream, IpcClientIdentity>? IdentifyClient { get; init; }

    /// <summary>Отказ клиенту в ослабляющей команде (для журнала службы).</summary>
    public Action<string>? OnDenied { get; init; }
}

/// <summary>
/// Сервер JSON-протокола поверх именованного канала. Обслуживает любое число клиентов:
/// отвечает на запросы, обращаясь к <see cref="ISentinelBackend"/>, и рассылает его события
/// (прогресс проверки, телеметрия, находки) всем подключённым.
/// </summary>
public sealed class SentinelIpcServer : IAsyncDisposable
{
    /// <summary>Сколько запросов одного клиента выполняется одновременно.</summary>
    public const int MaxConcurrentRequestsPerClient = 8;

    private readonly ISentinelBackend _backend;
    private readonly IpcServerOptions _options;
    private readonly ConcurrentDictionary<int, Connection> _connections = new();
    private readonly CancellationTokenSource _shutdown = new();
    private int _nextConnectionId;
    private int _instancesCreated;
    private bool _subscribed;

    public SentinelIpcServer(ISentinelBackend backend, IpcServerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(backend);
        _backend = backend;
        _options = options ?? new IpcServerOptions();
    }

    public string PipeName => _options.PipeName;

    public int ClientCount => _connections.Count;

    /// <summary>Журнал сбоев отдельных соединений (сервер при этом продолжает работу).</summary>
    public event Action<string>? ConnectionFaulted;

    /// <summary>Принимает подключения, пока не отменён <paramref name="cancellationToken"/>.</summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        var token = linked.Token;
        Subscribe();
        var clients = new List<Task>();
        try
        {
            while (!token.IsCancellationRequested)
            {
                var pipe = CreatePipe();
                try
                {
                    await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is OperationCanceledException or IOException)
                {
                    await pipe.DisposeAsync().ConfigureAwait(false);
                    if (ex is IOException)
                    {
                        ConnectionFaulted?.Invoke($"Подключение не установлено: {ex.Message}");
                        continue;
                    }

                    break;
                }

                clients.RemoveAll(t => t.IsCompleted);
                clients.Add(ServeAsync(pipe, token));
            }
        }
        finally
        {
            Unsubscribe();
            await Task.WhenAll(clients).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _shutdown.CancelAsync().ConfigureAwait(false);
        Unsubscribe();
        _shutdown.Dispose();
    }

    // ---- Канал -----------------------------------------------------------------

    private NamedPipeServerStream CreatePipe()
    {
        var first = Interlocked.Increment(ref _instancesCreated) == 1;
        var options = PipeOptions.Asynchronous;
        if (OperatingSystem.IsWindows())
        {
            // Первый экземпляр обязан быть первым в системе: если канал с таким именем уже создал
            // посторонний процесс (pipe squatting), сервер не запускается вместо того чтобы делить имя.
            if (first)
            {
                options |= PipeOptions.FirstPipeInstance;
            }

            return _options.AllowInteractiveUsers
                ? NamedPipeServerStreamAcl.Create(
                    _options.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, options, 0, 0, CreateServiceSecurity())
                : new NamedPipeServerStream(
                    _options.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, options | PipeOptions.CurrentUserOnly);
        }

        return new NamedPipeServerStream(
            _options.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, options | PipeOptions.CurrentUserOnly);
    }

    /// <summary>
    /// Права канала службы: <c>LocalSystem</c> и <c>Administrators</c> — полный доступ, <c>Authenticated Users</c> — чтение и запись
    /// (подключиться может интерфейс любого вошедшего пользователя, но не создать экземпляр канала), сетевой доступ запрещён.
    /// </summary>
    public static IReadOnlyList<ServicePipeRule> ServiceAccessRules { get; } =
    [
        new(ServicePipeAccount.LocalSystem, ServicePipeRights.FullControl, Allow: true),
        new(ServicePipeAccount.Administrators, ServicePipeRights.FullControl, Allow: true),
        new(ServicePipeAccount.AuthenticatedUsers, ServicePipeRights.ReadWrite, Allow: true),
        new(ServicePipeAccount.Network, ServicePipeRights.FullControl, Allow: false),
    ];

    [SupportedOSPlatform("windows")]
    public static PipeSecurity CreateServiceSecurity()
    {
        var security = new PipeSecurity();
        foreach (var rule in ServiceAccessRules)
        {
            var sid = rule.Account switch
            {
                ServicePipeAccount.LocalSystem => WellKnownSidType.LocalSystemSid,
                ServicePipeAccount.Administrators => WellKnownSidType.BuiltinAdministratorsSid,
                ServicePipeAccount.AuthenticatedUsers => WellKnownSidType.AuthenticatedUserSid,
                _ => WellKnownSidType.NetworkSid,
            };
            var rights = rule.Rights == ServicePipeRights.FullControl ? PipeAccessRights.FullControl : PipeAccessRights.ReadWrite;
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid, null), rights,
                rule.Allow ? AccessControlType.Allow : AccessControlType.Deny));
        }

        return security;
    }

    // ---- Соединение ------------------------------------------------------------

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        var id = Interlocked.Increment(ref _nextConnectionId);
        var connection = new Connection(pipe, _options.OutboundQueueLimit);
        _connections[id] = connection;
        IpcClientIdentity client;
        try
        {
            client = _options.IdentifyClient?.Invoke(pipe) ?? IpcClientIdentity.Unrestricted;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            client = new IpcClientIdentity(0, null, false, false); // не удалось определить — только безопасные команды
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        var writer = connection.PumpAsync(cts.Token);
        // Запросы одного клиента выполняются параллельно (ответ находит запрос по Id): медленный запрос — сводка автозагрузки
        // (1–3 мин), обновление баз, проверка флешки — больше не держит остальные разделы окна пустыми.
        using var slots = new SemaphoreSlim(MaxConcurrentRequestsPerClient);
        var inflight = new List<Task>();
        try
        {
            while (!cts.IsCancellationRequested)
            {
                var message = await IpcProtocol.ReadAsync(pipe, IpcProtocol.MaxRequestBytes, cts.Token).ConfigureAwait(false);
                if (message is null)
                {
                    break;
                }

                if (message.Kind != IpcMessageKind.Request)
                {
                    throw new IpcProtocolException("Клиент может отправлять только запросы.");
                }

                await slots.WaitAsync(cts.Token).ConfigureAwait(false);
                inflight.RemoveAll(t => t.IsCompleted);
                inflight.Add(Task.Run(async () =>
                {
                    try
                    {
                        var response = await HandleAsync(message, client, cts.Token).ConfigureAwait(false);
                        if (!connection.Enqueue(response))
                        {
                            connection.Abort();
                        }
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    finally
                    {
                        slots.Release();
                    }
                }, CancellationToken.None));
            }

            await Task.WhenAll(inflight).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is IOException or IpcProtocolException or ObjectDisposedException)
        {
            ConnectionFaulted?.Invoke($"Соединение {id} разорвано: {ex.Message}");
        }
        finally
        {
            _connections.TryRemove(id, out _);
            connection.Complete();
            await cts.CancelAsync().ConfigureAwait(false);
            try
            {
                await writer.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException)
            {
            }

            await pipe.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task<IpcMessage> HandleAsync(IpcMessage request, IpcClientIdentity client, CancellationToken token)
    {
        if (IpcClientPolicy.Authorize(request, client) is { } denied)
        {
            _options.OnDenied?.Invoke($"Канал службы: {request.Type} отклонён — {denied}");
            return new IpcMessage { Kind = IpcMessageKind.Response, Type = request.Type, Id = request.Id, Error = denied };
        }

        try
        {
            var payload = await IpcRequestRouter.DispatchAsync(_backend, request, token).ConfigureAwait(false);
            return new IpcMessage { Kind = IpcMessageKind.Response, Type = request.Type, Id = request.Id, Payload = payload };
        }
        catch (Exception ex) when (ex is IpcProtocolException or KeyNotFoundException or ArgumentException or InvalidOperationException
            or IOException or UnauthorizedAccessException or NotSupportedException or JsonException)
        {
            // Ошибка операции — не повод рвать соединение: клиент получает её текстом.
            return new IpcMessage { Kind = IpcMessageKind.Response, Type = request.Type, Id = request.Id, Error = ex.Message };
        }
    }

    // ---- Рассылка событий ------------------------------------------------------

    private void Subscribe()
    {
        if (_subscribed)
        {
            return;
        }

        _subscribed = true;
        _backend.ScanProgressChanged += OnScanProgress;
        _backend.TelemetryUpdated += OnTelemetry;
        _backend.ThreatRaised += OnThreatRaised;
        _backend.ThreatUpdated += OnThreatUpdated;
        _backend.StatusChanged += OnStatus;
    }

    private void Unsubscribe()
    {
        if (!_subscribed)
        {
            return;
        }

        _subscribed = false;
        _backend.ScanProgressChanged -= OnScanProgress;
        _backend.TelemetryUpdated -= OnTelemetry;
        _backend.ThreatRaised -= OnThreatRaised;
        _backend.ThreatUpdated -= OnThreatUpdated;
        _backend.StatusChanged -= OnStatus;
    }

    private void OnScanProgress(ScanProgress p) => Broadcast(IpcProtocol.ScanProgressEvent, p);

    private void OnTelemetry(TelemetrySample s) => Broadcast(IpcProtocol.TelemetryEvent, s);

    private void OnThreatRaised(ThreatEvent t) => Broadcast(IpcProtocol.ThreatRaisedEvent, t);

    private void OnThreatUpdated(ThreatEvent t) => Broadcast(IpcProtocol.ThreatUpdatedEvent, t);

    private void OnStatus(ServiceStatus s) => Broadcast(IpcProtocol.StatusEvent, s);

    private void Broadcast<T>(string type, T payload)
    {
        if (_connections.IsEmpty)
        {
            return;
        }

        var message = new IpcMessage { Kind = IpcMessageKind.Event, Type = type, Payload = IpcProtocol.ToElement(payload) };
        foreach (var (id, connection) in _connections)
        {
            if (!connection.Enqueue(message))
            {
                // Клиент не успевает читать: отключаем его, после переподключения он запросит состояние заново.
                ConnectionFaulted?.Invoke($"Соединение {id} отключено: клиент не читает сообщения.");
                connection.Abort();
            }
        }
    }

    private sealed class Connection(NamedPipeServerStream pipe, int queueLimit)
    {
        private readonly Channel<IpcMessage> _outbound = Channel.CreateBounded<IpcMessage>(
            new BoundedChannelOptions(queueLimit) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });

        public bool Enqueue(IpcMessage message) => _outbound.Writer.TryWrite(message);

        public void Complete() => _outbound.Writer.TryComplete();

        public void Abort()
        {
            Complete();
            try
            {
                pipe.Dispose();
            }
            catch (IOException)
            {
            }
        }

        public async Task PumpAsync(CancellationToken token)
        {
            await foreach (var message in _outbound.Reader.ReadAllAsync(token).ConfigureAwait(false))
            {
                await IpcProtocol.WriteAsync(pipe, message, token).ConfigureAwait(false);
            }
        }
    }
}

/// <summary>Сопоставляет тип запроса с методом <see cref="ISentinelBackend"/>.</summary>
public static class IpcRequestRouter
{
    public static async Task<JsonElement> DispatchAsync(ISentinelBackend backend, IpcMessage request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(request);
        var type = request.Type;
        switch (type)
        {
            case IpcProtocol.Hello:
                return IpcProtocol.ToElement(new HelloInfo(IpcProtocol.Version, "Sentinel"));
            case IpcProtocol.GetStatus:
                return IpcProtocol.ToElement(await backend.GetStatusAsync(token).ConfigureAwait(false));
            case IpcProtocol.SetRealtime:
                return IpcProtocol.ToElement(await backend.SetRealtimeProtectionAsync(Args<ToggleArgs>().Enabled, token).ConfigureAwait(false));
            case IpcProtocol.StartScan:
                return IpcProtocol.ToElement(await backend.StartScanAsync(Args<ScanRequest>(), token).ConfigureAwait(false));
            case IpcProtocol.PauseScan:
                return IpcProtocol.ToElement(await backend.PauseScanAsync(token).ConfigureAwait(false));
            case IpcProtocol.ResumeScan:
                return IpcProtocol.ToElement(await backend.ResumeScanAsync(token).ConfigureAwait(false));
            case IpcProtocol.StopScan:
                return IpcProtocol.ToElement(await backend.StopScanAsync(token).ConfigureAwait(false));
            case IpcProtocol.GetTelemetry:
                return IpcProtocol.ToElement(await backend.GetTelemetryHistoryAsync(token).ConfigureAwait(false));
            case IpcProtocol.GetProcesses:
                return IpcProtocol.ToElement(await backend.GetProcessesAsync(token).ConfigureAwait(false));
            case IpcProtocol.GetThreats:
                return IpcProtocol.ToElement(await backend.GetThreatsAsync(token).ConfigureAwait(false));
            case IpcProtocol.ResolveThreat:
            {
                var args = Args<ResolveThreatArgs>();
                return IpcProtocol.ToElement(await backend.ResolveThreatAsync(RequireId(args.Id), args.Decision, token).ConfigureAwait(false));
            }

            case IpcProtocol.GetQuarantine:
                return IpcProtocol.ToElement(await backend.GetQuarantineAsync(token).ConfigureAwait(false));
            case IpcProtocol.RestoreQuarantine:
            {
                var args = Args<IdArgs>();
                return IpcProtocol.ToElement(await backend.RestoreQuarantineAsync(RequireId(args.Id), args.Overwrite, token).ConfigureAwait(false));
            }

            case IpcProtocol.GetRollback:
                return IpcProtocol.ToElement(await backend.GetRollbackAsync(token).ConfigureAwait(false));
            case IpcProtocol.UndoRollback:
                return IpcProtocol.ToElement(await backend.UndoRollbackAsync(RequireId(Args<IdArgs>().Id), token).ConfigureAwait(false));
            case IpcProtocol.GetStartup:
                return IpcProtocol.ToElement(await backend.GetStartupAsync(Args<StartupArgs>().Refresh, token).ConfigureAwait(false));
            case IpcProtocol.CleanStartup:
                return IpcProtocol.ToElement(await backend.CleanStartupItemAsync(RequireId(Args<IdArgs>().Id), token).ConfigureAwait(false));
            case IpcProtocol.GetReports:
                return IpcProtocol.ToElement(await backend.GetReportsAsync(token).ConfigureAwait(false));
            case IpcProtocol.ExportReport:
            {
                var args = Args<ExportReportArgs>();
                return IpcProtocol.ToElement(await backend.ExportReportAsync(RequireId(args.Id), args.Format, token).ConfigureAwait(false));
            }

            case IpcProtocol.DeleteQuarantine:
                return IpcProtocol.ToElement(await backend.DeleteQuarantineAsync(RequireId(Args<IdArgs>().Id), token).ConfigureAwait(false));
            case IpcProtocol.GetSettings:
                return IpcProtocol.ToElement(await backend.GetSettingsAsync(token).ConfigureAwait(false));
            case IpcProtocol.SaveSettings:
                return IpcProtocol.ToElement(await backend.SaveSettingsAsync(Args<SettingsUpdate>(), token).ConfigureAwait(false));
            case IpcProtocol.UpdateDatabases:
                return IpcProtocol.ToElement(await backend.UpdateDatabasesAsync(token).ConfigureAwait(false));
            case IpcProtocol.GetBehavioralStatus:
                return IpcProtocol.ToElement(await backend.GetBehavioralStatusAsync(token).ConfigureAwait(false));
            case IpcProtocol.ScanRemovable:
                return IpcProtocol.ToElement(await backend.ScanRemovableAsync(Args<ScanRemovableArgs>().PathOrDrive, token).ConfigureAwait(false));

            default:
                throw new IpcProtocolException($"Неизвестный тип запроса '{type}'.");
        }

        T Args<T>() => IpcProtocol.FromElement<T>(request.Payload, type);

        string RequireId(string? id) =>
            string.IsNullOrWhiteSpace(id) ? throw new IpcProtocolException($"Запрос '{type}' без идентификатора.") : id;
    }
}

public enum ServicePipeAccount
{
    LocalSystem,
    Administrators,
    AuthenticatedUsers,
    Network,
}

public enum ServicePipeRights
{
    ReadWrite,
    FullControl,
}

/// <summary>Правило доступа к каналу службы (платформонезависимое описание; ACL строится только в Windows).</summary>
public sealed record ServicePipeRule(ServicePipeAccount Account, ServicePipeRights Rights, bool Allow);
