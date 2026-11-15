using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Tests;

/// <summary>Бэкенд-двойник: фиксирует вызовы и позволяет поднимать события вручную.</summary>
internal sealed class FakeBackend : ISentinelBackend
{
    public List<string> Calls { get; } = [];

    public List<ThreatEvent> Threats { get; } = [];

    public event Action<ScanProgress>? ScanProgressChanged;

    public event Action<TelemetrySample>? TelemetryUpdated;

    public event Action<ThreatEvent>? ThreatRaised;

    public event Action<ThreatEvent>? ThreatUpdated;

    public event Action<ServiceStatus>? StatusChanged;

    public bool HasSubscribers => ScanProgressChanged is not null;

    public void RaiseScan(ScanProgress p) => ScanProgressChanged?.Invoke(p);

    public void RaiseTelemetry(TelemetrySample s) => TelemetryUpdated?.Invoke(s);

    public void RaiseThreat(ThreatEvent t) => ThreatRaised?.Invoke(t);

    public void RaiseStatus(ServiceStatus s) => StatusChanged?.Invoke(s);

    public static ThreatEvent Threat(string id, ThreatStatus status = ThreatStatus.PendingDecision) => new()
    {
        Id = id,
        Kind = ThreatKind.File,
        Name = "спорный.exe",
        Path = @"C:\Users\Тест\Downloads\спорный.exe",
        Sha256 = new string('a', 64),
        Entropy = 7.61,
        SignatureStatus = "NotSigned",
        Reason = "Heuristic.Packed",
        Severity = Severity.Medium,
        DetectedAtUtc = new DateTime(2026, 11, 15, 10, 0, 0, DateTimeKind.Utc),
        Status = status,
    };

    public Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        Calls.Add("status");
        return Task.FromResult(new ServiceStatus { Mode = "service", RealtimeEnabled = true, FilesChecked = 42, Version = "4.0" });
    }

    public Task<OperationResult> SetRealtimeProtectionAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        Calls.Add($"realtime:{enabled}");
        return Task.FromResult(OperationResult.Ok("ok"));
    }

    public Task<OperationResult> StartScanAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        Calls.Add($"scan:{request.Mode}:{request.Path}");
        return Task.FromResult(request.Mode == ScanMode.Custom && request.Path is null
            ? OperationResult.Fail("Не указана папка.")
            : OperationResult.Ok("Проверка запущена."));
    }

    public Task<OperationResult> PauseScanAsync(CancellationToken cancellationToken = default) => Op("pause");

    public Task<OperationResult> ResumeScanAsync(CancellationToken cancellationToken = default) => Op("resume");

    public Task<OperationResult> StopScanAsync(CancellationToken cancellationToken = default) => Op("stop");

    public Task<IReadOnlyList<TelemetrySample>> GetTelemetryHistoryAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<TelemetrySample>>([new TelemetrySample(DateTime.UnixEpoch, 12.5, 40, 3, 4, 10)]);

    public Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ProcessInfo>>([new ProcessInfo(4100, "miner.exe", @"C:\Temp\miner.exe", 97.5, Severity.High, "PROC-MINER-CMD")]);

    public Task<IReadOnlyList<ThreatEvent>> GetThreatsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ThreatEvent>>(Threats.ToArray());

    public Task<ThreatEvent> ResolveThreatAsync(string id, ThreatDecision decision, CancellationToken cancellationToken = default)
    {
        Calls.Add($"resolve:{id}:{decision}");
        var index = Threats.FindIndex(t => t.Id == id);
        if (index < 0)
        {
            throw new KeyNotFoundException($"Находка '{id}' отсутствует в журнале.");
        }

        Threats[index] = Threats[index] with { Status = decision == ThreatDecision.Allow ? ThreatStatus.Allowed : ThreatStatus.Quarantined };
        ThreatUpdated?.Invoke(Threats[index]);
        return Task.FromResult(Threats[index]);
    }

    public Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<QuarantineItem>>([new QuarantineItem("q1", @"C:\x.exe", "ab", 68, DateTime.UnixEpoch, "EICAR", false, null)]);

    public Task<OperationResult> RestoreQuarantineAsync(string id, bool overwrite = false, CancellationToken cancellationToken = default) =>
        Op($"restore:{id}:{overwrite}");

    public Task<IReadOnlyList<RollbackItem>> GetRollbackAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<RollbackItem>>([new RollbackItem("r1", DateTime.UnixEpoch, "RegistryValue", @"HKCU\Run", "evil", "x", null, "PERS", false)]);

    public Task<OperationResult> UndoRollbackAsync(string id, CancellationToken cancellationToken = default) => Op($"undo:{id}");

    public Task<StartupSnapshot> GetStartupAsync(bool refresh = false, CancellationToken cancellationToken = default)
    {
        Calls.Add($"startup:{refresh}");
        return Task.FromResult(new StartupSnapshot(
            [new StartupItem { Key = "k", Category = "Автозапуск", Name = "evil", Flagged = true, NotSigned = true, Severity = Severity.High }],
            DateTime.UnixEpoch));
    }

    public Task<OperationResult> CleanStartupItemAsync(string key, CancellationToken cancellationToken = default) => Op($"clean:{key}");

    public Task<IReadOnlyList<ReportSummary>> GetReportsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ReportSummary>>([new ReportSummary("rep1", DateTime.UnixEpoch, "Быстрая проверка", "remediate", 3.5, 100, 2, 1)]);

    public Task<ReportExport> ExportReportAsync(string id, ReportFormat format, CancellationToken cancellationToken = default)
    {
        Calls.Add($"export:{id}:{format}");
        return Task.FromResult(new ReportExport($"{id}.{format.ToString().ToLowerInvariant()}", "<html>отчёт</html>"));
    }

    private Task<OperationResult> Op(string call)
    {
        Calls.Add(call);
        return Task.FromResult(OperationResult.Ok(call));
    }
}

public class IpcFramingTests
{
    [Fact]
    public async Task WriteThenRead_RoundTripsUnicodePayload()
    {
        using var stream = new MemoryStream();
        var sent = new IpcMessage { Kind = IpcMessageKind.Event, Type = IpcProtocol.ThreatRaisedEvent, Id = 7, Payload = IpcProtocol.ToElement(FakeBackend.Threat("t1")) };
        await IpcProtocol.WriteAsync(stream, sent);
        await IpcProtocol.WriteAsync(stream, sent with { Id = 8 });
        stream.Position = 0;

        var first = await IpcProtocol.ReadAsync(stream, IpcProtocol.MaxRequestBytes);
        var second = await IpcProtocol.ReadAsync(stream, IpcProtocol.MaxRequestBytes);
        var end = await IpcProtocol.ReadAsync(stream, IpcProtocol.MaxRequestBytes);

        Assert.Equal(7, first!.Id);
        Assert.Equal(8, second!.Id);
        Assert.Null(end);
        var threat = IpcProtocol.FromElement<ThreatEvent>(first.Payload, first.Type);
        Assert.Equal(FakeBackend.Threat("t1"), threat);
        Assert.Contains("\"status\":\"PendingDecision\"", Encoding.UTF8.GetString(stream.ToArray()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(IpcProtocol.MaxRequestBytes + 1)]
    public async Task Read_RejectsInvalidLength(int length)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, length);
        using var stream = new MemoryStream(header);
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcProtocol.ReadAsync(stream, IpcProtocol.MaxRequestBytes));
    }

    [Fact]
    public async Task Read_RejectsTruncatedAndMalformedMessages()
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, 10);
        using var truncated = new MemoryStream([.. header, 1, 2, 3]);
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcProtocol.ReadAsync(truncated, 100));

        var junk = "{not json}"u8.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(header, junk.Length);
        using var malformed = new MemoryStream([.. header, .. junk]);
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcProtocol.ReadAsync(malformed, 100));

        var noType = "{\"kind\":\"Request\",\"type\":\"\"}"u8.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(header, noType.Length);
        using var untyped = new MemoryStream([.. header, .. noType]);
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcProtocol.ReadAsync(untyped, 100));
    }
}

public class IpcRequestRouterTests
{
    private static IpcMessage Request(string type, object? args = null) => new()
    {
        Kind = IpcMessageKind.Request,
        Type = type,
        Id = 1,
        Payload = args is null ? null : System.Text.Json.JsonSerializer.SerializeToElement(args, args.GetType(), IpcProtocol.Json),
    };

    [Fact]
    public async Task ResolveThreat_RoutesDecisionToBackend()
    {
        var backend = new FakeBackend();
        backend.Threats.Add(FakeBackend.Threat("t1"));

        var allow = await IpcRequestRouter.DispatchAsync(backend, Request(IpcProtocol.ResolveThreat, new ResolveThreatArgs("t1", ThreatDecision.Allow)), default);

        Assert.Equal(ThreatStatus.Allowed, IpcProtocol.FromElement<ThreatEvent>(allow, "t").Status);
        Assert.Equal(["resolve:t1:Allow"], backend.Calls);
    }

    [Fact]
    public async Task UnknownTypeOrMissingArguments_AreProtocolErrors()
    {
        var backend = new FakeBackend();
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcRequestRouter.DispatchAsync(backend, Request("format.disk"), default));
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcRequestRouter.DispatchAsync(backend, Request(IpcProtocol.ResolveThreat), default));
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcRequestRouter.DispatchAsync(backend, Request(IpcProtocol.RestoreQuarantine, new IdArgs(" ")), default));
        await Assert.ThrowsAsync<IpcProtocolException>(() => IpcRequestRouter.DispatchAsync(backend,
            Request(IpcProtocol.ResolveThreat, new { id = "t1", decision = "Format" }), default));
        Assert.Empty(backend.Calls);
    }
}

/// <summary>Сквозные тесты поверх настоящего именованного канала (в Linux — сокет домена Unix).</summary>
public sealed class IpcPipeTests : IAsyncLifetime
{
    private readonly FakeBackend _backend = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly string _pipe = "sentinel-test-" + Guid.NewGuid().ToString("N");
    private SentinelIpcServer _server = null!;
    private Task _serverTask = Task.CompletedTask;

    public async Task InitializeAsync()
    {
        _server = new SentinelIpcServer(_backend, new IpcServerOptions { PipeName = _pipe });
        _serverTask = _server.RunAsync(_cts.Token);
        await WaitAsync(() => _backend.HasSubscribers);
    }

    public async Task DisposeAsync()
    {
        await _cts.CancelAsync();
        await _serverTask;
        await _server.DisposeAsync();
        _cts.Dispose();
    }

    private async Task<SentinelIpcClient> ConnectAsync() =>
        await SentinelIpcClient.TryConnectAsync(_pipe, TimeSpan.FromSeconds(10)) ?? throw new InvalidOperationException("Сервер недоступен.");

    private static async Task WaitAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "Условие не выполнено за 10 секунд.");
            await Task.Delay(10);
        }
    }

    [Fact]
    public async Task Requests_ReachBackend_AndResultsComeBackTyped()
    {
        await using var client = await ConnectAsync();

        var status = await client.GetStatusAsync();
        var scan = await client.StartScanAsync(new ScanRequest(ScanMode.Custom, @"D:\Папка"));
        var rejected = await client.StartScanAsync(new ScanRequest(ScanMode.Custom));
        await client.PauseScanAsync();
        await client.ResumeScanAsync();
        await client.StopScanAsync();
        await client.SetRealtimeProtectionAsync(false);
        var telemetry = await client.GetTelemetryHistoryAsync();
        var processes = await client.GetProcessesAsync();
        var quarantine = await client.GetQuarantineAsync();
        var restore = await client.RestoreQuarantineAsync("q1", overwrite: true);
        var rollback = await client.GetRollbackAsync();
        await client.UndoRollbackAsync("r1");
        var startup = await client.GetStartupAsync(refresh: true);
        await client.CleanStartupItemAsync("k");
        var reports = await client.GetReportsAsync();
        var export = await client.ExportReportAsync("rep1", ReportFormat.Html);

        Assert.Equal("service", status.Mode);
        Assert.True(status.RealtimeEnabled);
        Assert.Equal(42, status.FilesChecked);
        Assert.True(scan.Success);
        Assert.False(rejected.Success);
        Assert.Equal(12.5, Assert.Single(telemetry).CpuPercent);
        Assert.Equal(Severity.High, Assert.Single(processes).Severity);
        Assert.Equal("q1", Assert.Single(quarantine).Id);
        Assert.Equal("restore:q1:True", restore.Message);
        Assert.False(Assert.Single(rollback).Undone);
        Assert.True(Assert.Single(startup.Items).NotSigned);
        Assert.Equal("Быстрая проверка", Assert.Single(reports).Title);
        Assert.Equal("rep1.html", export.FileName);
        Assert.Equal("<html>отчёт</html>", export.Content);
        Assert.Equal(
            ["status", @"scan:Custom:D:\Папка", "scan:Custom:", "pause", "resume", "stop", "realtime:False", "restore:q1:True",
                "undo:r1", "startup:True", "clean:k", "export:rep1:Html"],
            _backend.Calls);
    }

    [Fact]
    public async Task ServerEvents_AreBroadcastToEveryClient()
    {
        await using var first = await ConnectAsync();
        await using var second = await ConnectAsync();
        await WaitAsync(() => _server.ClientCount == 2);
        var progress = new List<ScanProgress>();
        var raised = new List<ThreatEvent>();
        var telemetry = new List<TelemetrySample>();
        var statuses = new List<ServiceStatus>();
        first.ScanProgressChanged += p => { lock (progress) { progress.Add(p); } };
        second.ThreatRaised += t => { lock (raised) { raised.Add(t); } };
        second.TelemetryUpdated += s => { lock (telemetry) { telemetry.Add(s); } };
        first.StatusChanged += s => { lock (statuses) { statuses.Add(s); } };

        _backend.RaiseScan(new ScanProgress { State = ScanState.Running, CurrentItem = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", Scanned = 10, Total = 40, Percent = 25 });
        _backend.RaiseThreat(FakeBackend.Threat("t9"));
        _backend.RaiseTelemetry(new TelemetrySample(DateTime.UnixEpoch, 55, 60, 5, 6, 10));
        _backend.RaiseStatus(new ServiceStatus { RealtimeEnabled = false });

        await WaitAsync(() => progress.Count == 1 && raised.Count == 1 && telemetry.Count == 1 && statuses.Count == 1);
        Assert.Equal(25, progress[0].Percent);
        Assert.Contains("CurrentVersion", progress[0].CurrentItem);
        Assert.Equal(FakeBackend.Threat("t9"), raised[0]);
        Assert.Equal(55, telemetry[0].CpuPercent);
        Assert.False(statuses[0].RealtimeEnabled);
    }

    [Fact]
    public async Task InteractiveDecision_PendingThreatIsResolved_AndAllClientsAreNotified()
    {
        _backend.Threats.Add(FakeBackend.Threat("t1"));
        await using var ui = await ConnectAsync();
        await using var tray = await ConnectAsync();
        await WaitAsync(() => _server.ClientCount == 2);
        var updates = new List<ThreatEvent>();
        tray.ThreatUpdated += t => { lock (updates) { updates.Add(t); } };

        var pending = Assert.Single(await ui.GetThreatsAsync());
        Assert.Equal(ThreatStatus.PendingDecision, pending.Status);
        var resolved = await ui.ResolveThreatAsync(pending.Id, ThreatDecision.Quarantine);

        Assert.Equal(ThreatStatus.Quarantined, resolved.Status);
        await WaitAsync(() => updates.Count == 1);
        Assert.Equal(ThreatStatus.Quarantined, updates[0].Status);
    }

    [Fact]
    public async Task BackendError_IsReturnedAsRemoteException_AndConnectionSurvives()
    {
        await using var client = await ConnectAsync();

        var error = await Assert.ThrowsAsync<IpcRemoteException>(() => client.ResolveThreatAsync("missing", ThreatDecision.Allow));

        Assert.Contains("missing", error.Message);
        Assert.Equal("service", (await client.GetStatusAsync()).Mode);
    }

    [Fact]
    public async Task MalformedClient_IsDisconnected_WithoutAffectingOthers()
    {
        await using var good = await ConnectAsync();
        var faults = new List<string>();
        _server.ConnectionFaulted += m => { lock (faults) { faults.Add(m); } };

        await using (var raw = new NamedPipeClientStream(".", _pipe, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await raw.ConnectAsync(5000);
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, int.MaxValue); // заявлен гигантский запрос
            await raw.WriteAsync(header);
            await raw.FlushAsync();
            var buffer = new byte[1];
            Assert.Equal(0, await raw.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(10))); // сервер закрыл канал
        }

        await WaitAsync(() => faults.Count == 1);
        Assert.Equal("service", (await good.GetStatusAsync()).Mode);
    }

    [Fact]
    public async Task ServerShutdown_FailsPendingWork_AndRaisesDisconnected()
    {
        var client = await ConnectAsync();
        var disconnected = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Disconnected += disconnected.SetResult;

        await _cts.CancelAsync();
        await _serverTask;

        await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(client.IsConnected);
        await Assert.ThrowsAsync<IOException>(() => client.GetStatusAsync());
        await client.DisposeAsync();
    }

    [Fact]
    public async Task TryConnect_WithoutServer_ReturnsNull()
    {
        var client = await SentinelIpcClient.TryConnectAsync("sentinel-absent-" + Guid.NewGuid().ToString("N"), TimeSpan.FromMilliseconds(300));
        Assert.Null(client);
    }
}
