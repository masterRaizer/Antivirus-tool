using System.IO;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Runtime;

namespace Sentinel.App.Services;

/// <summary>
/// Двойной режим работы. Хаб реализует <see cref="ISentinelBackend"/> и прозрачно направляет вызовы
/// либо службе <c>Sentinel.Service</c> (по именованному каналу), либо локальному рантайму
/// <c>Sentinel.Core</c> (автономный режим — приложение работает как портативный .exe).
/// При остановке службы хаб переходит в автономный режим, при её появлении — подключается обратно.
/// </summary>
public sealed class BackendHub : ISentinelBackend, IAsyncDisposable
{
    private static readonly TimeSpan ReconnectInterval = TimeSpan.FromSeconds(2);

    /// <summary>Имя службы Windows (совпадает с <c>ServiceOptions.ServiceName</c> и установщиком).</summary>
    public const string ServiceName = "SentinelService";

    private readonly SemaphoreSlim _switchLock = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private ISentinelBackend? _current;
    private SentinelIpcClient? _client;
    private SentinelRuntime? _local;
    private CancellationTokenSource? _localLoops;
    private Task _localTasks = Task.CompletedTask;
    private Task _reconnectLoop = Task.CompletedTask;

    public event Action<ScanProgress>? ScanProgressChanged;

    public event Action<TelemetrySample>? TelemetryUpdated;

    public event Action<ThreatEvent>? ThreatRaised;

    public event Action<ThreatEvent>? ThreatUpdated;

    public event Action<ServiceStatus>? StatusChanged;

    /// <summary>Сменился источник данных (служба ↔ автономный режим): разделам нужно перечитать состояние.</summary>
    public event Action? ModeChanged;

    public bool IsServiceMode { get; private set; }

    /// <summary>Каталог данных автономного режима (для подсказки в интерфейсе).</summary>
    public string? LocalDataDirectory => _local?.DataDirectory;

    private ISentinelBackend Current =>
        _current ?? throw new InvalidOperationException("Движок Sentinel ещё не инициализирован.");

    /// <summary>Подключается к службе, а если она не запущена — поднимает локальный рантайм.</summary>
    public async Task InitializeAsync()
    {
        await _switchLock.WaitAsync();
        try
        {
            if (!await TryAttachServiceAsync())
            {
                StartLocal();
            }
        }
        finally
        {
            _switchLock.Release();
        }

        ModeChanged?.Invoke();
        _reconnectLoop = Task.Run(ReconnectLoopAsync);
    }

    public async ValueTask DisposeAsync()
    {
        await _lifetime.CancelAsync();
        try
        {
            await _reconnectLoop;
        }
        catch (OperationCanceledException)
        {
        }

        Detach();
        if (_client is not null)
        {
            await _client.DisposeAsync();
        }

        await StopLocalLoopsAsync();
        if (_local is not null)
        {
            await _local.DisposeAsync();
        }

        _lifetime.Dispose();
        _switchLock.Dispose();
    }

    // ---- ISentinelBackend: переадресация текущему источнику --------------------

    public Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default) => Current.GetStatusAsync(cancellationToken);

    public Task<OperationResult> SetRealtimeProtectionAsync(bool enabled, CancellationToken cancellationToken = default) =>
        Current.SetRealtimeProtectionAsync(enabled, cancellationToken);

    public Task<OperationResult> StartScanAsync(ScanRequest request, CancellationToken cancellationToken = default) =>
        Current.StartScanAsync(request, cancellationToken);

    public Task<OperationResult> PauseScanAsync(CancellationToken cancellationToken = default) => Current.PauseScanAsync(cancellationToken);

    public Task<OperationResult> ResumeScanAsync(CancellationToken cancellationToken = default) => Current.ResumeScanAsync(cancellationToken);

    public Task<OperationResult> StopScanAsync(CancellationToken cancellationToken = default) => Current.StopScanAsync(cancellationToken);

    public Task<IReadOnlyList<TelemetrySample>> GetTelemetryHistoryAsync(CancellationToken cancellationToken = default) =>
        Current.GetTelemetryHistoryAsync(cancellationToken);

    public Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken cancellationToken = default) =>
        Current.GetProcessesAsync(cancellationToken);

    public Task<IReadOnlyList<ThreatEvent>> GetThreatsAsync(CancellationToken cancellationToken = default) =>
        Current.GetThreatsAsync(cancellationToken);

    public Task<ThreatEvent> ResolveThreatAsync(string id, ThreatDecision decision, CancellationToken cancellationToken = default) =>
        Current.ResolveThreatAsync(id, decision, cancellationToken);

    public Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync(CancellationToken cancellationToken = default) =>
        Current.GetQuarantineAsync(cancellationToken);

    public Task<OperationResult> RestoreQuarantineAsync(string id, bool overwrite = false, CancellationToken cancellationToken = default) =>
        Current.RestoreQuarantineAsync(id, overwrite, cancellationToken);

    public Task<IReadOnlyList<RollbackItem>> GetRollbackAsync(CancellationToken cancellationToken = default) =>
        Current.GetRollbackAsync(cancellationToken);

    public Task<OperationResult> UndoRollbackAsync(string id, CancellationToken cancellationToken = default) =>
        Current.UndoRollbackAsync(id, cancellationToken);

    public Task<StartupSnapshot> GetStartupAsync(bool refresh = false, CancellationToken cancellationToken = default) =>
        Current.GetStartupAsync(refresh, cancellationToken);

    public Task<OperationResult> CleanStartupItemAsync(string key, CancellationToken cancellationToken = default) =>
        Current.CleanStartupItemAsync(key, cancellationToken);

    public Task<IReadOnlyList<ReportSummary>> GetReportsAsync(CancellationToken cancellationToken = default) =>
        Current.GetReportsAsync(cancellationToken);

    public Task<ReportExport> ExportReportAsync(string id, ReportFormat format, CancellationToken cancellationToken = default) =>
        Current.ExportReportAsync(id, format, cancellationToken);

    public Task<OperationResult> DeleteQuarantineAsync(string id, CancellationToken cancellationToken = default) =>
        Current.DeleteQuarantineAsync(id, cancellationToken);

    public Task<SettingsSnapshot> GetSettingsAsync(CancellationToken cancellationToken = default) => Current.GetSettingsAsync(cancellationToken);

    public Task<OperationResult> SaveSettingsAsync(SettingsUpdate update, CancellationToken cancellationToken = default) =>
        Current.SaveSettingsAsync(update, cancellationToken);

    public Task<Sentinel.Core.ThreatIntel.DatabaseStatus> UpdateDatabasesAsync(CancellationToken cancellationToken = default) =>
        Current.UpdateDatabasesAsync(cancellationToken);

    /// <summary>
    /// Запускает службу <c>SentinelService</c> командой <c>sc.exe start</c> с запросом повышения прав (UAC).
    /// Подключение к запущенной службе выполнит цикл автопереподключения (каждые 2 секунды).
    /// </summary>
    public static Task<OperationResult> StartServiceAsync() => Task.Run(() =>
    {
        try
        {
            var sc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe");
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(sc, $"start {ServiceName}")
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            });
            if (process is null)
            {
                return OperationResult.Fail("Не удалось запустить sc.exe.");
            }

            process.WaitForExit(30_000);
            return process.ExitCode switch
            {
                0 => OperationResult.Ok("Служба запускается — подключение произойдёт автоматически."),
                1056 => OperationResult.Ok("Служба уже запущена — выполняется подключение."),
                1060 => OperationResult.Fail("Служба SentinelService не установлена. Установите Sentinel из MSI-пакета."),
                _ => OperationResult.Fail($"sc.exe start завершился с кодом {process.ExitCode}."),
            };
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return OperationResult.Fail("Запуск отменён: для запуска службы нужны права администратора.");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return OperationResult.Fail($"Не удалось запустить службу: {ex.Message}");
        }
    });

    // ---- Переключение режимов ---------------------------------------------------

    private async Task<bool> TryAttachServiceAsync()
    {
        var client = await SentinelIpcClient.TryConnectAsync(timeout: TimeSpan.FromMilliseconds(1500), cancellationToken: _lifetime.Token);
        if (client is null)
        {
            return false;
        }

        // Служба и локальный рантайм не должны защищать систему одновременно.
        await StopLocalLoopsAsync();
        Detach();
        _client = client;
        client.Disconnected += OnServiceDisconnected;
        Attach(client);
        IsServiceMode = true;
        return true;
    }

    private void StartLocal()
    {
        Detach();
        _local ??= new SentinelRuntime(SentinelRuntimeOptions.CreateDefault("standalone", ChooseDataDirectory()));
        _localLoops = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        var token = _localLoops.Token;
        var runtime = _local;
        _localTasks = Task.WhenAll(
            Task.Run(() => runtime.RunTelemetryAsync(token)),
            Task.Run(() => runtime.RunFileMonitorAsync(token)),
            Task.Run(() => runtime.RunPeriodicAuditAsync(token)),
            Task.Run(() => runtime.RunDatabaseUpdatesAsync(token)));
        Attach(runtime);
        IsServiceMode = false;
    }

    private async Task StopLocalLoopsAsync()
    {
        if (_localLoops is null)
        {
            return;
        }

        await _localLoops.CancelAsync();
        try
        {
            await _localTasks;
        }
        catch (OperationCanceledException)
        {
        }

        _localLoops.Dispose();
        _localLoops = null;
    }

    private void OnServiceDisconnected(string reason) => _ = Task.Run(async () =>
    {
        if (_lifetime.IsCancellationRequested)
        {
            return;
        }

        await _switchLock.WaitAsync();
        try
        {
            if (_client is { } client)
            {
                client.Disconnected -= OnServiceDisconnected;
                _client = null;
                await client.DisposeAsync();
            }

            StartLocal();
        }
        finally
        {
            _switchLock.Release();
        }

        ModeChanged?.Invoke();
    });

    private async Task ReconnectLoopAsync()
    {
        using var timer = new PeriodicTimer(ReconnectInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(_lifetime.Token))
            {
                // Идущую локальную проверку не прерываем: к службе вернёмся после её завершения.
                if (IsServiceMode || _local?.CurrentScan.IsActive == true)
                {
                    continue;
                }

                var attached = false;
                await _switchLock.WaitAsync(_lifetime.Token);
                try
                {
                    attached = !IsServiceMode && await TryAttachServiceAsync();
                }
                finally
                {
                    _switchLock.Release();
                }

                if (attached)
                {
                    ModeChanged?.Invoke();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void Attach(ISentinelBackend backend)
    {
        backend.ScanProgressChanged += OnScan;
        backend.TelemetryUpdated += OnTelemetry;
        backend.ThreatRaised += OnThreatRaised;
        backend.ThreatUpdated += OnThreatUpdated;
        backend.StatusChanged += OnStatus;
        _current = backend;
    }

    private void Detach()
    {
        if (_current is not { } backend)
        {
            return;
        }

        backend.ScanProgressChanged -= OnScan;
        backend.TelemetryUpdated -= OnTelemetry;
        backend.ThreatRaised -= OnThreatRaised;
        backend.ThreatUpdated -= OnThreatUpdated;
        backend.StatusChanged -= OnStatus;
    }

    private void OnScan(ScanProgress p) => ScanProgressChanged?.Invoke(p);

    private void OnTelemetry(TelemetrySample s) => TelemetryUpdated?.Invoke(s);

    private void OnThreatRaised(ThreatEvent t) => ThreatRaised?.Invoke(t);

    private void OnThreatUpdated(ThreatEvent t) => ThreatUpdated?.Invoke(t);

    private void OnStatus(ServiceStatus s) => StatusChanged?.Invoke(s);

    /// <summary>
    /// Каталог данных автономного режима: общий <c>%ProgramData%\Sentinel</c>, если в него можно писать
    /// (приложение запущено администратором), иначе личный <c>%LocalAppData%\Sentinel</c>.
    /// </summary>
    private static string ChooseDataDirectory()
    {
        var shared = SentinelRuntimeOptions.DefaultDataDirectory();
        try
        {
            Directory.CreateDirectory(shared);
            var probe = Path.Combine(shared, $".write-probe-{Environment.ProcessId}");
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            return shared;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel");
        }
    }
}
