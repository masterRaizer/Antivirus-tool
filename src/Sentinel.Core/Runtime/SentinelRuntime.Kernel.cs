using Sentinel.Core.Kernel;
using Sentinel.Core.Protection;

namespace Sentinel.Core.Runtime;

/// <summary>Связь с драйвером ядра SentinelDrv (модуль 8/4): статус, защищаемые PID, телеметрия процессов.</summary>
public sealed partial class SentinelRuntime
{
    private readonly object _kernelSync = new();
    private IKernelBridge? _kernel;
    private volatile bool _kernelReleased;

    /// <summary>Мост к драйверу; без драйвера — <see cref="NullKernelBridge"/> (профиль User-Mode EDR, без ошибок).</summary>
    public IKernelBridge KernelBridge
    {
        get
        {
            lock (_kernelSync)
            {
                return _kernel ??= CreateKernelBridge();
            }
        }
    }

    public KernelDriverStatus GetKernelStatus() => KernelBridge.GetStatus();

    /// <summary>
    /// Цикл драйвера. Каждые <see cref="SentinelRuntimeOptions.KernelHealthInterval"/> (2 с) проверяет, жив ли драйвер:
    /// при <c>sc stop SentinelDrv</c> мост сразу отпускает дескриптор устройства (драйвер выгружается без остановки службы),
    /// защита PID в <see cref="CriticalProcessGuard"/> снимается, служба переходит в профиль User-Mode EDR. Без драйвера раз в
    /// <see cref="SentinelRuntimeOptions.KernelReconnectInterval"/> пробует подключиться снова (после <c>sc start SentinelDrv</c>).
    /// При подключённом драйвере раз в <see cref="SentinelRuntimeOptions.KernelSyncInterval"/> передаёт защищаемые PID.
    /// </summary>
    public async Task RunKernelBridgeAsync(CancellationToken cancellationToken)
    {
        if (_o.KernelBridgeFactory is null)
        {
            return; // вне Windows и в автономных тестах драйвера нет и не будет
        }

        KernelProtectionSync? sync = null;
        IKernelBridge? syncBridge = null;
        long? lastSync = null;
        var lastReconnect = _o.TimeProvider.GetTimestamp();
        using var timer = new PeriodicTimer(_o.KernelHealthInterval, _o.TimeProvider);
        try
        {
            do
            {
                if (_kernelReleased)
                {
                    return;
                }

                var bridge = KernelBridge;
                if (bridge.IsConnected && !bridge.CheckConnection())
                {
                    var message = bridge.GetStatus().Message;
                    ReplaceKernelBridge(new NullKernelBridge(message));
                    Info?.Invoke($"Драйвер ядра отключён: {message}. Защита PID ядром снята, работа продолжается в профиле User-Mode EDR.");
                    sync = null;
                    continue;
                }

                if (!bridge.IsConnected)
                {
                    if (_o.TimeProvider.GetElapsedTime(lastReconnect) >= _o.KernelReconnectInterval)
                    {
                        lastReconnect = _o.TimeProvider.GetTimestamp();
                        var fresh = CreateKernelBridge();
                        if (fresh.IsConnected)
                        {
                            ReplaceKernelBridge(fresh);
                            Info?.Invoke($"Драйвер ядра подключён: {fresh.GetStatus().Message}");
                            lastSync = null;
                        }
                        else
                        {
                            fresh.Dispose();
                        }
                    }

                    continue;
                }

                if (!ReferenceEquals(syncBridge, bridge) || sync is null)
                {
                    sync = new KernelProtectionSync(bridge, _o.KernelProtectionProcesses ?? _o.Processes, extraOwnDirectories: [_o.DataDirectory]);
                    syncBridge = bridge;
                    lastSync = null;
                }

                if (lastSync is null || _o.TimeProvider.GetElapsedTime(lastSync.Value) >= _o.KernelSyncInterval)
                {
                    lastSync = _o.TimeProvider.GetTimestamp();
                    SynchronizeKernelProtection(sync);
                }
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>
    /// Отпускает драйвер (остановка службы): закрывает дескриптор устройства, снимает публикацию PID и больше не переподключается.
    /// </summary>
    public void ReleaseKernelBridge()
    {
        _kernelReleased = true;
        ReplaceKernelBridge(new NullKernelBridge($"{KernelDriverStatus.NotLoadedMessage} (Sentinel service is stopping)"));
    }

    private void SynchronizeKernelProtection(KernelProtectionSync sync)
    {
        try
        {
            if (sync.Synchronize() is { } result)
            {
                if (result.Success)
                {
                    Info?.Invoke($"Драйвер ядра: защищаемых процессов {sync.Current.Count} ({string.Join(", ", sync.Current)}).");
                }
                else
                {
                    Log?.Invoke($"Драйвер ядра: список защищаемых процессов не принят — {result.Message}");
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException
            or System.ComponentModel.Win32Exception or ArgumentException)
        {
            Log?.Invoke($"Драйвер ядра: синхронизация защищаемых процессов не выполнена: {ex.Message}");
        }
    }

    private IKernelBridge CreateKernelBridge()
    {
        if (_kernelReleased)
        {
            return new NullKernelBridge($"{KernelDriverStatus.NotLoadedMessage} (Sentinel service is stopping)");
        }

        try
        {
            return _o.KernelBridgeFactory?.Invoke() ?? new NullKernelBridge();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception
            or DllNotFoundException or EntryPointNotFoundException)
        {
            return new NullKernelBridge($"{KernelDriverStatus.NotLoadedMessage} ({ex.Message})");
        }
    }

    private void ReplaceKernelBridge(IKernelBridge replacement)
    {
        IKernelBridge? previous;
        lock (_kernelSync)
        {
            previous = _kernel;
            _kernel = replacement;
        }

        if (!replacement.IsConnected)
        {
            CriticalProcessGuard.SetKernelProtectedProcessIds([]);
        }

        if (!ReferenceEquals(previous, replacement))
        {
            previous?.Dispose();
        }
    }

    private void DisposeKernelBridge()
    {
        IKernelBridge? kernel;
        lock (_kernelSync)
        {
            kernel = _kernel;
            _kernel = null;
        }

        if (kernel is { IsConnected: true })
        {
            CriticalProcessGuard.SetKernelProtectedProcessIds([]);
        }

        kernel?.Dispose();
    }
}
