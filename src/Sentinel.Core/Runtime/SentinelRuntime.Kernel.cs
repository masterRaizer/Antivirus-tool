using Sentinel.Core.Kernel;
using Sentinel.Core.Protection;

namespace Sentinel.Core.Runtime;

/// <summary>Связь с драйвером ядра SentinelDrv (модуль 8/4): статус, защищаемые PID, телеметрия процессов.</summary>
public sealed partial class SentinelRuntime
{
    private readonly object _kernelSync = new();
    private IKernelBridge? _kernel;

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
    /// Цикл драйвера: при загруженном драйвере раз в <see cref="SentinelRuntimeOptions.KernelSyncInterval"/> передаёт ему
    /// актуальные защищаемые PID. Без драйвера сразу завершается — служба работает в профиле User-Mode EDR.
    /// </summary>
    public async Task RunKernelBridgeAsync(CancellationToken cancellationToken)
    {
        var bridge = KernelBridge;
        if (!bridge.IsConnected)
        {
            return;
        }

        var sync = new KernelProtectionSync(bridge, _o.KernelProtectionProcesses ?? _o.Processes, extraOwnDirectories: [_o.DataDirectory]);
        using var timer = new PeriodicTimer(_o.KernelSyncInterval, _o.TimeProvider);
        try
        {
            do
            {
                try
                {
                    if (sync.Synchronize() is { } result)
                    {
                        Log?.Invoke(result.Success
                            ? $"Драйвер ядра: защищаемых процессов {sync.Current.Count} ({string.Join(", ", sync.Current)})."
                            : $"Драйвер ядра: список защищаемых процессов не принят — {result.Message}");
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException
                    or System.ComponentModel.Win32Exception or ArgumentException)
                {
                    Log?.Invoke($"Драйвер ядра: синхронизация защищаемых процессов не выполнена: {ex.Message}");
                }

                if (!bridge.IsConnected)
                {
                    CriticalProcessGuard.SetKernelProtectedProcessIds([]);
                    Log?.Invoke(bridge.GetStatus().Message);
                    return;
                }
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    private IKernelBridge CreateKernelBridge()
    {
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
