using System.IO.Pipes;

namespace Sentinel.Core.Scanning.Pool;

/// <summary>
/// Рабочая сторона пула: подключается к каналу координатора, получает пути, возвращает результаты <see cref="FileAnalyzer"/>.
/// Режим <c>Sentinel.Cli.exe --scan-worker --pipe &lt;имя&gt; --parent-pid &lt;pid&gt;</c>. Сторожевой поток каждые 500 мс проверяет,
/// жив ли родитель: если родитель завершился или упал, рабочий процесс немедленно завершает сам себя.
/// </summary>
public static class ScanWorkerHost
{
    public static readonly TimeSpan ParentCheckInterval = TimeSpan.FromMilliseconds(500);

    /// <param name="isParentAlive">Проверка родителя (подменяется в тестах); по умолчанию — наличие процесса с PID.</param>
    /// <param name="onParentGone">Действие при исчезновении родителя; по умолчанию — завершение процесса.</param>
    public static async Task<int> RunAsync(string pipeName, int parentPid, Func<string, FileScanResult> analyze,
        Func<int, bool>? isParentAlive = null, Action? onParentGone = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentNullException.ThrowIfNull(analyze);
        isParentAlive ??= IsProcessAlive;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var stop = linked.Token;
        var watchdog = new Thread(() =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    if (!isParentAlive(parentPid))
                    {
                        if (onParentGone is not null)
                        {
                            onParentGone();
                            linked.Cancel();
                        }
                        else
                        {
                            Environment.Exit(3);
                        }

                        return;
                    }

                    stop.WaitHandle.WaitOne(ParentCheckInterval);
                }
            }
            catch (ObjectDisposedException)
            {
                // рабочий уже завершается
            }
        })
        {
            IsBackground = true,
            Name = "Sentinel.ParentWatchdog",
        };
        watchdog.Start();

        try
        {
            await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(15_000, linked.Token).ConfigureAwait(false);
            await WorkerProtocol.WriteAsync(client, new WorkerMessage { Type = "hello", ProcessId = Environment.ProcessId }, linked.Token).ConfigureAwait(false);
            while (!linked.IsCancellationRequested)
            {
                var message = await WorkerProtocol.ReadAsync(client, linked.Token).ConfigureAwait(false);
                if (message is null || message.Type == "quit")
                {
                    return 0;
                }

                if (message.Type != "scan" || message.Path is null)
                {
                    continue;
                }

                var reply = new WorkerMessage { Type = "result", Id = message.Id, Path = message.Path };
                try
                {
                    reply.Result = analyze(message.Path);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or InvalidDataException)
                {
                    reply.Error = ex.Message;
                }

                await WorkerProtocol.WriteAsync(client, reply, linked.Token).ConfigureAwait(false);
            }

            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException)
        {
            return 2;
        }
        finally
        {
            await linked.CancelAsync().ConfigureAwait(false);

            // Источник отмены освобождается только после остановки сторожевого потока.
            watchdog.Join(TimeSpan.FromSeconds(2));
        }
    }

    public static bool IsProcessAlive(int pid)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
