using System.Windows;
using System.Windows.Threading;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.App.Views;
using Sentinel.Core.Realtime;

namespace Sentinel.App;

/// <summary>
/// Точка входа: единственный экземпляр, главное окно, значок в трее и всплывающее окно решений.
/// Параметр <c>--tray</c> запускает приложение свёрнутым в трей (для автозапуска).
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable",
    Justification = "Время жизни ресурсов совпадает с процессом: они освобождаются в ExitAsync и OnExit.")]
public partial class App : Application
{
    private const string InstanceName = "Sentinel.App.SingleInstance";
    private const string ShowSignalName = "Sentinel.App.ShowWindow";

    private Mutex? _instance;
    private EventWaitHandle? _showSignal;
    private RegisteredWaitHandle? _showRegistration;
    private BackendHub? _hub;
    private MainViewModel? _model;
    private MainWindow? _window;
    private DecisionPopup? _popup;
    private TrayIcon? _tray;
    private bool _exiting;

    protected override async void OnStartup(StartupEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);
        base.OnStartup(e);

        _instance = new Mutex(initiallyOwned: true, InstanceName, out var first);
        if (!first)
        {
            // Уже запущено: просим работающий экземпляр показать окно и выходим.
            if (EventWaitHandle.TryOpenExisting(ShowSignalName, out var signal))
            {
                signal.Set();
                signal.Dispose();
            }

            _instance.Dispose();
            _instance = null;
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
        _showRegistration = ThreadPool.RegisterWaitForSingleObject(
            _showSignal, (_, _) => Dispatcher.BeginInvoke(ShowMainWindow), null, Timeout.Infinite, executeOnlyOnce: false);

        _hub = new BackendHub();
        _model = new MainViewModel(_hub);
        _window = new MainWindow { DataContext = _model };
        MainWindow = _window;
        _popup = new DecisionPopup(_model.Decisions);

        _tray = new TrayIcon();
        _tray.OpenRequested += ShowMainWindow;
        _tray.QuickScanRequested += OnQuickScanRequested;
        _tray.RealtimeToggled += enabled => _ = _model.SetRealtimeAsync(enabled);
        _tray.ExitRequested += () => _ = ExitAsync();

        _model.Dashboard.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(DashboardViewModel.Status))
            {
                _tray?.SetProtection(_model.Dashboard.Status.RealtimeEnabled, _model.Dashboard.Status.PendingDecisions);
            }
        };
        _model.ThreatNeutralized += OnThreatNeutralized;
        _model.DecisionRequested += () => _popup?.Refresh();

        if (!e.Args.Contains("--tray", StringComparer.OrdinalIgnoreCase))
        {
            _window.Show();
        }

        await _model.InitializeAsync();
    }

    private void ShowMainWindow() => _window?.BringToFront();

    private async void OnQuickScanRequested()
    {
        if (_model is null)
        {
            return;
        }

        ShowMainWindow();
        try
        {
            await _model.QuickScanAsync();
        }
        catch (Exception ex) when (ex is System.IO.IOException or InvalidOperationException or Sentinel.Core.Ipc.IpcRemoteException)
        {
            _tray?.Notify("Sentinel", ex.Message, warning: true);
        }
    }

    private void OnThreatNeutralized(ThreatEvent threat) =>
        _tray?.Notify(
            "Sentinel: угроза нейтрализована",
            $"{threat.Name}\n{ThreatStatusTextConverter.Text(threat.Status)} · {threat.Reason}",
            warning: true);

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Сбой отрисовки или обработчика не должен молча убивать защиту: сообщаем и продолжаем работу.
        e.Handled = true;
        _tray?.Notify("Sentinel: внутренняя ошибка", e.Exception.Message, warning: true);
    }

    private async Task ExitAsync()
    {
        if (_exiting)
        {
            return;
        }

        _exiting = true;
        _popup?.Close();
        if (_window is not null)
        {
            _window.AllowClose = true;
            _window.Close();
        }

        _tray?.Dispose();
        _model?.Dispose();
        if (_hub is not null)
        {
            await _hub.DisposeAsync();
        }

        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _showRegistration?.Unregister(null);
        _showSignal?.Dispose();
        if (_instance is not null)
        {
            _instance.ReleaseMutex();
            _instance.Dispose();
        }

        base.OnExit(e);
    }
}
