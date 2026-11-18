using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Sentinel.App.Mvvm;
using Sentinel.App.Services;
using Sentinel.Core.Ipc;
using Sentinel.Core.Runtime;
using Sentinel.Core.Realtime;

namespace Sentinel.App.ViewModels;

public enum Section
{
    Dashboard,
    Scan,
    Threats,
    Quarantine,
    Startup,
    Reports,
    Behavioral,
    Settings,
}

/// <summary>Корневая модель окна: навигация, режим работы, строка состояния и маршрутизация событий движка.</summary>
public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly BackendHub _hub;
    private readonly Dispatcher _ui;
    private readonly DispatcherTimer _processTimer;
    private Section _section = Section.Dashboard;
    private string _statusMessage = "Запуск…";
    private bool _statusIsError;
    private bool _isServiceMode;
    private bool _isReady;
    private string _version = string.Empty;

    public MainViewModel(BackendHub hub)
    {
        _hub = hub;
        _ui = Application.Current.Dispatcher;
        Dashboard = new DashboardViewModel(hub, Notify, QuickScanAsync, FullScanAsync, () => Section = Section.Settings);
        Scan = new ScanViewModel(hub, Notify, id => _ = OpenReportAsync(id));
        Threats = new ThreatsViewModel(hub, Notify);
        Quarantine = new QuarantineViewModel(hub, Notify);
        Startup = new StartupViewModel(hub, Notify);
        Reports = new ReportsViewModel(hub, Notify);
        Behavioral = new BehavioralViewModel(hub, Notify);
        Settings = new SettingsViewModel(hub, Notify);
        StartServiceCommand = new AsyncCommand(StartServiceAsync, () => !IsServiceMode && !_hub.IsRecoveryMode, ex => Notify(ex.Message, true));
        Decisions = new DecisionViewModel(Threats);

        hub.ModeChanged += () => Post(() => _ = ReloadAsync());
        hub.StatusChanged += s => Post(() =>
        {
            Dashboard.ApplyStatus(s);
            _ = RefreshDatabaseStatusAsync();
        });
        hub.TelemetryUpdated += s => Post(() => Dashboard.AddSample(s));
        hub.ScanProgressChanged += p => Post(() => OnScanProgress(p));
        hub.ThreatRaised += t => Post(() => OnThreatRaised(t));
        hub.ThreatUpdated += t => Post(() => OnThreatUpdated(t));
        Threats.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ThreatsViewModel.PendingCount))
            {
                Raise(nameof(PendingCount));
            }
        };

        // Список процессов обновляется, только пока открыт дашборд.
        _processTimer = new DispatcherTimer(TimeSpan.FromSeconds(5), DispatcherPriority.Background, OnProcessTimer, _ui);
        _processTimer.Start();
    }

    /// <summary>Автоматически нейтрализованная угроза — для уведомления в трее.</summary>
    public event Action<ThreatEvent>? ThreatNeutralized;

    /// <summary>Спорная находка ждёт решения — для всплывающего окна.</summary>
    public event Action? DecisionRequested;

    public DashboardViewModel Dashboard { get; }

    public ScanViewModel Scan { get; }

    public ThreatsViewModel Threats { get; }

    public QuarantineViewModel Quarantine { get; }

    public StartupViewModel Startup { get; }

    public ReportsViewModel Reports { get; }

    public BehavioralViewModel Behavioral { get; }

    public SettingsViewModel Settings { get; }

    /// <summary>«Запустить службу»: <c>sc.exe start SentinelService</c> с запросом прав администратора.</summary>
    public System.Windows.Input.ICommand StartServiceCommand { get; }

    public DecisionViewModel Decisions { get; }

    public Section Section
    {
        get => _section;
        set
        {
            if (Set(ref _section, value))
            {
                _ = RefreshSectionAsync(value);
            }
        }
    }

    public int PendingCount => Threats.PendingCount;

    public bool IsServiceMode
    {
        get => _isServiceMode;
        private set
        {
            if (Set(ref _isServiceMode, value))
            {
                Raise(nameof(ModeTitle));
                Raise(nameof(ModeDetail));
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string ModeTitle => _hub.IsRecoveryMode ? "Режим восстановления (Автономно)" : IsServiceMode ? "Служба Sentinel" : "Автономный режим";

    /// <summary>Режим загрузки, определённый при старте (Безопасный режим или WinRE).</summary>
    public BootEnvironment BootEnvironment { get; set; } = BootEnvironment.Normal;

    public string ModeDetail => _hub.IsRecoveryMode
        ? $"{_hub.BootEnvironment.Describe()}: службы Windows ограничены, интерфейс отрисовывается программно, Sentinel работает напрямую через Sentinel.Core."
          + (_hub.LocalDataDirectory is { } recoveryDir ? $" Данные: {recoveryDir}" : string.Empty)
        : IsServiceMode
        ? "Подключено к фоновой службе Sentinel.Service (канал \\\\.\\pipe\\" + IpcProtocol.DefaultPipeName + "). Защита работает и при закрытом окне."
        : "Служба не запущена: приложение работает напрямую через Sentinel.Core. Защита действует, пока Sentinel открыт или свёрнут в трей."
          + (_hub.LocalDataDirectory is { } dir ? $" Данные: {dir}" : string.Empty);

    public string Version
    {
        get => _version;
        private set => Set(ref _version, value);
    }

    public bool IsReady
    {
        get => _isReady;
        private set => Set(ref _isReady, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => Set(ref _statusMessage, value);
    }

    public bool StatusIsError
    {
        get => _statusIsError;
        private set => Set(ref _statusIsError, value);
    }

    /// <summary>Подключение к службе или запуск автономного режима и первая загрузка данных.</summary>
    public async Task InitializeAsync()
    {
        try
        {
            await _hub.InitializeAsync(BootEnvironment);
            IsReady = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Text.Json.JsonException)
        {
            Notify($"Не удалось запустить движок Sentinel: {ex.Message}", true);
        }
    }

    public async Task QuickScanAsync()
    {
        Section = Section.Scan;
        if (!Scan.IsActive)
        {
            await Scan.StartAsync(ScanMode.Quick);
        }
    }

    public async Task FullScanAsync()
    {
        Section = Section.Scan;
        if (!Scan.IsActive)
        {
            await Scan.StartAsync(ScanMode.Full);
        }
    }

    private async Task StartServiceAsync()
    {
        var result = await BackendHub.StartServiceAsync();
        Notify(result);
    }

    /// <summary>Статус баз на дашборде и в настройках обновляется по событию службы (например, после «Обновить базы»).</summary>
    private async Task RefreshDatabaseStatusAsync()
    {
        if (!IsReady)
        {
            return;
        }

        try
        {
            await Dashboard.RefreshDatabaseAsync();

            // Строка состояния выставляется при нажатии «Обновить базы» и сама не меняется: когда служба сообщила о
            // завершении, «выполняется…» заменяется итогом (сколько источников и новых хешей, или ошибка).
            const string running = "Обновление баз выполняется…";
            if (StatusMessage == running && Dashboard.Database.LastStatus is { Length: > 0 } result && result != running)
            {
                Notify(result, result.StartsWith("Обновление не выполнено", StringComparison.Ordinal));
            }

            if (Section == Section.Settings)
            {
                await Settings.RefreshDatabaseAsync();
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException)
        {
            Notify(ex.Message, true);
        }
    }

    public async Task SetRealtimeAsync(bool enabled)
    {
        try
        {
            Notify(await _hub.SetRealtimeProtectionAsync(enabled));
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException)
        {
            Notify(ex.Message, true);
        }
    }

    public void Dispose() => _processTimer.Stop();

    private async Task ReloadAsync()
    {
        IsServiceMode = _hub.IsServiceMode;
        Startup.Invalidate();
        try
        {
            await Dashboard.RefreshAsync();
            Version = Dashboard.Status.Version;
            await Scan.RefreshAsync();
            await Threats.RefreshAsync();
            Decisions.Sync();
            if (Section is not (Section.Dashboard or Section.Scan or Section.Threats))
            {
                await RefreshSectionAsync(Section);
            }

            Notify(_hub.IsRecoveryMode
                ? $"{_hub.BootEnvironment.Describe()}: режим восстановления, автономная работа."
                : IsServiceMode ? "Подключено к службе Sentinel." : "Автономный режим: служба не запущена.");
            Raise(nameof(ModeTitle));
            Raise(nameof(ModeDetail));
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException)
        {
            Notify(ex.Message, true);
        }
    }

    private async Task RefreshSectionAsync(Section section)
    {
        if (!IsReady)
        {
            return;
        }

        SectionViewModel target = section switch
        {
            Section.Scan => Scan,
            Section.Threats => Threats,
            Section.Quarantine => Quarantine,
            Section.Startup => Startup,
            Section.Reports => Reports,
            Section.Behavioral => Behavioral,
            Section.Settings => Settings,
            _ => Dashboard,
        };
        try
        {
            await target.RefreshAsync();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException or TimeoutException
            or OperationCanceledException or System.Text.Json.JsonException or NotSupportedException or UnauthorizedAccessException
            or ArgumentException or KeyNotFoundException)
        {
            // Раньше таймаут или ошибка разбора ответа молча оставляли раздел пустым: теперь видно, что случилось.
            Notify($"Раздел не загрузился: {ex.Message}. Нажмите «Обновить» или проверьте, что служба Sentinel запущена.", true);
        }
    }

    private async Task OpenReportAsync(string id)
    {
        Section = Section.Reports;
        try
        {
            await Reports.SelectAsync(id);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException)
        {
            Notify(ex.Message, true);
        }
    }

    private void OnScanProgress(ScanProgress progress)
    {
        var finished = Scan.Progress.IsActive && !progress.IsActive;
        Scan.Apply(progress);
        if (finished)
        {
            Notify(progress.Message ?? Scan.StateText, progress.State == ScanState.Failed);
            Startup.Invalidate();
            if (Section is Section.Quarantine or Section.Reports)
            {
                _ = RefreshSectionAsync(Section);
            }
        }
    }

    private void OnThreatRaised(ThreatEvent threat)
    {
        Threats.Upsert(threat);
        if (threat.Status == ThreatStatus.PendingDecision)
        {
            Decisions.Sync();
            DecisionRequested?.Invoke();
        }
        else if (threat.Status is ThreatStatus.Quarantined or ThreatStatus.Terminated or ThreatStatus.Cleaned)
        {
            ThreatNeutralized?.Invoke(threat);
        }
    }

    private void OnThreatUpdated(ThreatEvent threat)
    {
        Threats.Upsert(threat);
        Decisions.Sync();
        if (Section == Section.Quarantine)
        {
            _ = RefreshSectionAsync(Section);
        }
    }

    private async void OnProcessTimer(object? sender, EventArgs e)
    {
        if (!IsReady || Section != Section.Dashboard || Application.Current.MainWindow is not { IsVisible: true })
        {
            return;
        }

        try
        {
            await Dashboard.RefreshProcessesAsync();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException)
        {
            // Список процессов второстепенен: сбой обновления не должен перекрывать строку состояния.
        }
    }

    private void Notify(string message, bool isError)
    {
        StatusMessage = message;
        StatusIsError = isError;
    }

    private void Notify(OperationResult result) => Notify(result.Message, !result.Success);

    private void Notify(string message) => Notify(message, false);

    private void Post(Action action)
    {
        if (!_ui.HasShutdownStarted)
        {
            _ui.BeginInvoke(action);
        }
    }
}

/// <summary>
/// Модель всплывающего окна подтверждения: показывает очередную спорную находку (Medium)
/// и применяет решение пользователя — «В карантин» или «В исключения».
/// </summary>
public sealed class DecisionViewModel : ObservableObject
{
    private readonly ThreatsViewModel _threats;
    private readonly HashSet<string> _postponed = [];
    private ThreatEvent? _current;

    public DecisionViewModel(ThreatsViewModel threats)
    {
        _threats = threats;
        QuarantineCommand = new AsyncCommand(() => ResolveAsync(ThreatDecision.Quarantine), () => Current is not null, _ => Sync());
        AllowCommand = new AsyncCommand(() => ResolveAsync(ThreatDecision.Allow), () => Current is not null, _ => Sync());
        LaterCommand = new RelayCommand(() =>
        {
            if (Current is { } threat)
            {
                _postponed.Add(threat.Id);
            }

            Sync();
        });
    }

    public ICommand QuarantineCommand { get; }

    public ICommand AllowCommand { get; }

    public ICommand LaterCommand { get; }

    /// <summary>Находка, по которой сейчас запрашивается решение; <c>null</c> — окно скрывается.</summary>
    public ThreatEvent? Current
    {
        get => _current;
        private set
        {
            if (Set(ref _current, value))
            {
                Raise(nameof(HasCurrent));
            }
        }
    }

    public bool HasCurrent => Current is not null;

    public string QueueText
    {
        get
        {
            var more = Queue().Count() - 1;
            return more > 0 ? $"Ещё ждут решения: {more}" : "Решение можно принять и позже — в разделе «Угрозы и события».";
        }
    }

    /// <summary>Пересчитывает текущую находку по очереди ожидающих решений.</summary>
    public void Sync()
    {
        Current = Queue().LastOrDefault(); // самая ранняя из ожидающих (список отсортирован «новые первыми»)
        Raise(nameof(QueueText));
        CommandManager.InvalidateRequerySuggested();
    }

    private IEnumerable<ThreatEvent> Queue() =>
        _threats.Items.Where(t => t.Status == ThreatStatus.PendingDecision && !_postponed.Contains(t.Id));

    private async Task ResolveAsync(ThreatDecision decision)
    {
        if (Current is { } threat)
        {
            await _threats.ResolveAsync(threat, decision);
        }

        Sync();
    }
}
