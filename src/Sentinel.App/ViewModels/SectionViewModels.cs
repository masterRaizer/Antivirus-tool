using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Data;
using System.Windows.Input;
using Sentinel.App.Mvvm;
using Sentinel.App.Services;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Reporting;
using Sentinel.Core.Signatures;

namespace Sentinel.App.ViewModels;

/// <summary>Общее для разделов: доступ к движку и вывод результата операции в строку состояния.</summary>
public abstract class SectionViewModel(BackendHub hub, Action<string, bool> notify) : ObservableObject
{
    private bool _isBusy;

    protected BackendHub Hub { get; } = hub;

    public bool IsBusy
    {
        get => _isBusy;
        protected set => Set(ref _isBusy, value);
    }

    public abstract Task RefreshAsync();

    protected void Notify(string message, bool isError = false) => notify(message, isError);

    protected void Notify(OperationResult result) => notify(result.Message, !result.Success);

    protected void OnError(Exception ex) => notify(ex.Message, true);

    protected AsyncCommand Command(Func<Task> execute, Func<bool>? canExecute = null) => new(execute, canExecute, OnError);

    protected AsyncCommand Command<T>(Func<T, Task> execute)
        where T : class =>
        new(p => p is T item ? execute(item) : Task.CompletedTask, p => p is T, OnError);
}

// ---- 1. Дашборд ----------------------------------------------------------------

public sealed class DashboardViewModel : SectionViewModel
{
    private const int ChartPoints = 60;
    private ServiceStatus _status = new();
    private bool _realtimeEnabled;
    private bool _applyingStatus;
    private string _cpuText = "0 %";
    private string _ramText = "0 %";
    private string _diskText = "0 %";
    private string _ramDetail = string.Empty;

    private Sentinel.Core.ThreatIntel.DatabaseStatus _database = new();

    public DashboardViewModel(BackendHub hub, Action<string, bool> notify, Func<Task> quickScan, Func<Task> fullScan, Action openSettings)
        : base(hub, notify)
    {
        QuickScanCommand = Command(quickScan);
        FullScanCommand = Command(fullScan);
        RefreshProcessesCommand = Command(RefreshProcessesAsync);
        UpdateDatabasesCommand = Command(async () =>
        {
            var status = await Hub.UpdateDatabasesAsync();
            Database = status;
            Notify(status.LastStatus);
        });
        OpenSettingsCommand = new RelayCommand(openSettings);
    }

    public ICommand FullScanCommand { get; }

    public ICommand UpdateDatabasesCommand { get; }

    public ICommand OpenSettingsCommand { get; }

    public Sentinel.Core.ThreatIntel.DatabaseStatus Database
    {
        get => _database;
        private set
        {
            if (Set(ref _database, value))
            {
                Raise(nameof(DatabaseTitle));
                Raise(nameof(DatabaseDetail));
            }
        }
    }

    public string DatabaseTitle => Database.HashCount > 0
        ? string.Format(System.Globalization.CultureInfo.CurrentCulture, "{0:N0} хешей угроз", Database.HashCount)
        : "База угроз не загружена";

    public string DatabaseDetail
    {
        get
        {
            var stamp = Database.DatabaseTimestampUtc is { } t ? t.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture) : "—";
            return $"Версия: {stamp}. {Database.LastStatus}";
        }
    }

    public async Task RefreshDatabaseAsync() => Database = (await Hub.GetSettingsAsync()).Database;

    public ObservableCollection<double> Cpu { get; } = [];

    public ObservableCollection<double> Ram { get; } = [];

    public ObservableCollection<double> Disk { get; } = [];

    public ObservableCollection<ProcessInfo> Processes { get; } = [];

    public ICommand QuickScanCommand { get; }

    public ICommand RefreshProcessesCommand { get; }

    public ServiceStatus Status
    {
        get => _status;
        private set
        {
            if (Set(ref _status, value))
            {
                Raise(nameof(ProtectionTitle));
                Raise(nameof(ProtectionDetail));
                Raise(nameof(HasProcesses));
            }
        }
    }

    /// <summary>Тумблер защиты: изменение пользователем сразу отправляется движку.</summary>
    public bool RealtimeEnabled
    {
        get => _realtimeEnabled;
        set
        {
            if (Set(ref _realtimeEnabled, value) && !_applyingStatus)
            {
                _ = ToggleRealtimeAsync(value);
            }
        }
    }

    public string ProtectionTitle => Status.RealtimeEnabled ? "Защита в реальном времени активна" : "Защита в реальном времени приостановлена";

    public string ProtectionDetail => Status.RealtimeEnabled
        ? $"Наблюдение за каталогами: {Status.WatchedDirectories.Count}; правил загружено: {Status.RulesLoaded}. Опасное нейтрализуется сразу, о спорном Sentinel спросит."
        : "Новые файлы и процессы не проверяются. Включите защиту или запустите проверку вручную.";

    public string CpuText
    {
        get => _cpuText;
        private set => Set(ref _cpuText, value);
    }

    public string RamText
    {
        get => _ramText;
        private set => Set(ref _ramText, value);
    }

    public string DiskText
    {
        get => _diskText;
        private set => Set(ref _diskText, value);
    }

    public string RamDetail
    {
        get => _ramDetail;
        private set => Set(ref _ramDetail, value);
    }

    public bool HasProcesses => Processes.Count > 0;

    public override async Task RefreshAsync()
    {
        ApplyStatus(await Hub.GetStatusAsync());
        var history = await Hub.GetTelemetryHistoryAsync();
        Cpu.Clear();
        Ram.Clear();
        Disk.Clear();
        foreach (var sample in history.TakeLast(ChartPoints))
        {
            AddSample(sample);
        }

        await RefreshProcessesAsync();
        await RefreshDatabaseAsync();
    }

    public void ApplyStatus(ServiceStatus status)
    {
        Status = status;
        _applyingStatus = true;
        RealtimeEnabled = status.RealtimeEnabled;
        _applyingStatus = false;
    }

    public void AddSample(TelemetrySample sample)
    {
        Push(Cpu, sample.CpuPercent);
        Push(Ram, sample.RamPercent);
        Push(Disk, sample.DiskPercent);
        CpuText = $"{sample.CpuPercent:0} %";
        RamText = $"{sample.RamPercent:0} %";
        DiskText = $"{sample.DiskPercent:0} %";
        RamDetail = sample.RamTotalBytes > 0
            ? $"{BytesConverter.Format(sample.RamUsedBytes)} из {BytesConverter.Format(sample.RamTotalBytes)}"
            : string.Empty;
    }

    public async Task RefreshProcessesAsync()
    {
        var rows = await Hub.GetProcessesAsync();
        Processes.Clear();
        foreach (var row in rows)
        {
            Processes.Add(row);
        }

        Raise(nameof(HasProcesses));
    }

    private async Task ToggleRealtimeAsync(bool enabled)
    {
        try
        {
            Notify(await Hub.SetRealtimeProtectionAsync(enabled));
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException)
        {
            OnError(ex);
        }
    }

    private static void Push(ObservableCollection<double> series, double value)
    {
        series.Add(Math.Clamp(value, 0, 100));
        while (series.Count > ChartPoints)
        {
            series.RemoveAt(0);
        }
    }
}

// ---- 2. Сканирование -----------------------------------------------------------

public sealed class ScanViewModel : SectionViewModel
{
    private readonly Action<string> _openReport;
    private ScanMode _mode = ScanMode.Quick;
    private string _customPath = string.Empty;
    private ScanProgress _progress = ScanProgress.Idle;

    public ScanViewModel(BackendHub hub, Action<string, bool> notify, Action<string> openReport)
        : base(hub, notify)
    {
        _openReport = openReport;
        StartCommand = Command(() => StartAsync(Mode), () => !Progress.IsActive && (Mode != ScanMode.Custom || !string.IsNullOrWhiteSpace(CustomPath)));
        PauseResumeCommand = Command(
            async () => Notify(Progress.State == ScanState.Paused ? await Hub.ResumeScanAsync() : await Hub.PauseScanAsync()),
            () => Progress.State is ScanState.Running or ScanState.Paused);
        StopCommand = Command(async () => Notify(await Hub.StopScanAsync()), () => Progress.IsActive);
        BrowseCommand = new RelayCommand(Browse, () => !Progress.IsActive);
        OpenReportCommand = new RelayCommand(() => _openReport(Progress.ReportId!), () => Progress.ReportId is not null);
    }

    public ICommand StartCommand { get; }

    public ICommand PauseResumeCommand { get; }

    public ICommand StopCommand { get; }

    public ICommand BrowseCommand { get; }

    public ICommand OpenReportCommand { get; }

    public ScanMode Mode
    {
        get => _mode;
        set
        {
            if (Set(ref _mode, value))
            {
                Raise(nameof(IsCustom));
            }
        }
    }

    public bool IsCustom => Mode == ScanMode.Custom;

    public string CustomPath
    {
        get => _customPath;
        set => Set(ref _customPath, value);
    }

    public ScanProgress Progress
    {
        get => _progress;
        private set
        {
            if (Set(ref _progress, value))
            {
                foreach (var name in new[]
                         {
                             nameof(IsActive), nameof(IsIdle), nameof(StateText), nameof(PercentText), nameof(ScannedText), nameof(SpeedText),
                             nameof(ElapsedText), nameof(CurrentItemText), nameof(PauseResumeText), nameof(HasResult), nameof(ResultIsWarning),
                             nameof(WorkersText), nameof(CacheText),
                         })
                {
                    Raise(name);
                }

                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool IsActive => Progress.IsActive;

    public bool IsIdle => !Progress.IsActive;

    public string StateText => Progress.State switch
    {
        ScanState.Counting => "Подсчёт объектов…",
        ScanState.Running => string.IsNullOrEmpty(Progress.Stage) ? "Идёт проверка" : $"Идёт проверка · {Progress.Stage}",
        ScanState.Paused => "Проверка приостановлена",
        ScanState.Completed => "Проверка завершена",
        ScanState.Cancelled => "Проверка остановлена",
        ScanState.Failed => "Проверка прервана ошибкой",
        _ => "Проверка не запущена",
    };

    public string PercentText => Progress.State == ScanState.Counting ? "…" : $"{Progress.Percent:0} %";

    public string ScannedText => Progress.Total > 0
        ? $"{Progress.Scanned:N0} из {(Progress.EnumerationComplete || !Progress.IsActive ? string.Empty : "≈")}{Progress.Total:N0}"
        : $"{Progress.Scanned:N0}";

    public string SpeedText => $"{Progress.ItemsPerSecond:N0} объектов/сек";

    /// <summary>Пул проверки: режим (процессы или потоки), занятые рабочие и размер пула.</summary>
    public string WorkersText => Progress.Workers == 0
        ? "—"
        : $"{Progress.PoolMode}: {Progress.ActiveWorkers} из {Progress.Workers}";

    public string CacheText => Progress.Errors > 0
        ? $"{Progress.CachedSkipped:N0} по кэшу · ошибок {Progress.Errors:N0}"
        : $"{Progress.CachedSkipped:N0} по кэшу";

    public string ElapsedText => DurationConverter.Format(Progress.ElapsedSeconds);

    public string CurrentItemText => string.IsNullOrEmpty(Progress.CurrentItem) ? "—" : Progress.CurrentItem;

    public string PauseResumeText => Progress.State == ScanState.Paused ? "Продолжить" : "Пауза";

    public bool HasResult => Progress.State is ScanState.Completed or ScanState.Cancelled or ScanState.Failed;

    public bool ResultIsWarning => Progress.Threats > 0 || Progress.State == ScanState.Failed;

    public override async Task RefreshAsync() => Progress = (await Hub.GetStatusAsync()).Scan;

    public void Apply(ScanProgress progress) => Progress = progress;

    public async Task StartAsync(ScanMode mode)
    {
        Mode = mode;
        var result = await Hub.StartScanAsync(new ScanRequest(mode, mode == ScanMode.Custom ? CustomPath.Trim() : null));
        Notify(result);
    }

    private void Browse()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Папка для проверки", Multiselect = false };
        if (dialog.ShowDialog() == true)
        {
            CustomPath = dialog.FolderName;
            Mode = ScanMode.Custom;
        }
    }
}

// ---- 3. Угрозы и события -------------------------------------------------------

public enum ThreatFilter
{
    All,
    Pending,
    Neutralized,

    /// <summary>Журнал: зафиксированное без действий, проигнорированное, разрешённое, заблокированное белым списком, сбои.</summary>
    Journal,
}

public sealed class ThreatsViewModel : SectionViewModel
{
    private ThreatFilter _filter = ThreatFilter.All;

    public ThreatsViewModel(BackendHub hub, Action<string, bool> notify)
        : base(hub, notify)
    {
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is ThreatEvent t && Filter switch
        {
            ThreatFilter.Pending => t.Status == ThreatStatus.PendingDecision,
            ThreatFilter.Neutralized => t.Status is ThreatStatus.Quarantined or ThreatStatus.Terminated or ThreatStatus.Cleaned,
            ThreatFilter.Journal => t.Status is ThreatStatus.Detected or ThreatStatus.Skipped or ThreatStatus.Allowed or ThreatStatus.Blocked or ThreatStatus.Failed,
            _ => true,
        };
        QuarantineCommand = Command<ThreatEvent>(t => ResolveAsync(t, ThreatDecision.Quarantine));
        AllowCommand = Command<ThreatEvent>(t => ResolveAsync(t, ThreatDecision.Allow));
        IgnoreCommand = Command<ThreatEvent>(t => ResolveAsync(t, ThreatDecision.Ignore));
    }

    public ObservableCollection<ThreatEvent> Items { get; } = [];

    public ICollectionView View { get; }

    public ICommand QuarantineCommand { get; }

    public ICommand AllowCommand { get; }

    public ICommand IgnoreCommand { get; }

    public ThreatFilter Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value))
            {
                View.Refresh();
                Raise(nameof(IsEmpty));
            }
        }
    }

    public int PendingCount => Items.Count(t => t.Status == ThreatStatus.PendingDecision);

    public string Summary => Items.Count == 0
        ? "Событий пока нет"
        : $"Всего событий: {Items.Count} · ждут решения: {PendingCount}";

    public bool IsEmpty => View.IsEmpty;

    public override async Task RefreshAsync()
    {
        var threats = await Hub.GetThreatsAsync();
        Items.Clear();
        foreach (var threat in threats)
        {
            Items.Add(threat);
        }

        RaiseCounts();
    }

    /// <summary>Новая или обновлённая находка (события движка).</summary>
    public void Upsert(ThreatEvent threat)
    {
        var index = IndexOf(threat.Id);
        if (index >= 0)
        {
            Items[index] = threat;
        }
        else
        {
            Items.Insert(0, threat);
        }

        RaiseCounts();
    }

    public async Task ResolveAsync(ThreatEvent threat, ThreatDecision decision)
    {
        var updated = await Hub.ResolveThreatAsync(threat.Id, decision);
        Upsert(updated);
        Notify(updated.ActionMessage ?? ThreatStatusTextConverter.Text(updated.Status), updated.Status == ThreatStatus.Failed);
    }

    private int IndexOf(string id)
    {
        for (var i = 0; i < Items.Count; i++)
        {
            if (Items[i].Id == id)
            {
                return i;
            }
        }

        return -1;
    }

    private void RaiseCounts()
    {
        Raise(nameof(PendingCount));
        Raise(nameof(Summary));
        Raise(nameof(IsEmpty));
    }
}

// ---- 4. Карантин и откат -------------------------------------------------------

public sealed class QuarantineViewModel : SectionViewModel
{
    public QuarantineViewModel(BackendHub hub, Action<string, bool> notify)
        : base(hub, notify)
    {
        RefreshCommand = Command(RefreshAsync);
        RestoreCommand = Command<QuarantineItem>(async item =>
        {
            Notify(await Hub.RestoreQuarantineAsync(item.Id));
            await RefreshAsync();
        });
        UndoCommand = Command<RollbackItem>(async item =>
        {
            Notify(await Hub.UndoRollbackAsync(item.Id));
            await RefreshAsync();
        });
        DeleteCommand = Command<QuarantineItem>(async item =>
        {
            var answer = System.Windows.MessageBox.Show(
                $"Удалить навсегда?\n\n{item.OriginalPath}\n\nВосстановить файл после этого будет невозможно.",
                "Sentinel — удаление из карантина", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning, System.Windows.MessageBoxResult.No);
            if (answer != System.Windows.MessageBoxResult.Yes)
            {
                return;
            }

            Notify(await Hub.DeleteQuarantineAsync(item.Id));
            await RefreshAsync();
        });
    }

    public ICommand DeleteCommand { get; }

    public ObservableCollection<QuarantineItem> Files { get; } = [];

    public ObservableCollection<RollbackItem> Rollback { get; } = [];

    public ICommand RefreshCommand { get; }

    public ICommand RestoreCommand { get; }

    public ICommand UndoCommand { get; }

    public string FilesHeader => $"Файлы в карантине ({Files.Count(f => f.IsActive)})";

    public string RollbackHeader => $"Откат конфигурации ({Rollback.Count(r => !r.Undone)})";

    public bool NoFiles => Files.Count == 0;

    public bool NoRollback => Rollback.Count == 0;

    public override async Task RefreshAsync()
    {
        var files = await Hub.GetQuarantineAsync();
        var rollback = await Hub.GetRollbackAsync();
        Files.Clear();
        foreach (var file in files)
        {
            Files.Add(file);
        }

        Rollback.Clear();
        foreach (var entry in rollback)
        {
            Rollback.Add(entry);
        }

        Raise(nameof(FilesHeader));
        Raise(nameof(RollbackHeader));
        Raise(nameof(NoFiles));
        Raise(nameof(NoRollback));
    }
}

// ---- 5. Автозагрузка и службы --------------------------------------------------

public sealed class StartupViewModel : SectionViewModel
{
    private bool _onlyFlagged;
    private string _search = string.Empty;
    private string? _note;
    private string _summary = "Нажмите «Обновить», чтобы собрать сводку.";
    private bool _loaded;

    public StartupViewModel(BackendHub hub, Action<string, bool> notify)
        : base(hub, notify)
    {
        View = CollectionViewSource.GetDefaultView(Items);
        // Однотипные информационные записи (например, блокировка телеметрии в hosts) собраны в свёрнутые группы.
        View.GroupDescriptions.Add(new PropertyGroupDescription(nameof(StartupItem.Group)));
        View.SortDescriptions.Add(new SortDescription(nameof(StartupItem.Group), ListSortDirection.Ascending));
        View.SortDescriptions.Add(new SortDescription(nameof(StartupItem.Severity), ListSortDirection.Descending));
        View.Filter = o => o is StartupItem item
            && (!OnlyFlagged || item.Flagged || item.NotSigned)
            && (Search.Length == 0 || Matches(item, Search));
        RefreshCommand = Command(() => LoadAsync(refresh: true), () => !IsBusy);
        CleanCommand = Command<StartupItem>(async item =>
        {
            Notify(await Hub.CleanStartupItemAsync(item.Key));
            await LoadAsync(refresh: false);
        });
        AllowCommand = Command<StartupItem>(async item =>
        {
            if (string.IsNullOrWhiteSpace(item.Target))
            {
                return;
            }

            // Тот же путь, что и в «Настройках и базах»: список разрешённого хранится в службе.
            var settings = await Hub.GetSettingsAsync();
            var result = await Hub.SaveSettingsAsync(new SettingsUpdate
            {
                AutoUpdateDatabases = settings.AutoUpdateDatabases,
                AllowedPaths = [.. settings.AllowedPaths, item.Target],
                AllowedProcesses = settings.AllowedProcesses,
                AllowedHashes = settings.AllowedHashes,
            });
            Notify(result.Success ? $"В исключения добавлено: {item.Target}" : result.Message, !result.Success);
            await LoadAsync(refresh: true);
        });
    }

    public ICommand AllowCommand { get; }

    public ObservableCollection<StartupItem> Items { get; } = [];

    public ICollectionView View { get; }

    public ICommand RefreshCommand { get; }

    public ICommand CleanCommand { get; }

    public bool OnlyFlagged
    {
        get => _onlyFlagged;
        set
        {
            if (Set(ref _onlyFlagged, value))
            {
                View.Refresh();
            }
        }
    }

    public string Search
    {
        get => _search;
        set
        {
            if (Set(ref _search, value ?? string.Empty))
            {
                View.Refresh();
            }
        }
    }

    public string? Note
    {
        get => _note;
        private set => Set(ref _note, value);
    }

    public string Summary
    {
        get => _summary;
        private set => Set(ref _summary, value);
    }

    /// <summary>Сводка собирается при первом открытии раздела (аудит реестра и служб занимает секунды).</summary>
    public override Task RefreshAsync() => _loaded ? Task.CompletedTask : LoadAsync(refresh: false);

    public void Invalidate() => _loaded = false;

    private async Task LoadAsync(bool refresh)
    {
        IsBusy = true;
        try
        {
            Summary = "Сбор сведений: реестр, службы, планировщик задач, WMI, hosts, исключения Defender…";
            var snapshot = await Hub.GetStartupAsync(refresh);
            Items.Clear();
            foreach (var item in snapshot.Items)
            {
                Items.Add(item);
            }

            Note = snapshot.Note;
            Summary = $"Записей: {Items.Count} · нестандартных: {Items.Count(i => i.Flagged)} · без подписи: {Items.Count(i => i.NotSigned)}";
            _loaded = true;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static bool Matches(StartupItem item, string text) =>
        Contains(item.Name, text) || Contains(item.Location, text) || Contains(item.Command, text)
        || Contains(item.Target, text) || Contains(item.Category, text);

    private static bool Contains(string? value, string text) =>
        value is not null && value.Contains(text, StringComparison.OrdinalIgnoreCase);
}

// ---- 6. История отчётов --------------------------------------------------------

public sealed class ReportsViewModel : SectionViewModel
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);
    private ReportSummary? _selected;
    private SentinelReport? _details;
    private string? _lastExportPath;

    public ReportsViewModel(BackendHub hub, Action<string, bool> notify)
        : base(hub, notify)
    {
        RefreshCommand = Command(RefreshAsync);
        ExportHtmlCommand = Command(() => ExportAsync(ReportFormat.Html), () => Selected is not null);
        ExportJsonCommand = Command(() => ExportAsync(ReportFormat.Json), () => Selected is not null);
        OpenExportFolderCommand = new RelayCommand(
            () => Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{LastExportPath}\"") { UseShellExecute = true })?.Dispose(),
            () => LastExportPath is not null);
    }

    public ObservableCollection<ReportSummary> Items { get; } = [];

    public ICommand RefreshCommand { get; }

    public ICommand ExportHtmlCommand { get; }

    public ICommand ExportJsonCommand { get; }

    public ICommand OpenExportFolderCommand { get; }

    public static string ExportDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Sentinel Reports");

    public ReportSummary? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                _ = LoadDetailsAsync(value);
            }
        }
    }

    public SentinelReport? Details
    {
        get => _details;
        private set
        {
            if (Set(ref _details, value))
            {
                Raise(nameof(HasDetails));
            }
        }
    }

    public bool HasDetails => Details is not null;

    public bool IsEmpty => Items.Count == 0;

    public string? LastExportPath
    {
        get => _lastExportPath;
        private set => Set(ref _lastExportPath, value);
    }

    public override async Task RefreshAsync()
    {
        var keep = Selected?.Id;
        var reports = await Hub.GetReportsAsync();
        Items.Clear();
        foreach (var report in reports)
        {
            Items.Add(report);
        }

        Raise(nameof(IsEmpty));
        Selected = Items.FirstOrDefault(r => r.Id == keep) ?? Items.FirstOrDefault();
    }

    public async Task SelectAsync(string id)
    {
        await RefreshAsync();
        Selected = Items.FirstOrDefault(r => r.Id == id) ?? Selected;
    }

    private async Task LoadDetailsAsync(ReportSummary? summary)
    {
        if (summary is null)
        {
            Details = null;
            return;
        }

        try
        {
            var export = await Hub.ExportReportAsync(summary.Id, ReportFormat.Json);
            if (Selected?.Id == summary.Id)
            {
                Details = ReportGenerator.FromJson(export.Content);
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or IpcRemoteException or System.Text.Json.JsonException)
        {
            Details = null;
            OnError(ex);
        }
    }

    /// <summary>Экспорт в один клик: файл сохраняется в «Документы\Sentinel Reports», HTML сразу открывается.</summary>
    private async Task ExportAsync(ReportFormat format)
    {
        if (Selected is not { } summary)
        {
            return;
        }

        var export = await Hub.ExportReportAsync(summary.Id, format);
        Directory.CreateDirectory(ExportDirectory);
        var path = Path.Combine(ExportDirectory, Path.GetFileName(export.FileName));
        await File.WriteAllTextAsync(path, export.Content, Utf8NoBom);
        LastExportPath = path;
        CommandManager.InvalidateRequerySuggested();
        Notify($"Отчёт сохранён: {path}");
        if (format == ReportFormat.Html)
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true })?.Dispose();
        }
    }
}
