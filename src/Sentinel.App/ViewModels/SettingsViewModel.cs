using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Input;
using Sentinel.App.Mvvm;
using Sentinel.App.Services;
using Sentinel.Core.Ipc;
using Sentinel.Core.ThreatIntel;

namespace Sentinel.App.ViewModels;

/// <summary>Одна строка редактора исключений: значение и его вид (папка/файл, процесс, SHA-256).</summary>
public sealed record AllowedEntry(string Value, string Kind);

/// <summary>Состояние одного источника обновления баз для таблицы.</summary>
public sealed record FeedRow(string Name, string Status, string Counts, string Message);

// ---- 7. Настройки и базы ------------------------------------------------------

/// <summary>
/// Редактор <c>allowed_exclusions.json</c>, ключи облачных сервисов, автообновление баз и статус базы угроз.
/// «Сохранить и применить» отправляет всё службе одним запросом: служба перечитывает файлы сразу.
/// Значения ключей с сервера не приходят — показывается только, задан ли ключ.
/// </summary>
public sealed class SettingsViewModel : SectionViewModel
{
    private string _newValue = string.Empty;
    private AllowedEntry? _selected;
    private bool _autoUpdate = true;
    private bool _hasKaspersky;
    private bool _hasVirusTotal;
    private bool _hasAbuseCh;
    private bool _clearKaspersky;
    private bool _clearVirusTotal;
    private bool _clearAbuseCh;
    private DatabaseStatus _database = new();
    private string _dataDirectory = string.Empty;

    public SettingsViewModel(BackendHub hub, Action<string, bool> notify)
        : base(hub, notify)
    {
        AddFolderCommand = new RelayCommand(AddFolder);
        AddFileCommand = new RelayCommand(AddFile);
        AddHashCommand = new RelayCommand(AddHash, () => !string.IsNullOrWhiteSpace(NewValue));
        AddProcessCommand = new RelayCommand(AddProcess, () => !string.IsNullOrWhiteSpace(NewValue));
        RemoveCommand = new RelayCommand(Remove, () => Selected is not null);
        SaveCommand = Command(SaveAsync, () => !IsBusy);
        UpdateDatabasesCommand = Command(UpdateDatabasesAsync, () => !IsBusy);
        ReloadCommand = Command(RefreshAsync, () => !IsBusy);
    }

    public ObservableCollection<AllowedEntry> Allowed { get; } = [];

    public ObservableCollection<FeedRow> Feeds { get; } = [];

    public ICommand AddFolderCommand { get; }

    public ICommand AddFileCommand { get; }

    public ICommand AddHashCommand { get; }

    public ICommand AddProcessCommand { get; }

    public ICommand RemoveCommand { get; }

    public ICommand SaveCommand { get; }

    public ICommand UpdateDatabasesCommand { get; }

    public ICommand ReloadCommand { get; }

    /// <summary>Поле ввода: SHA-256 или имя процесса.</summary>
    public string NewValue
    {
        get => _newValue;
        set
        {
            if (Set(ref _newValue, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public AllowedEntry? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool AutoUpdateDatabases
    {
        get => _autoUpdate;
        set => Set(ref _autoUpdate, value);
    }

    /// <summary>Новые значения ключей из полей пароля; пустое — оставить прежний.</summary>
    public string KasperskyKey { get; set; } = string.Empty;

    public string VirusTotalKey { get; set; } = string.Empty;

    public string AbuseChKey { get; set; } = string.Empty;

    public bool ClearKaspersky
    {
        get => _clearKaspersky;
        set => Set(ref _clearKaspersky, value);
    }

    public bool ClearVirusTotal
    {
        get => _clearVirusTotal;
        set => Set(ref _clearVirusTotal, value);
    }

    public bool ClearAbuseCh
    {
        get => _clearAbuseCh;
        set => Set(ref _clearAbuseCh, value);
    }

    public string KasperskyState => _hasKaspersky ? "ключ задан" : "не задан";

    public string VirusTotalState => _hasVirusTotal ? "ключ задан" : "не задан";

    public string AbuseChState => _hasAbuseCh ? "ключ задан" : "не задан — используются открытые GitHub-источники и Feodo Tracker";

    public DatabaseStatus Database
    {
        get => _database;
        private set
        {
            if (Set(ref _database, value))
            {
                Raise(nameof(DatabaseSummary));
                Raise(nameof(DatabaseDetail));
            }
        }
    }

    public string DatabaseSummary => Database.HashCount > 0
        ? string.Format(CultureInfo.CurrentCulture, "{0:N0} SHA-256 известных угроз", Database.HashCount)
        : "База угроз не загружена";

    public string DatabaseDetail
    {
        get
        {
            var stamp = Database.DatabaseTimestampUtc is { } t ? t.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : "—";
            var success = Database.LastSuccessUtc is { } s ? s.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : "ещё не было";
            return $"Версия базы: {stamp}. Последнее успешное обновление: {success}. Сетевых индикаторов: {Database.NetworkIndicatorCount:N0}. {Database.LastStatus}";
        }
    }

    public string DataDirectory
    {
        get => _dataDirectory;
        private set => Set(ref _dataDirectory, value);
    }

    public override async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            Apply(await Hub.GetSettingsAsync());
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Только статус баз (по событию службы после обновления), без сброса несохранённых правок.</summary>
    public async Task RefreshDatabaseAsync() => ApplyDatabase((await Hub.GetSettingsAsync()).Database);

    private void Apply(SettingsSnapshot snapshot)
    {
        Allowed.Clear();
        foreach (var path in snapshot.AllowedPaths)
        {
            Allowed.Add(new AllowedEntry(path, "Путь"));
        }

        foreach (var process in snapshot.AllowedProcesses)
        {
            Allowed.Add(new AllowedEntry(process, "Процесс"));
        }

        foreach (var hash in snapshot.AllowedHashes)
        {
            Allowed.Add(new AllowedEntry(hash, "SHA-256"));
        }

        AutoUpdateDatabases = snapshot.AutoUpdateDatabases;
        _hasKaspersky = snapshot.HasKasperskyOpenTipApiKey;
        _hasVirusTotal = snapshot.HasVirusTotalApiKey;
        _hasAbuseCh = snapshot.HasAbuseChAuthKey;
        ClearKaspersky = ClearVirusTotal = ClearAbuseCh = false;
        Raise(nameof(KasperskyState));
        Raise(nameof(VirusTotalState));
        Raise(nameof(AbuseChState));
        DataDirectory = snapshot.DataDirectory;
        ApplyDatabase(snapshot.Database);
    }

    private void ApplyDatabase(DatabaseStatus status)
    {
        Database = status;
        Feeds.Clear();
        foreach (var source in status.Sources)
        {
            Feeds.Add(new FeedRow(source.Name, source.Status, $"{source.Hashes:N0} / {source.NetworkIndicators:N0}", source.Message ?? string.Empty));
        }
    }

    private async Task SaveAsync()
    {
        IsBusy = true;
        try
        {
            var result = await Hub.SaveSettingsAsync(new SettingsUpdate
            {
                KasperskyOpenTipApiKey = KeyUpdate(KasperskyKey, ClearKaspersky),
                VirusTotalApiKey = KeyUpdate(VirusTotalKey, ClearVirusTotal),
                AbuseChAuthKey = KeyUpdate(AbuseChKey, ClearAbuseCh),
                AutoUpdateDatabases = AutoUpdateDatabases,
                AllowedPaths = Allowed.Where(a => a.Kind == "Путь").Select(a => a.Value).ToArray(),
                AllowedProcesses = Allowed.Where(a => a.Kind == "Процесс").Select(a => a.Value).ToArray(),
                AllowedHashes = Allowed.Where(a => a.Kind == "SHA-256").Select(a => a.Value).ToArray(),
            });
            Notify(result);
            if (result.Success)
            {
                Apply(await Hub.GetSettingsAsync());
            }
        }
        finally
        {
            IsBusy = false;
        }

        static string? KeyUpdate(string value, bool clear) => clear ? string.Empty : string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private async Task UpdateDatabasesAsync()
    {
        var status = await Hub.UpdateDatabasesAsync();
        ApplyDatabase(status);
        Notify(status.LastStatus);
    }

    private void AddFolder()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Папка, которую Sentinel не будет трогать", Multiselect = true };
        if (dialog.ShowDialog() == true)
        {
            foreach (var folder in dialog.FolderNames)
            {
                AddUnique(new AllowedEntry(folder, "Путь"));
            }
        }
    }

    private void AddFile()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = "Файл, который Sentinel не будет трогать", Multiselect = true, CheckFileExists = true };
        if (dialog.ShowDialog() == true)
        {
            foreach (var file in dialog.FileNames)
            {
                AddUnique(new AllowedEntry(file, "Путь"));
            }
        }
    }

    private void AddHash()
    {
        if (!ThreatFeedParsers.TryNormalizeSha256(NewValue, out var hash))
        {
            Notify("SHA-256 должен состоять из 64 шестнадцатеричных символов.", true);
            return;
        }

        AddUnique(new AllowedEntry(hash, "SHA-256"));
        NewValue = string.Empty;
    }

    private void AddProcess()
    {
        var name = NewValue.Trim();
        if (name.IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0)
        {
            Notify("Недопустимые символы в имени процесса.", true);
            return;
        }

        AddUnique(new AllowedEntry(name, "Процесс"));
        NewValue = string.Empty;
    }

    private void Remove()
    {
        if (Selected is { } entry)
        {
            Allowed.Remove(entry);
            Selected = null;
            Notify("Запись удалена из списка. Нажмите «Сохранить и применить».");
        }
    }

    private void AddUnique(AllowedEntry entry)
    {
        if (Allowed.Any(a => a.Kind == entry.Kind && string.Equals(a.Value, entry.Value, StringComparison.OrdinalIgnoreCase)))
        {
            Notify($"«{entry.Value}» уже в списке.");
            return;
        }

        Allowed.Add(entry);
        Notify($"Добавлено: {entry.Value}. Нажмите «Сохранить и применить».");
    }
}
