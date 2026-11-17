using System.Collections.ObjectModel;
using System.Windows.Input;
using Sentinel.App.Mvvm;
using Sentinel.App.Services;
using Sentinel.Core.Ipc;
using Sentinel.Core.Protection;

namespace Sentinel.App.ViewModels;

/// <summary>Раздел «Поведенческий щит и USB»: переключатели защиты, статус приманок и сканирование съёмных носителей.</summary>
public sealed class BehavioralViewModel : SectionViewModel
{
    private bool _ransomware = true;
    private bool _canary = true;
    private bool _usb = true;
    private bool _shadow;
    private bool _evasion = true;
    private bool _applying;
    private string _usbPath = string.Empty;
    private string _statusLine = "Загрузка состояния…";
    private SettingsSnapshot _settings = new();

    public BehavioralViewModel(BackendHub hub, Action<string, bool> notify)
        : base(hub, notify)
    {
        ScanUsbCommand = Command(ScanUsbAsync, () => !IsBusy);
        ReloadCommand = Command(RefreshAsync, () => !IsBusy);
    }

    public ObservableCollection<UsbFinding> Findings { get; } = [];

    public ObservableCollection<string> RecentChains { get; } = [];

    public ICommand ScanUsbCommand { get; }

    public ICommand ReloadCommand { get; }

    public bool RansomwareShield { get => _ransomware; set => Toggle(ref _ransomware, value); }

    public bool CanaryFiles { get => _canary; set => Toggle(ref _canary, value); }

    public bool UsbShield { get => _usb; set => Toggle(ref _usb, value); }

    public bool ShadowMode { get => _shadow; set => Toggle(ref _shadow, value); }

    /// <summary>Детектор скрытых майнеров, прячущихся от Диспетчера задач.</summary>
    public bool EvasionWatch { get => _evasion; set => Toggle(ref _evasion, value); }

    private string _evasionLine = "Детектор скрытых майнеров: нет данных.";

    /// <summary>Состояние детектора: замеры, открытия мониторинга, находки.</summary>
    public string EvasionLine { get => _evasionLine; private set => Set(ref _evasionLine, value); }

    public string UsbPath { get => _usbPath; set => Set(ref _usbPath, value); }

    public string StatusLine { get => _statusLine; private set => Set(ref _statusLine, value); }

    public override async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            _settings = await Hub.GetSettingsAsync();
            _applying = true;
            RansomwareShield = _settings.EnableRansomwareShield;
            CanaryFiles = _settings.EnableCanaryFiles;
            UsbShield = _settings.EnableUsbShield;
            ShadowMode = _settings.BehavioralShadowMode;
            EvasionWatch = _settings.EnableMonitorEvasionWatch;
            _applying = false;

            var status = await Hub.GetBehavioralStatusAsync();
            RecentChains.Clear();
            foreach (var chain in status.RecentChains)
            {
                RecentChains.Add(chain);
            }

            StatusLine = $"Приманок: {status.CanaryCount}; вмешательств: {status.CanaryTampered}; теневой режим: {(status.ShadowMode ? "вкл" : "выкл")}.";
            EvasionLine = status.EvasionWatch is { } evasion ? evasion.Describe() : "Детектор скрытых майнеров недоступен в этом режиме.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ScanUsbAsync()
    {
        IsBusy = true;
        try
        {
            var path = string.IsNullOrWhiteSpace(UsbPath) ? null : UsbPath.Trim();
            var findings = await Hub.ScanRemovableAsync(path);
            Findings.Clear();
            foreach (var finding in findings)
            {
                Findings.Add(finding);
            }

            Notify(findings.Count == 0 ? "Угроз на съёмных носителях не найдено." : $"Найдено угроз: {findings.Count}.");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ApplyAsync()
    {
        if (_applying)
        {
            return;
        }

        var result = await Hub.SaveSettingsAsync(new SettingsUpdate
        {
            KasperskyOpenTipApiKey = null,
            VirusTotalApiKey = null,
            AbuseChAuthKey = null,
            AutoUpdateDatabases = _settings.AutoUpdateDatabases,
            EnableRansomwareShield = RansomwareShield,
            EnableCanaryFiles = CanaryFiles,
            EnableUsbShield = UsbShield,
            BehavioralShadowMode = ShadowMode,
            EnableMonitorEvasionWatch = EvasionWatch,
            EnableKnownGoodLookup = _settings.EnableKnownGoodLookup,
            PowerSaverOnBattery = _settings.PowerSaverOnBattery,
            AllowedPaths = _settings.AllowedPaths,
            AllowedProcesses = _settings.AllowedProcesses,
            AllowedHashes = _settings.AllowedHashes,
        });
        Notify(result);
    }

    private void Toggle(ref bool field, bool value)
    {
        if (Set(ref field, value) && !_applying)
        {
            _ = ApplyAsync();
        }
    }
}
