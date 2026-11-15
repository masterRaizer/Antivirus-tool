using System.Windows;
using System.Windows.Controls;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

/// <summary>PasswordBox не поддерживает привязку: значения ключей передаются в модель из обработчиков.</summary>
public partial class SettingsView : UserControl
{
    public SettingsView() => InitializeComponent();

    private SettingsViewModel? Model => DataContext as SettingsViewModel;

    private void OnKasperskyChanged(object sender, RoutedEventArgs e)
    {
        if (Model is { } m)
        {
            m.KasperskyKey = KasperskyBox.Password;
        }
    }

    private void OnVirusTotalChanged(object sender, RoutedEventArgs e)
    {
        if (Model is { } m)
        {
            m.VirusTotalKey = VirusTotalBox.Password;
        }
    }

    private void OnAbuseChChanged(object sender, RoutedEventArgs e)
    {
        if (Model is { } m)
        {
            m.AbuseChKey = AbuseChBox.Password;
        }
    }

    /// <summary>После отправки ключи стираются из полей: в окне они не хранятся.</summary>
    private void OnSaved(object sender, RoutedEventArgs e) => Dispatcher.BeginInvoke(() =>
    {
        KasperskyBox.Clear();
        VirusTotalBox.Clear();
        AbuseChBox.Clear();
    }, System.Windows.Threading.DispatcherPriority.Background);
}
