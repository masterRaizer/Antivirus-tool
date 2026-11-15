using System.ComponentModel;
using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

/// <summary>
/// Компактное всплывающее окно подтверждения в правом нижнем углу рабочей области.
/// Показывается, пока есть спорная находка, и не перехватывает фокус у пользователя.
/// </summary>
public partial class DecisionPopup : Window
{
    private readonly DecisionViewModel _model;

    public DecisionPopup(DecisionViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        InitializeComponent();
        _model = model;
        DataContext = model;
        model.PropertyChanged += OnModelChanged;
        SizeChanged += (_, _) => Place();
        Loaded += (_, _) => Place();
    }

    /// <summary>Показывает окно, если есть находка, ожидающая решения.</summary>
    public void Refresh()
    {
        if (_model.HasCurrent)
        {
            if (!IsVisible)
            {
                Show();
            }

            Place();
        }
        else if (IsVisible)
        {
            Hide();
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _model.PropertyChanged -= OnModelChanged;
        base.OnClosed(e);
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DecisionViewModel.HasCurrent))
        {
            Refresh();
        }
    }

    private void Place()
    {
        var area = SystemParameters.WorkArea;
        Left = area.Right - ActualWidth - 6;
        Top = area.Bottom - ActualHeight - 6;
    }
}
