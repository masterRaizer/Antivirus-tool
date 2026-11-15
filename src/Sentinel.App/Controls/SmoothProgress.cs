using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace Sentinel.App.Controls;

/// <summary>
/// Плавный прогресс: присоединённое свойство, которое анимирует <see cref="ProgressBar.Value"/>
/// к новому значению вместо скачка.
/// </summary>
public static class SmoothProgress
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.RegisterAttached(
        "Value", typeof(double), typeof(SmoothProgress), new PropertyMetadata(0.0, OnValueChanged));

    public static double GetValue(DependencyObject element)
    {
        ArgumentNullException.ThrowIfNull(element);
        return (double)element.GetValue(ValueProperty);
    }

    public static void SetValue(DependencyObject element, double value)
    {
        ArgumentNullException.ThrowIfNull(element);
        element.SetValue(ValueProperty, value);
    }

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not ProgressBar bar)
        {
            return;
        }

        var target = (double)e.NewValue;
        if (target < bar.Value)
        {
            // Новая проверка: сброс без обратной анимации.
            bar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, null);
            bar.Value = target;
            return;
        }

        var animation = new DoubleAnimation(target, TimeSpan.FromMilliseconds(350))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut },
        };
        bar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, animation, HandoffBehavior.SnapshotAndReplace);
    }
}
