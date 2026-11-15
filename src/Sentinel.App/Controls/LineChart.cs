using System.Collections;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace Sentinel.App.Controls;

/// <summary>
/// Лёгкий живой график на Canvas: линия (Polyline), заливка под ней и горизонтальная сетка.
/// Значения — проценты 0..100; перерисовывается при изменении коллекции или размера.
/// </summary>
public sealed class LineChart : Canvas
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IEnumerable), typeof(LineChart), new PropertyMetadata(null, OnValuesChanged));

    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(LineChart), new PropertyMetadata(Brushes.DodgerBlue, (d, _) => ((LineChart)d).Redraw()));

    public static readonly DependencyProperty CapacityProperty = DependencyProperty.Register(
        nameof(Capacity), typeof(int), typeof(LineChart), new PropertyMetadata(60, (d, _) => ((LineChart)d).Redraw()));

    private readonly Polyline _line = new() { StrokeThickness = 1.8, StrokeLineJoin = PenLineJoin.Round };
    private readonly Polygon _area = new() { Opacity = 0.16 };
    private readonly Line[] _grid = new Line[3];

    public LineChart()
    {
        ClipToBounds = true;
        SnapsToDevicePixels = true;
        var gridBrush = new SolidColorBrush(Color.FromArgb(0x30, 0x8B, 0x94, 0x9E));
        gridBrush.Freeze();
        for (var i = 0; i < _grid.Length; i++)
        {
            _grid[i] = new Line { Stroke = gridBrush, StrokeThickness = 1, StrokeDashArray = [3, 4] };
            Children.Add(_grid[i]);
        }

        Children.Add(_area);
        Children.Add(_line);
        SizeChanged += (_, _) => Redraw();
    }

    /// <summary>Последовательность значений (double), новые — в конце.</summary>
    public IEnumerable? Values
    {
        get => (IEnumerable?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public Brush Stroke
    {
        get => (Brush)GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    /// <summary>Сколько точек помещается по ширине графика.</summary>
    public int Capacity
    {
        get => (int)GetValue(CapacityProperty);
        set => SetValue(CapacityProperty, value);
    }

    private static void OnValuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var chart = (LineChart)d;
        if (e.OldValue is INotifyCollectionChanged old)
        {
            old.CollectionChanged -= chart.OnCollectionChanged;
        }

        if (e.NewValue is INotifyCollectionChanged current)
        {
            current.CollectionChanged += chart.OnCollectionChanged;
        }

        chart.Redraw();
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => Redraw();

    private void Redraw()
    {
        var width = ActualWidth;
        var height = ActualHeight;
        if (width <= 0 || height <= 0)
        {
            return;
        }

        for (var i = 0; i < _grid.Length; i++)
        {
            var y = Math.Round(height * (i + 1) / (_grid.Length + 1)) + 0.5;
            _grid[i].X1 = 0;
            _grid[i].X2 = width;
            _grid[i].Y1 = y;
            _grid[i].Y2 = y;
        }

        var values = Values?.Cast<object>().Select(Convert.ToDouble).ToArray() ?? [];
        var capacity = Math.Max(2, Capacity);
        if (values.Length > capacity)
        {
            values = values[^capacity..];
        }

        var points = new PointCollection(values.Length);
        var step = width / (capacity - 1);
        var offset = capacity - values.Length; // график прижат к правому краю: свежие значения справа
        for (var i = 0; i < values.Length; i++)
        {
            var value = Math.Clamp(values[i], 0, 100);
            points.Add(new Point((offset + i) * step, 1 + (height - 2) * (1 - value / 100.0)));
        }

        _line.Stroke = Stroke;
        _line.Points = points;
        _area.Fill = Stroke;
        var area = new PointCollection(points.Count + 2);
        if (points.Count > 1)
        {
            foreach (var p in points)
            {
                area.Add(p);
            }

            area.Add(new Point(points[^1].X, height));
            area.Add(new Point(points[0].X, height));
        }

        _area.Points = area;
    }
}
