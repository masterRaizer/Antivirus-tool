using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Sentinel.Core.Ipc;
using Sentinel.Core.Realtime;
using Sentinel.Core.Reporting;
using Sentinel.Core.Signatures;

namespace Sentinel.App;

/// <summary>bool → Visibility; параметр <c>invert</c> меняет смысл на обратный.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value switch
        {
            bool b => b,
            string s => !string.IsNullOrWhiteSpace(s),
            int i => i > 0,
            null => false,
            _ => true,
        };
        if (parameter is "invert")
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Значение перечисления ↔ флажок переключателя (параметр — имя значения).</summary>
public sealed class EnumMatchConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        string.Equals(value?.ToString(), parameter as string, StringComparison.Ordinal);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true && parameter is string name ? Enum.Parse(targetType, name) : Binding.DoNothing;
}

public sealed class LocalTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        DateTime { Year: > 1 } utc => DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture),
        _ => "—",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class BytesConverter : IValueConverter
{
    public static string Format(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} ГБ",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} МБ",
        >= 1L << 10 => $"{bytes / (double)(1L << 10):0.0} КБ",
        _ => $"{bytes} Б",
    };

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is long bytes ? Format(bytes) : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class DurationConverter : IValueConverter
{
    public static string Format(double seconds)
    {
        var t = TimeSpan.FromSeconds(Math.Max(0, seconds));
        return t.TotalHours >= 1 ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}" : $"{t.Minutes:00}:{t.Seconds:00}";
    }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is double seconds ? Format(seconds) : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class EntropyConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        double h when h >= 7.2 => $"{h:0.000} бит/байт — высокая (упаковка или шифрование)",
        double h => $"{h:0.000} бит/байт",
        _ => "—",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Пустое значение → прочерк (для необязательных полей карточек).</summary>
public sealed class DashIfEmptyConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        string.IsNullOrWhiteSpace(value?.ToString()) ? "—" : value!;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class SeverityTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Severity severity ? ReportGenerator.SeverityLabel(severity) : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Критичность → кисть; параметр <c>soft</c> — полупрозрачный фон для плашки.</summary>
public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value switch
        {
            Severity.Critical or Severity.High => "Danger",
            Severity.Medium => "Warn",
            Severity.Low => "Accent",
            _ => "Muted",
        };
        return Palette.Brush(key, parameter is "soft");
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ThreatStatusTextConverter : IValueConverter
{
    public static string Text(ThreatStatus status) => status switch
    {
        ThreatStatus.PendingDecision => "Ждёт решения",
        ThreatStatus.Quarantined => "В карантине",
        ThreatStatus.Terminated => "Процесс завершён",
        ThreatStatus.Cleaned => "Параметр очищен",
        ThreatStatus.Allowed => "В исключениях",
        ThreatStatus.Blocked => "Защищено белым списком",
        ThreatStatus.Skipped => "Пропущено",
        ThreatStatus.Failed => "Ошибка действия",
        _ => "Обнаружено",
    };

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is ThreatStatus status ? Text(status) : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ThreatStatusBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value switch
        {
            ThreatStatus.Quarantined or ThreatStatus.Terminated or ThreatStatus.Cleaned => "Ok",
            ThreatStatus.PendingDecision => "Warn",
            ThreatStatus.Failed => "Danger",
            ThreatStatus.Allowed => "Accent",
            _ => "Muted",
        };
        return Palette.Brush(key, parameter is "soft");
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ThreatKindTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ThreatKind.File => "Файл",
        ThreatKind.Process => "Процесс",
        ThreatKind.Persistence => "Автозагрузка",
        ThreatKind.DefenderExclusion => "Исключение Defender",
        _ => "—",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ThreatSourceTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        "realtime" => "защита в реальном времени",
        "scan" => "проверка по требованию",
        _ => value?.ToString() ?? "—",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ActionStatusTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is FindingActionStatus status ? ReportGenerator.StatusLabel(status) : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ReportModeTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        "remediate" => "с нейтрализацией",
        "dry-run" => "предпросмотр",
        "audit" => "только аудит",
        _ => value?.ToString() ?? "—",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Подсветка строки автозагрузки: нестандартная запись — красным, неподписанная — жёлтым.</summary>
public sealed class StartupRowBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        StartupItem { Flagged: true, Severity: >= Severity.High } => Palette.Brush("Danger", soft: true),
        StartupItem { Flagged: true } => Palette.Brush("Warn", soft: true),
        StartupItem { NotSigned: true } => Palette.Brush("Muted", soft: true),
        _ => Brushes.Transparent,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Доступ к кистям темы из кода (конвертеры не могут использовать StaticResource).</summary>
public static class Palette
{
    public static Brush Brush(string key, bool soft = false) =>
        Application.Current?.TryFindResource(key + (soft ? "SoftBrush" : "Brush")) as Brush ?? Brushes.Gray;
}

/// <summary>Значение перечисления → видимость (параметр — имя значения, при котором элемент показан).</summary>
public sealed class EnumVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        string.Equals(value?.ToString(), parameter as string, StringComparison.Ordinal) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Имя группы «N. Заголовок» → «Заголовок» (номер задаёт только порядок групп).</summary>
public sealed class GroupTitleConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var text = value?.ToString() ?? string.Empty;
        var dot = text.IndexOf(". ", StringComparison.Ordinal);
        return dot is > 0 and < 3 ? text[(dot + 2)..] : text;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Развёрнута по умолчанию только группа «Требуют внимания»; информационные и штатные записи свёрнуты.</summary>
public sealed class GroupExpandedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value?.ToString()?.StartsWith("1.", StringComparison.Ordinal) == true;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}
