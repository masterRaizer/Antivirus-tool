using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Runtime;

/// <summary>Режим, в котором запущена Windows.</summary>
public enum BootEnvironment
{
    Normal,

    /// <summary>Безопасный режим (<c>SM_CLEANBOOT</c> = 1, «Минимальный»).</summary>
    SafeMode,

    /// <summary>Безопасный режим с загрузкой сетевых драйверов (<c>SM_CLEANBOOT</c> = 2).</summary>
    SafeModeWithNetworking,

    /// <summary>Среда восстановления Windows (WinRE/WinPE).</summary>
    RecoveryEnvironment,
}

/// <summary>Источники сведений о режиме загрузки; подменяются в тестах.</summary>
public sealed record BootProbes(
    Func<int> CleanBootMetric,
    Func<string, string?> Environment,
    Func<string, bool> FileExists,
    Func<string, bool> RegistryKeyExists);

/// <summary>
/// Определение Безопасного режима и WinRE. Безопасный режим — <c>GetSystemMetrics(SM_CLEANBOOT = 67) &gt; 0</c>
/// или непустая переменная <c>SAFEBOOT_OPTION</c>; WinRE/WinPE — файл <c>X:\Windows\System32\winpeshl.ini</c>
/// или ветка <c>HKLM\SYSTEM\CurrentControlSet\Control\MiniNT</c>.
/// </summary>
public static class RecoveryEnvironment
{
    public const int SmCleanBoot = 67;
    public const string WinPeShellIni = @"X:\Windows\System32\winpeshl.ini";
    public const string MiniNtKey = @"SYSTEM\CurrentControlSet\Control\MiniNT";

    public static BootEnvironment Detect(BootProbes probes)
    {
        ArgumentNullException.ThrowIfNull(probes);
        if (Safe(() => probes.FileExists(WinPeShellIni)) || Safe(() => probes.RegistryKeyExists(MiniNtKey)))
        {
            return BootEnvironment.RecoveryEnvironment;
        }

        var metric = 0;
        try
        {
            metric = probes.CleanBootMetric();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or PlatformNotSupportedException)
        {
            metric = 0;
        }

        if (metric == 2)
        {
            return BootEnvironment.SafeModeWithNetworking;
        }

        if (metric > 0)
        {
            return BootEnvironment.SafeMode;
        }

        var option = probes.Environment("SAFEBOOT_OPTION");
        if (!string.IsNullOrWhiteSpace(option))
        {
            return option.Trim().Equals("NETWORK", StringComparison.OrdinalIgnoreCase)
                ? BootEnvironment.SafeModeWithNetworking
                : BootEnvironment.SafeMode;
        }

        return BootEnvironment.Normal;
    }

    /// <summary>Режим текущей системы (вне Windows — всегда <see cref="BootEnvironment.Normal"/>).</summary>
    public static BootEnvironment DetectCurrent() =>
        OperatingSystem.IsWindows() ? Detect(WindowsProbes()) : BootEnvironment.Normal;

    public static bool IsRecoveryMode(this BootEnvironment environment) => environment != BootEnvironment.Normal;

    public static string Describe(this BootEnvironment environment) => environment switch
    {
        BootEnvironment.SafeMode => "Безопасный режим Windows",
        BootEnvironment.SafeModeWithNetworking => "Безопасный режим Windows с загрузкой сетевых драйверов",
        BootEnvironment.RecoveryEnvironment => "Среда восстановления Windows (WinRE)",
        _ => "Обычный режим Windows",
    };

    [SupportedOSPlatform("windows")]
    private static BootProbes WindowsProbes() => new(
        () => GetSystemMetrics(SmCleanBoot),
        System.Environment.GetEnvironmentVariable,
        File.Exists,
        key =>
        {
            using var opened = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(key);
            return opened is not null;
        });

    private static bool Safe(Func<bool> probe)
    {
        try
        {
            return probe();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    [DllImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GetSystemMetrics(int index);
}

/// <summary>
/// Выбор рабочего каталога (карантин, кэш, отчёты, настройки): первый каталог, в который удаётся записать.
/// Порядок: <c>%ProgramData%\Sentinel</c> → <c>SentinelData</c> рядом с исполняемым файлом (портативный запуск с флешки, WinRE)
/// → <c>%LocalAppData%\Sentinel</c> → <c>%TEMP%\SentinelData</c>.
/// </summary>
public static class DataDirectoryResolver
{
    public const string PortableFolderName = "SentinelData";

    public static IReadOnlyList<string> DefaultCandidates()
    {
        var list = new List<string> { SentinelRuntimeOptions.DefaultDataDirectory() };
        list.Add(Path.Combine(AppContext.BaseDirectory, PortableFolderName));
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(local))
        {
            list.Add(Path.Combine(local, "Sentinel"));
        }

        list.Add(Path.Combine(Path.GetTempPath(), PortableFolderName));
        return list;
    }

    /// <summary>Первый доступный для записи каталог; <paramref name="isWritable"/> по умолчанию создаёт и удаляет пробный файл.</summary>
    public static string Choose(IEnumerable<string> candidates, Func<string, bool>? isWritable = null)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        isWritable ??= IsWritable;
        string? last = null;
        foreach (var candidate in candidates.Where(c => !string.IsNullOrWhiteSpace(c)))
        {
            last = candidate;
            if (isWritable(candidate))
            {
                return candidate;
            }
        }

        return last ?? throw new InvalidOperationException("Не задан ни один каталог данных.");
    }

    public static string ChooseDefault() => Choose(DefaultCandidates());

    public static bool IsWritable(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var probe = Path.Combine(directory, $".write-probe-{Environment.ProcessId}-{Guid.NewGuid():N}");
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException)
        {
            return false;
        }
    }
}
