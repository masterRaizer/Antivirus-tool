using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Sentinel.Core.Audit;

/// <summary>Шаг аудита, пропущенный из-за недоступности системной службы или источника данных.</summary>
public sealed record SkippedAuditStep(string Step, string Reason);

/// <summary>
/// Изоляция шагов аудита. В Безопасном режиме и WinRE обычно остановлены WMI (<c>winmgmt</c>), брандмауэр (<c>mpssvc</c>),
/// планировщик и Defender, а части реестра или файловой системы недоступны: такой шаг пропускается с записью причины,
/// остальные шаги и проверка в целом продолжаются.
/// </summary>
public static class AuditStepGuard
{
    public static void Run(string step, Action action, List<SkippedAuditStep> skipped)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(skipped);
        try
        {
            action();
        }
        catch (Exception ex) when (IsUnavailable(ex))
        {
            skipped.Add(new SkippedAuditStep(step, $"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    /// <summary>Сбои недоступной службы или источника (а не ошибки программы, которые нужно видеть).</summary>
    public static bool IsUnavailable(Exception ex) => ex is COMException or Win32Exception or InvalidOperationException or IOException
        or UnauthorizedAccessException or TimeoutException or System.Security.SecurityException or System.Text.Json.JsonException
        or PlatformNotSupportedException or ExternalException or System.Security.Cryptography.CryptographicException;
}
