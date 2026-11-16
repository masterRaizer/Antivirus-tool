using Sentinel.Core.Scanning;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Protection;

/// <summary>
/// Предохранитель деструктивных действий (завершение, приостановка, карантин): запрещает трогать критические процессы ОС,
/// подписанные Microsoft бинарники и сам Sentinel. С защитой от маскировки — системное имя даёт иммунитет только для файла
/// в системном каталоге, поэтому поддельный <c>C:\Temp\lsass.exe</c> иммунитета не получает. Применять действие можно
/// только к процессам, НЕ прошедшим этот фильтр.
/// </summary>
public static class CriticalProcessGuard
{
    private static readonly HashSet<string> CriticalImages = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "smss.exe", "lsass.exe", "wininit.exe", "services.exe", "svchost.exe",
        "explorer.exe", "winlogon.exe", "ntoskrnl.exe", "winload.efi", "system",
    };

    /// <summary>
    /// Имя образа совпадает с критическим системным процессом (без учёта каталога). Вместе с отрицательным
    /// <see cref="IsProtectedProcess"/> означает маскировку: системное имя вне системного каталога.
    /// </summary>
    public static bool IsCriticalImageName(string? processNameOrPath) =>
        FileNameOf(processNameOrPath) is { } name && CriticalImages.Contains(name);

    /// <summary>Нельзя ли применять деструктивное действие к процессу.</summary>
    public static bool IsProtectedProcess(int pid, string? processName, string? executablePath, ISignatureVerifier? verifier = null)
    {
        // Ядро системы и неизвестные низкие PID.
        if (pid is <= 4 and >= 0)
        {
            return true;
        }

        if (SelfProtection.IsOwnImageName(processName) || (executablePath is not null && SelfProtection.IsInOwnDirectory(executablePath)))
        {
            return true;
        }

        var name = FileNameOf(processName) ?? FileNameOf(executablePath);
        if (name is not null && CriticalImages.Contains(name))
        {
            // Критическое имя защищается, если файл в системном каталоге или путь недоступен (системные процессы часто без пути).
            if (string.IsNullOrEmpty(executablePath) || IsInSystemDirectory(executablePath))
            {
                return true;
            }
        }

        // Действительная подпись доверенного издателя (Microsoft и др.) — не трогаем.
        if (verifier is not null && !string.IsNullOrEmpty(executablePath))
        {
            try
            {
                if (TrustedPublishers.IsTrusted(verifier.Verify(executablePath)))
                {
                    return true;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // не удалось проверить подпись — решение принимается по имени/пути выше
            }
        }

        return false;
    }

    private static string? FileNameOf(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim().Replace('/', '\\');
        return normalized[(normalized.LastIndexOf('\\') + 1)..];
    }

    private static bool IsInSystemDirectory(string path)
    {
        var normalized = path.Replace('/', '\\').ToLowerInvariant();
        return normalized.Contains(@"\windows\system32\", StringComparison.Ordinal)
            || normalized.Contains(@"\windows\syswow64\", StringComparison.Ordinal)
            || normalized.Contains(@"\windows\winsxs\", StringComparison.Ordinal)
            || normalized.EndsWith(@"\windows\explorer.exe", StringComparison.Ordinal);
    }
}
