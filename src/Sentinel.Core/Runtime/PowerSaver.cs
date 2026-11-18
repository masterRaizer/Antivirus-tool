using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Runtime;

/// <summary>Источник питания: работает ли компьютер от батареи.</summary>
public interface IPowerSource
{
    bool OnBattery { get; }
}

/// <summary>
/// Питание по <c>GetSystemPowerStatus</c>: <c>ACLineStatus == 0</c> — от батареи. Вне Windows и при ошибке вызова считается,
/// что компьютер подключён к сети (режим экономии не включается).
/// </summary>
public sealed class SystemPowerSource : IPowerSource
{
    public static SystemPowerSource Instance { get; } = new();

    public bool OnBattery => OperatingSystem.IsWindows() && WindowsOnBattery();

    [SupportedOSPlatform("windows")]
    private static bool WindowsOnBattery() => GetSystemPowerStatus(out var status) && status.ACLineStatus == 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SystemPowerStatus status);

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemPowerStatus
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }
}

/// <summary>
/// Режим ноутбука (как отложенные задачи Касперского при работе от батареи): от батареи реже идёт только плановый аудит
/// автозагрузки и конфигурации. Проверка файлов и процессов всегда работает в полную ширину пула (до 8 потоков); защита
/// в реальном времени, аудит новых процессов и внеочередной аудит после изменения hosts/задач не откладываются.
/// </summary>
public static class PowerSaverPolicy
{
    /// <summary>Интервал планового аудита конфигурации от батареи.</summary>
    public static readonly TimeSpan BatteryConfigAuditInterval = TimeSpan.FromMinutes(30);

    public static TimeSpan ConfigAuditInterval(TimeSpan normal, bool saving) =>
        saving && normal < BatteryConfigAuditInterval ? BatteryConfigAuditInterval : normal;
}
