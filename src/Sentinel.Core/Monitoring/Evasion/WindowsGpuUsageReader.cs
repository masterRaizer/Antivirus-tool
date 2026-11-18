using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Monitoring.Evasion;

/// <summary>
/// Нагрузка на видеокарту по процессам — счётчики производительности «GPU Engine» (те же, что рисует Диспетчер задач):
/// экземпляры вида <c>pid_1234_luid_…_phys_0_eng_3_engtype_3D</c>. Для процесса берётся максимум по типам движков
/// (3D, Compute, Copy, VideoDecode…) суммы движков одного типа — так считает и Диспетчер задач. Английские имена счётчиков
/// (<c>PdhAddEnglishCounterW</c>) работают на любой локализации Windows. Если счётчиков нет (нет WDDM 2.x, служба
/// счётчиков отключена) — <see cref="Read"/> возвращает пустой словарь, детектор работает только по процессору.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsGpuUsageReader : IDisposable
{
    private const string CounterPath = @"\GPU Engine(*)\Utilization Percentage";
    private const uint PdhFmtDouble = 0x00000200;
    private const uint PdhFmtNoCap100 = 0x00008000;
    private const uint PdhMoreData = 0x800007D2;
    private const int ItemSize = 24; // PDH_FMT_COUNTERVALUE_ITEM_W: указатель на имя + {CStatus, double} с выравниванием 8
    private const int StatusOffset = 8;
    private const int ValueOffset = 16;

    private IntPtr _query;
    private IntPtr _counter;
    private bool _primed;
    private bool _disposed;

    /// <summary>Причина, по которой нагрузка видеокарты недоступна (<c>null</c> — доступна).</summary>
    public string? Unavailable { get; private set; }

    /// <summary>
    /// Нагрузка видеокарты по PID, 0–100 %; процессов без нагрузки в словаре нет. <c>null</c> — замер недоступен
    /// (счётчиков нет или это первый вызов: счётчик — скорость, ему нужны два замера).
    /// </summary>
    public IReadOnlyDictionary<int, double>? Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Unavailable is not null || !EnsureQuery() || NativeMethods.PdhCollectQueryData(_query) != 0)
        {
            return null;
        }

        if (!_primed)
        {
            _primed = true;
            return null;
        }

        var result = new Dictionary<int, double>();
        uint size = 0;
        var status = NativeMethods.PdhGetFormattedCounterArrayW(_counter, PdhFmtDouble | PdhFmtNoCap100, ref size, out _, IntPtr.Zero);
        if (status == 0)
        {
            return result; // экземпляров нет — никто не нагружает видеокарту
        }

        if (status != PdhMoreData || size == 0)
        {
            return null;
        }

        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            status = NativeMethods.PdhGetFormattedCounterArrayW(_counter, PdhFmtDouble | PdhFmtNoCap100, ref size, out var count, buffer);
            if (status != 0)
            {
                return null;
            }

            // pid → (тип движка → сумма загрузки движков этого типа)
            var byType = new Dictionary<int, Dictionary<string, double>>();
            for (var i = 0; i < count; i++)
            {
                var item = buffer + (i * ItemSize);
                var cstatus = Marshal.ReadInt32(item, StatusOffset);
                if (cstatus is not 0 and not 1)
                {
                    continue; // PDH_CSTATUS_VALID_DATA / NEW_DATA
                }

                var value = BitConverter.Int64BitsToDouble(Marshal.ReadInt64(item, ValueOffset));
                var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(item, 0));
                if (value <= 0 || !GpuEngineInstance.TryParse(name, out var pid, out var engine))
                {
                    continue;
                }

                if (!byType.TryGetValue(pid, out var engines))
                {
                    byType[pid] = engines = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
                }

                engines[engine] = engines.GetValueOrDefault(engine) + value;
            }

            foreach (var (pid, engines) in byType)
            {
                result[pid] = Math.Clamp(engines.Values.Max(), 0, 100);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private bool EnsureQuery()
    {
        if (_query != IntPtr.Zero)
        {
            return true;
        }

        var status = NativeMethods.PdhOpenQueryW(null, IntPtr.Zero, out _query);
        if (status != 0)
        {
            Unavailable = $"PdhOpenQuery: 0x{status:X8}";
            return false;
        }

        status = NativeMethods.PdhAddEnglishCounterW(_query, CounterPath, IntPtr.Zero, out _counter);
        if (status != 0)
        {
            Unavailable = $"счётчики GPU Engine недоступны (0x{status:X8})";
            _ = NativeMethods.PdhCloseQuery(_query); // закрытие запроса: ошибка не влияет на дальнейшую работу
            _query = IntPtr.Zero;
            return false;
        }

        return true;
    }

    public void Dispose()
    {
        if (_query != IntPtr.Zero)
        {
            _ = NativeMethods.PdhCloseQuery(_query); // закрытие запроса: ошибка не влияет на дальнейшую работу
            _query = IntPtr.Zero;
        }

        _disposed = true;
    }

    private static class NativeMethods
    {
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        public static extern uint PdhOpenQueryW(string? dataSource, IntPtr userData, out IntPtr query);

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        public static extern uint PdhAddEnglishCounterW(IntPtr query, string fullCounterPath, IntPtr userData, out IntPtr counter);

        [DllImport("pdh.dll")]
        public static extern uint PdhCollectQueryData(IntPtr query);

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        public static extern uint PdhGetFormattedCounterArrayW(IntPtr counter, uint format, ref uint bufferSize, out uint itemCount, IntPtr itemBuffer);

        [DllImport("pdh.dll")]
        public static extern uint PdhCloseQuery(IntPtr query);
    }
}

/// <summary>Имена экземпляров счётчиков «GPU Engine» (разбор не зависит от платформы и проверяется тестами на Linux).</summary>
public static class GpuEngineInstance
{
    /// <summary>Разбор имени экземпляра «pid_1234_luid_0x0_0xD1A4_phys_0_eng_0_engtype_3D».</summary>
    public static bool TryParse(string? instance, out int pid, out string engineType)
    {
        pid = 0;
        engineType = string.Empty;
        if (string.IsNullOrEmpty(instance) || !instance.StartsWith("pid_", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var end = instance.IndexOf('_', 4);
        if (end < 0 || !int.TryParse(instance.AsSpan(4, end - 4), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out pid) || pid <= 0)
        {
            return false;
        }

        var type = instance.IndexOf("engtype_", StringComparison.OrdinalIgnoreCase);
        engineType = type < 0 ? "?" : instance[(type + "engtype_".Length)..];
        return true;
    }
}
