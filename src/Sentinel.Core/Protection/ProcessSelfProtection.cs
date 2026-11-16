namespace Sentinel.Core.Protection;

/// <summary>Категория владельца ACE в DACL процесса (для расчёта, какие права урезать).</summary>
public enum ProcessSidCategory
{
    LocalSystem,
    SentinelSelf,
    Administrators,
    AuthenticatedUsers,
    Other,
}

/// <summary>Один элемент DACL процесса: кому, разрешение или запрет, маска доступа.</summary>
public sealed record ProcessDaclAce(ProcessSidCategory Sid, bool Allow, int Mask);

/// <summary>
/// Расчёт «усиленного» DACL собственного процесса службы. Из разрешающих ACE всех учётных записей, кроме LocalSystem и
/// самого Sentinel, удаляются опасные права (<c>PROCESS_TERMINATE</c>, <c>PROCESS_VM_WRITE</c>, <c>PROCESS_VM_OPERATION</c>,
/// <c>PROCESS_SUSPEND_RESUME</c>); запрещающие ACE и права LocalSystem сохраняются. Эта чистая логика тестируется на Linux,
/// а применение к живому процессу (<c>GetKernelObjectSecurity</c>/<c>SetKernelObjectSecurity</c>) выполняется в службе на Windows.
/// </summary>
public static class ProcessSelfProtection
{
    public const int ProcessTerminate = 0x0001;
    public const int ProcessVmOperation = 0x0008;
    public const int ProcessVmRead = 0x0010;
    public const int ProcessVmWrite = 0x0020;
    public const int ProcessSuspendResume = 0x0800;
    public const int ProcessQueryLimitedInformation = 0x1000;
    public const int Synchronize = 0x0010_0000;

    /// <summary>Права, которые урезаются у посторонних учётных записей.</summary>
    public const int DangerousRights = ProcessTerminate | ProcessVmOperation | ProcessVmWrite | ProcessSuspendResume;

    /// <summary>Минимально необходимые права, которые остаются доступны всем (чтение состояния и ожидание).</summary>
    public const int SafeRights = Synchronize | ProcessQueryLimitedInformation;

    /// <summary>Снимает опасные биты из маски.</summary>
    public static int ReduceMask(int mask) => mask & ~DangerousRights;

    /// <summary>
    /// Пересчитывает DACL: у разрешающих ACE посторонних учётных записей снимаются опасные права; LocalSystem, Sentinel
    /// и запрещающие ACE не меняются. Возвращает новый список той же длины и порядка.
    /// </summary>
    public static IReadOnlyList<ProcessDaclAce> Harden(IReadOnlyList<ProcessDaclAce> aces)
    {
        ArgumentNullException.ThrowIfNull(aces);
        var result = new List<ProcessDaclAce>(aces.Count);
        foreach (var ace in aces)
        {
            var preserve = !ace.Allow || ace.Sid is ProcessSidCategory.LocalSystem or ProcessSidCategory.SentinelSelf;
            result.Add(preserve ? ace : ace with { Mask = ReduceMask(ace.Mask) });
        }

        return result;
    }
}
