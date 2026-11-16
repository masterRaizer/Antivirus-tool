using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Remediation;

/// <summary>
/// Приостановка потоков процесса средствами Win32. Первым шагом — <see cref="ContainmentBarrier"/> (PID ≤ 4, собственный
/// процесс, <c>CriticalProcessGuard</c>): при отказе дескрипторы не открываются. Затем снимок
/// <c>CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)</c> → потоки процесса → <c>OpenThread(THREAD_SUSPEND_RESUME)</c> →
/// <c>SuspendThread</c>, дескриптор закрывается в <c>finally</c>. Проходы повторяются (до 5), пока очередной не найдёт
/// новых потоков: так закрывается гонка с потоками, созданными во время заморозки. Приостановленные ID запоминаются —
/// повторный проход не увеличивает счётчик приостановки, а <see cref="ResumeProcess"/> возобновляет только их.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessContainment : IProcessContainment
{
    public const int MaxPasses = 5;

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint TH32CS_SNAPTHREAD = 0x00000004;
    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint SuspendFailed = 0xFFFFFFFF;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_INVALID_PARAMETER = 87;
    private static readonly IntPtr InvalidHandle = new(-1);

    private readonly ConcurrentDictionary<int, HashSet<uint>> _suspended = new();

    public ContainmentResult SuspendProcess(int processId, string? processName = null, string? executablePath = null)
    {
        if (ContainmentBarrier.Check(processId, processName, executablePath) is { } denied)
        {
            return ContainmentResult.SelfDefense(processId, denied);
        }

        var suspended = _suspended.GetOrAdd(processId, _ => []);
        var attempted = new HashSet<uint>();
        var newlySuspended = 0;
        var failed = 0;
        string? lastError = null;

        lock (suspended)
        {
            for (var pass = 0; pass < MaxPasses; pass++)
            {
                var found = 0;
                foreach (var threadId in ThreadsOf(processId))
                {
                    if (suspended.Contains(threadId) || !attempted.Add(threadId))
                    {
                        continue;
                    }

                    found++;
                    switch (SuspendOne(threadId, out var error))
                    {
                        case true:
                            suspended.Add(threadId);
                            newlySuspended++;
                            break;
                        case false when error == ERROR_INVALID_PARAMETER:
                            break; // поток завершился сам до OpenThread — не ошибка
                        default:
                            failed++;
                            lastError = error == ERROR_ACCESS_DENIED ? "ERROR_ACCESS_DENIED" : $"Win32 {error}";
                            break;
                    }
                }

                if (found == 0)
                {
                    break; // за проход не появилось новых потоков
                }
            }
        }

        // Повторный вызов для уже замороженного процесса — успех без повторного SuspendThread (счётчик не накручивается).
        return newlySuspended > 0 || suspended.Count > 0
            ? new ContainmentResult(true, processId, newlySuspended, failed, [processId], false, failed > 0 ? $"Часть потоков не приостановлена: {lastError}." : null)
            : ContainmentResult.Failed(processId, failed > 0 ? $"Потоки не приостановлены: {lastError}." : "У процесса нет потоков (завершён).", failed);
    }

    public ContainmentResult ResumeProcess(int processId)
    {
        if (!_suspended.TryRemove(processId, out var threads))
        {
            return new ContainmentResult(true, processId, 0, 0, [], false, null);
        }

        var resumed = 0;
        var failed = 0;
        lock (threads)
        {
            foreach (var threadId in threads)
            {
                var handle = OpenThread(THREAD_SUSPEND_RESUME, false, threadId);
                if (handle == IntPtr.Zero)
                {
                    if (Marshal.GetLastPInvokeError() != ERROR_INVALID_PARAMETER)
                    {
                        failed++;
                    }

                    continue;
                }

                try
                {
                    if (ResumeThread(handle) == SuspendFailed)
                    {
                        failed++;
                    }
                    else
                    {
                        resumed++;
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
        }

        return new ContainmentResult(failed == 0, processId, resumed, failed, resumed > 0 ? [processId] : [], false,
            failed > 0 ? "Часть потоков не возобновлена." : null);
    }

    public ContainmentResult SuspendProcessTree(int rootProcessId, string? rootProcessName = null, string? rootExecutablePath = null)
    {
        if (ContainmentBarrier.Check(rootProcessId, rootProcessName, rootExecutablePath) is { } denied)
        {
            return ContainmentResult.SelfDefense(rootProcessId, denied);
        }

        // Дерево собирается по снимку процессов до начала заморозки; каждый потомок проходит барьер отдельно.
        var processes = SnapshotProcesses();
        var tree = new List<(int Pid, string Name)> { (rootProcessId, rootProcessName ?? processes.GetValueOrDefault(rootProcessId).Name ?? string.Empty) };
        var visited = new HashSet<int> { rootProcessId };
        for (var i = 0; i < tree.Count; i++)
        {
            var parent = tree[i].Pid;
            foreach (var (pid, info) in processes)
            {
                if (info.ParentPid == parent && pid != parent && visited.Add(pid))
                {
                    tree.Add((pid, info.Name ?? string.Empty));
                }
            }
        }

        var affected = new List<int>();
        var suspendedThreads = 0;
        var failedThreads = 0;
        var skipped = 0;
        foreach (var (pid, name) in tree)
        {
            var result = pid == rootProcessId
                ? SuspendProcess(pid, name, rootExecutablePath)
                : SuspendProcess(pid, name);
            if (result.SkippedBySelfDefense)
            {
                skipped++;
                continue;
            }

            suspendedThreads += result.SuspendedThreadCount;
            failedThreads += result.FailedThreadCount;
            affected.AddRange(result.AffectedProcessIds);
        }

        return new ContainmentResult(suspendedThreads > 0, rootProcessId, suspendedThreads, failedThreads, affected, false,
            skipped > 0 ? $"Защищённых потомков пропущено: {skipped}." : null);
    }

    private static bool SuspendOne(uint threadId, out int error)
    {
        error = 0;
        var handle = OpenThread(THREAD_SUSPEND_RESUME, false, threadId);
        if (handle == IntPtr.Zero)
        {
            error = Marshal.GetLastPInvokeError();
            return false;
        }

        try
        {
            if (SuspendThread(handle) == SuspendFailed)
            {
                error = Marshal.GetLastPInvokeError();
                return false;
            }

            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static List<uint> ThreadsOf(int processId)
    {
        var result = new List<uint>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == InvalidHandle)
        {
            return result;
        }

        try
        {
            var entry = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            if (!Thread32First(snapshot, ref entry))
            {
                return result;
            }

            do
            {
                if (entry.th32OwnerProcessID == (uint)processId)
                {
                    result.Add(entry.th32ThreadID);
                }
            }
            while (Thread32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return result;
    }

    private static Dictionary<int, (int ParentPid, string? Name)> SnapshotProcesses()
    {
        var map = new Dictionary<int, (int, string?)>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == InvalidHandle)
        {
            return map;
        }

        try
        {
            var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32First(snapshot, ref entry))
            {
                return map;
            }

            do
            {
                map[(int)entry.th32ProcessID] = ((int)entry.th32ParentProcessID, entry.szExeFile);
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return map;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
