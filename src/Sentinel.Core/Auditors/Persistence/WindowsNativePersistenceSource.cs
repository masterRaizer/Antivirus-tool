using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Sentinel.Core.Audit.Persistence.Registry;

namespace Sentinel.Core.Auditors.Persistence;

/// <summary>
/// Нативный сбор служб и реестровой персистентности на Windows без PowerShell и WMI: конфигурация из реестра
/// (<see cref="IRegistryProvider"/>), живое состояние служб — из SCM (<c>advapi32.dll</c>). Поддерживает переопределение
/// корня Windows для работы по примонтированному разделу в WinRE. Никогда не падает при остановленном SCM — состояние
/// тогда остаётся <see cref="ServiceRunState.Unknown"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsNativePersistenceSource : IServiceRegistrySource
{
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
    private readonly IRegistryProvider _registry;
    private readonly string _windowsRoot;
    private readonly bool _queryScm;

    public WindowsNativePersistenceSource(IRegistryProvider registry, string? windowsRoot = null, bool queryScm = true)
    {
        ArgumentNullException.ThrowIfNull(registry);
        _registry = registry;
        var win = windowsRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _windowsRoot = string.IsNullOrEmpty(win) ? @"C:\Windows" : win;
        _queryScm = queryScm;
    }

    public IReadOnlyList<RawServiceRecord> GetServices()
    {
        var live = _queryScm ? QueryScmStates() : new Dictionary<string, (ServiceRunState, int?)>(StringComparer.OrdinalIgnoreCase);
        var records = new List<RawServiceRecord>();
        foreach (var name in _registry.GetSubKeyNames(new RegistryKeyPath(RegistryHive.LocalMachine, ServicesKey)))
        {
            var key = new RegistryKeyPath(RegistryHive.LocalMachine, $"{ServicesKey}\\{name}");
            var imagePath = _registry.GetValue(key, "ImagePath")?.Value;
            var serviceDll = _registry.GetValue(new RegistryKeyPath(RegistryHive.LocalMachine, $"{ServicesKey}\\{name}\\Parameters"), "ServiceDll")?.Value;
            var failure = _registry.GetValue(new RegistryKeyPath(RegistryHive.LocalMachine, $"{ServicesKey}\\{name}\\FailureCommand"), string.Empty)?.Value
                ?? _registry.GetValue(key, "FailureCommand")?.Value;
            if (imagePath is null && serviceDll is null)
            {
                continue;
            }

            var (state, pid) = live.TryGetValue(name, out var s) ? s : (ServiceRunState.Unknown, (int?)null);
            records.Add(new RawServiceRecord(
                name,
                imagePath,
                ParseInt(_registry.GetValue(key, "Start")?.Value),
                ParseInt(_registry.GetValue(key, "Type")?.Value),
                _registry.GetValue(key, "ObjectName")?.Value)
            {
                ServiceDll = serviceDll,
                FailureCommand = failure,
                State = state,
                ProcessId = pid,
            });
        }

        return records;
    }

    public string WindowsRoot => _windowsRoot;

    private static int ParseInt(string? value) =>
        value is not null && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : -1;

    private static Dictionary<string, (ServiceRunState State, int? Pid)> QueryScmStates()
    {
        var result = new Dictionary<string, (ServiceRunState, int?)>(StringComparer.OrdinalIgnoreCase);
        var scm = IntPtr.Zero;
        try
        {
            scm = OpenSCManager(null, null, ScManagerEnumerateService);
            if (scm == IntPtr.Zero)
            {
                return result; // SCM недоступен (Безопасный режим/WinRE) — состояние останется Unknown
            }

            const int ServiceWin32 = 0x30;
            const int ServiceDriver = 0x0B;
            const int ServiceStateAll = 0x3;
            uint bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
            EnumServicesStatusEx(scm, 0, ServiceWin32 | ServiceDriver, ServiceStateAll, IntPtr.Zero, 0,
                ref bytesNeeded, ref servicesReturned, ref resumeHandle, null);
            if (bytesNeeded == 0)
            {
                return result;
            }

            var buffer = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                if (!EnumServicesStatusEx(scm, 0, ServiceWin32 | ServiceDriver, ServiceStateAll, buffer, bytesNeeded,
                        ref bytesNeeded, ref servicesReturned, ref resumeHandle, null))
                {
                    return result;
                }

                var size = Marshal.SizeOf<EnumServiceStatusProcess>();
                for (var i = 0; i < servicesReturned; i++)
                {
                    var entry = Marshal.PtrToStructure<EnumServiceStatusProcess>(buffer + (i * size));
                    var name = entry.ServiceName ?? string.Empty;
                    if (name.Length == 0)
                    {
                        continue;
                    }

                    var state = (ServiceRunState)entry.Status.CurrentState;
                    result[name] = (Enum.IsDefined(state) ? state : ServiceRunState.Unknown,
                        entry.Status.ProcessId == 0 ? null : (int)entry.Status.ProcessId);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or OutOfMemoryException)
        {
            return result;
        }
        finally
        {
            if (scm != IntPtr.Zero)
            {
                CloseServiceHandle(scm);
            }
        }

        return result;
    }

    private const uint ScManagerEnumerateService = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EnumServiceStatusProcess
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? DisplayName;
        public ServiceStatusProcess Status;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusEx(
        IntPtr serviceManager, int infoLevel, int serviceType, int serviceState, IntPtr services, uint bufSize,
        ref uint bytesNeeded, ref uint servicesReturned, ref uint resumeHandle, string? groupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}

/// <summary>
/// Нативный источник задач планировщика на Windows: обход <c>System32\Tasks</c> с пропуском <c>ReparsePoint</c>,
/// потоковое чтение XML (<see cref="TaskXmlStreamReader"/>), разрешение CLSID ComHandler через реестр и сбор имён из
/// <c>TaskCache\Tree</c>. Поддерживает переопределение корня Windows (для WinRE по примонтированному разделу).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsScheduledTaskSource : IScheduledTaskSource
{
    private const string TaskCacheTree = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
    private readonly IRegistryProvider _registry;
    private readonly string _tasksRoot;

    public WindowsScheduledTaskSource(IRegistryProvider registry, string? windowsRoot = null)
    {
        ArgumentNullException.ThrowIfNull(registry);
        _registry = registry;
        var win = windowsRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _tasksRoot = Path.Combine(string.IsNullOrEmpty(win) ? @"C:\Windows" : win, "System32", "Tasks");
    }

    public IReadOnlyList<RawScheduledTaskRecord> GetTasks()
    {
        if (!Directory.Exists(_tasksRoot))
        {
            return [];
        }

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint, // пропуск symlink/junction
        };

        var records = new List<RawScheduledTaskRecord>();
        foreach (var file in Directory.EnumerateFiles(_tasksRoot, "*", options))
        {
            TaskXmlData data;
            try
            {
                data = TaskXmlStreamReader.ReadFile(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
            {
                continue;
            }

            var name = Path.GetRelativePath(_tasksRoot, file).Replace(Path.DirectorySeparatorChar, '\\');
            records.Add(new RawScheduledTaskRecord(name, "\\" + name)
            {
                EnabledXml = data.Enabled,
                Hidden = data.Hidden,
                UserId = data.UserId,
                RunLevel = data.RunLevel,
                ExecActions = data.ExecActions,
                ComHandlers = data.ComHandlers.Select(c => new RawComHandler(c.ClassId, c.Data, ResolveClsid(c.ClassId))).ToArray(),
                PresentOnDisk = true,
                PresentInTaskCache = true,
            });
        }

        return records;
    }

    public IReadOnlyList<string> GetTaskCacheNames()
    {
        var names = new List<string>();
        CollectTree(string.Empty, names, 0);
        return names;
    }

    private void CollectTree(string relative, List<string> names, int depth)
    {
        if (depth > 32)
        {
            return;
        }

        var key = new RegistryKeyPath(RegistryHive.LocalMachine, relative.Length == 0 ? TaskCacheTree : $"{TaskCacheTree}\\{relative}");
        var children = _registry.GetSubKeyNames(key);
        if (children.Count == 0 && relative.Length > 0)
        {
            names.Add(relative);
            return;
        }

        foreach (var child in children)
        {
            CollectTree(relative.Length == 0 ? child : $"{relative}\\{child}", names, depth + 1);
        }
    }

    private string? ResolveClsid(string classId)
    {
        var guid = classId.Trim();
        if (guid.Length == 0)
        {
            return null;
        }

        foreach (var server in new[] { "InprocServer32", "LocalServer32" })
        {
            var value = _registry.GetValue(new RegistryKeyPath(RegistryHive.LocalMachine, $@"SOFTWARE\Classes\CLSID\{guid}\{server}"), string.Empty)?.Value
                ?? _registry.GetValue(new RegistryKeyPath(RegistryHive.CurrentUser, $@"SOFTWARE\Classes\CLSID\{guid}\{server}"), string.Empty)?.Value;
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }
}
