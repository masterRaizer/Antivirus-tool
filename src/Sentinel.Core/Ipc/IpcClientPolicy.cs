using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Sentinel.Core.Realtime;

namespace Sentinel.Core.Ipc;

/// <summary>Кто подключился к каналу службы: PID, образ, повышены ли права, доверенный ли это бинарник Sentinel.</summary>
public sealed record IpcClientIdentity(int ProcessId, string? ImagePath, bool Elevated, bool TrustedSentinelBinary)
{
    /// <summary>Клиент без ограничений (тесты, Linux, автономный режим без канала).</summary>
    public static IpcClientIdentity Unrestricted { get; } = new(0, null, Elevated: true, TrustedSentinelBinary: true);

    /// <summary>Может ли клиент ослаблять защиту: окно Sentinel из каталога программы или процесс с правами администратора.</summary>
    public bool MayWeakenProtection => Elevated || TrustedSentinelBinary;

    public string Describe() => $"PID {ProcessId}{(ImagePath is null ? string.Empty : " (" + ImagePath + ")")}";
}

/// <summary>
/// Самозащита канала службы. Канал открыт для всех вошедших пользователей (иначе окно Sentinel без прав администратора не смогло бы
/// управлять службой), поэтому команды, ослабляющие защиту, служба выполняет только для окна Sentinel из каталога программы
/// (Program Files — запись только администраторам) или для процесса с повышенными правами. Иначе любая программа пользователя, в том
/// числе вредоносная, могла бы сама выключить защиту, внести себя в исключения или вернуть файл из карантина.
/// </summary>
public static class IpcClientPolicy
{
    public const string DeniedMessage =
        "Отказано: это действие ослабляет защиту и выполняется только из окна Sentinel или с правами администратора";

    /// <summary>Ослабляет ли запрос защиту.</summary>
    public static bool IsProtectionWeakening(IpcMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            return request.Type switch
            {
                IpcProtocol.SetRealtime => !IpcProtocol.FromElement<ToggleArgs>(request.Payload, request.Type).Enabled,
                IpcProtocol.SaveSettings => true,
                IpcProtocol.RestoreQuarantine => true,
                IpcProtocol.UndoRollback => true,
                IpcProtocol.ResolveThreat => IpcProtocol.FromElement<ResolveThreatArgs>(request.Payload, request.Type).Decision == ThreatDecision.Allow,
                _ => false,
            };
        }
        catch (IpcProtocolException)
        {
            return true; // нераспознанные аргументы ослабляющей команды — считать ослабляющей, а ошибку вернёт обработчик
        }
    }

    /// <summary>Сообщение об отказе или <c>null</c>, если клиенту запрос разрешён.</summary>
    public static string? Authorize(IpcMessage request, IpcClientIdentity client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return IsProtectionWeakening(request) && !client.MayWeakenProtection
            ? $"{DeniedMessage} (клиент: {client.Describe()})."
            : null;
    }
}

/// <summary>Определение клиента канала через Win32: PID клиента, путь образа и повышение прав его маркера.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsIpcClientIdentifier
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenElevation = 20;

    /// <summary>Окна, которым разрешено ослаблять защиту без повышения прав: только из каталога службы.</summary>
    private static readonly string[] TrustedClients = ["Sentinel.App.exe"];

    public static IpcClientIdentity Identify(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid))
        {
            return new IpcClientIdentity(0, null, false, false); // неизвестный клиент — только безопасные команды
        }

        var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero)
        {
            return new IpcClientIdentity((int)pid, null, false, false);
        }

        try
        {
            var image = QueryImage(process);
            return new IpcClientIdentity((int)pid, image, IsElevated(process), IsTrustedBinary(image));
        }
        finally
        {
            CloseHandle(process);
        }
    }

    internal static bool IsTrustedBinary(string? image)
    {
        if (string.IsNullOrEmpty(image))
        {
            return false;
        }

        var directory = Path.GetDirectoryName(image)?.TrimEnd('\\');
        var own = AppContext.BaseDirectory.TrimEnd('\\');
        return string.Equals(directory, own, StringComparison.OrdinalIgnoreCase)
            && TrustedClients.Contains(Path.GetFileName(image), StringComparer.OrdinalIgnoreCase);
    }

    private static string? QueryImage(IntPtr process)
    {
        var buffer = new char[1024];
        var size = buffer.Length;
        return QueryFullProcessImageName(process, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
    }

    private static bool IsElevated(IntPtr process)
    {
        if (!OpenProcessToken(process, TOKEN_QUERY, out var token))
        {
            return false;
        }

        try
        {
            return GetTokenInformation(token, TokenElevation, out var elevation, sizeof(int), out _) && elevation != 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, [Out] char[] name, ref int size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int length, out int returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
