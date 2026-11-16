using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Core.Audit.Process;

/// <summary>Состояние TCP-соединения (подмножество MIB_TCP_STATE).</summary>
public enum TcpConnectionState
{
    Unknown,
    Listen,
    Established,
    Other,
}

/// <summary>TCP-соединение или прослушиваемый порт процесса.</summary>
public sealed record NetworkConnection(
    int Pid,
    TcpConnectionState State,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort);

/// <summary>Поставщик таблицы TCP-соединений с PID владельца. В тестах — заглушка, в Windows — <c>GetExtendedTcpTable</c>.</summary>
public interface INetworkConnectionProvider
{
    IReadOnlyList<NetworkConnection> GetConnections();
}

/// <summary>Таблица TCP (IPv4 и IPv6) через <c>iphlpapi!GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)</c>.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsNetworkConnectionProvider : INetworkConnectionProvider
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint NO_ERROR = 0;
    private const int MIB_TCP_STATE_LISTEN = 2;
    private const int MIB_TCP_STATE_ESTAB = 5;

    public IReadOnlyList<NetworkConnection> GetConnections()
    {
        var list = new List<NetworkConnection>();
        Read(AF_INET, list);
        Read(AF_INET6, list);
        return list;
    }

    private static void Read(int family, List<NetworkConnection> list)
    {
        var size = 0;
        var result = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
        for (var attempt = 0; attempt < 3 && result == ERROR_INSUFFICIENT_BUFFER; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
                if (result == NO_ERROR)
                {
                    Parse(buffer, size, family, list);
                    return;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static void Parse(IntPtr buffer, int size, int family, List<NetworkConnection> list)
    {
        var bytes = new byte[size];
        Marshal.Copy(buffer, bytes, 0, size);
        var span = bytes.AsSpan();
        var count = BinaryPrimitives.ReadInt32LittleEndian(span);

        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid — по 4 байта (24 байта).
        // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid (56 байт).
        var rowSize = family == AF_INET ? 24 : 56;
        for (var i = 0; i < count; i++)
        {
            var offset = 4 + (i * rowSize);
            if (offset + rowSize > span.Length)
            {
                break;
            }

            var row = span.Slice(offset, rowSize);
            if (family == AF_INET)
            {
                list.Add(new NetworkConnection(
                    Pid: BinaryPrimitives.ReadInt32LittleEndian(row[20..]),
                    State: MapState(BinaryPrimitives.ReadInt32LittleEndian(row)),
                    LocalAddress: new IPAddress(row.Slice(4, 4)).ToString(),
                    LocalPort: Port(row.Slice(8, 4)),
                    RemoteAddress: new IPAddress(row.Slice(12, 4)).ToString(),
                    RemotePort: Port(row.Slice(16, 4))));
            }
            else
            {
                list.Add(new NetworkConnection(
                    Pid: BinaryPrimitives.ReadInt32LittleEndian(row[52..]),
                    State: MapState(BinaryPrimitives.ReadInt32LittleEndian(row[48..])),
                    LocalAddress: new IPAddress(row[..16].ToArray()).ToString(),
                    LocalPort: Port(row.Slice(20, 4)),
                    RemoteAddress: new IPAddress(row.Slice(24, 16).ToArray()).ToString(),
                    RemotePort: Port(row.Slice(44, 4))));
            }
        }
    }

    /// <summary>Порт хранится в сетевом порядке байт в младших двух байтах DWORD.</summary>
    private static int Port(ReadOnlySpan<byte> dword) => (dword[0] << 8) | dword[1];

    private static TcpConnectionState MapState(int state) => state switch
    {
        MIB_TCP_STATE_LISTEN => TcpConnectionState.Listen,
        MIB_TCP_STATE_ESTAB => TcpConnectionState.Established,
        _ => TcpConnectionState.Other,
    };

    [DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder, int ulAf, int tableClass, uint reserved);
}
