using System.Buffers.Binary;
using System.Text;

namespace Sentinel.Core.Audit.Persistence;

/// <summary>Извлечённые из ярлыка (.lnk) данные: путь к цели и аргументы.</summary>
public sealed record ShellLinkInfo(string? TargetPath, string? Arguments, string? RelativePath);

/// <summary>
/// Минимальный разбор формата Shell Link (.lnk) по спецификации MS-SHLLINK:
/// извлекает LocalBasePath из структуры LinkInfo и COMMAND_LINE_ARGUMENTS/RELATIVE_PATH
/// из StringData. Этого достаточно, чтобы узнать, на какой файл указывает ярлык автозапуска.
/// Платформонезависим и покрыт unit-тестами на синтетических .lnk.
/// </summary>
public static class ShellLinkParser
{
    private static readonly byte[] LinkClsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    private const int HeaderSize = 0x4C;

    // Биты LinkFlags
    private const uint HasLinkTargetIdList = 0x1;
    private const uint HasLinkInfo = 0x2;
    private const uint HasName = 0x4;
    private const uint HasRelativePath = 0x8;
    private const uint HasWorkingDir = 0x10;
    private const uint HasArguments = 0x20;
    private const uint HasIconLocation = 0x40;
    private const uint IsUnicode = 0x80;

    public static bool IsShellLink(ReadOnlySpan<byte> data) =>
        data.Length >= HeaderSize &&
        BinaryPrimitives.ReadInt32LittleEndian(data) == HeaderSize &&
        data.Slice(4, 16).SequenceEqual(LinkClsid);

    public static ShellLinkInfo? Parse(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (!IsShellLink(data))
        {
            return null;
        }

        try
        {
            return ParseCore(data);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException or OverflowException)
        {
            // Повреждённый или нестандартный ярлык — не падаем, просто нет данных.
            return null;
        }
    }

    private static ShellLinkInfo? ParseCore(byte[] data)
    {
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x14));
        var unicode = (flags & IsUnicode) != 0;
        var pos = HeaderSize;

        if ((flags & HasLinkTargetIdList) != 0)
        {
            if (pos + 2 > data.Length)
            {
                return null;
            }

            var idListSize = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(pos));
            pos += 2 + idListSize;
        }

        string? targetPath = null;
        if ((flags & HasLinkInfo) != 0)
        {
            targetPath = ParseLinkInfo(data, pos, out var linkInfoSize);
            pos += linkInfoSize;
        }

        string? name = null, relativePath = null, arguments = null;
        if ((flags & HasName) != 0)
        {
            name = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasRelativePath) != 0)
        {
            relativePath = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasWorkingDir) != 0)
        {
            _ = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasArguments) != 0)
        {
            arguments = ReadStringData(data, ref pos, unicode);
        }

        _ = name;
        if ((flags & HasIconLocation) != 0)
        {
            _ = ReadStringData(data, ref pos, unicode);
        }

        return new ShellLinkInfo(targetPath, arguments, relativePath);
    }

    private static string? ParseLinkInfo(byte[] data, int start, out int linkInfoSize)
    {
        linkInfoSize = 0;
        if (start + 0x1C > data.Length)
        {
            return null;
        }

        var span = data.AsSpan(start);
        var size = (int)BinaryPrimitives.ReadUInt32LittleEndian(span);
        if (size <= 0 || start + size > data.Length)
        {
            return null;
        }

        linkInfoSize = size;
        var headerSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[4..]);
        var localBasePathOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[16..]);
        var commonPathSuffixOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[24..]);

        string? basePath = null;
        if (localBasePathOffset > 0 && localBasePathOffset < size)
        {
            basePath = ReadAnsiZ(span, localBasePathOffset);
        }

        // Unicode-смещения присутствуют только если LinkInfoHeaderSize >= 0x24.
        if (headerSize >= 0x24)
        {
            var localBasePathOffsetUnicode = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[28..]);
            if (localBasePathOffsetUnicode > 0 && localBasePathOffsetUnicode < size)
            {
                basePath = ReadUnicodeZ(span, localBasePathOffsetUnicode);
            }
        }

        if (basePath is null)
        {
            return null;
        }

        var suffix = commonPathSuffixOffset > 0 && commonPathSuffixOffset < size
            ? ReadAnsiZ(span, commonPathSuffixOffset)
            : null;

        return string.IsNullOrEmpty(suffix) ? basePath : basePath + suffix;
    }

    private static string? ReadStringData(byte[] data, ref int pos, bool unicode)
    {
        if (pos + 2 > data.Length)
        {
            return null;
        }

        var count = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(pos));
        pos += 2;
        var byteCount = unicode ? count * 2 : count;
        if (byteCount == 0 || pos + byteCount > data.Length)
        {
            pos += Math.Max(0, Math.Min(byteCount, data.Length - pos));
            return count == 0 ? string.Empty : null;
        }

        var value = unicode
            ? Encoding.Unicode.GetString(data, pos, byteCount)
            : Encoding.Default.GetString(data, pos, byteCount);
        pos += byteCount;
        return value;
    }

    private static string ReadAnsiZ(ReadOnlySpan<byte> span, int offset)
    {
        var end = offset;
        while (end < span.Length && span[end] != 0)
        {
            end++;
        }

        return Encoding.ASCII.GetString(span[offset..end]);
    }

    private static string ReadUnicodeZ(ReadOnlySpan<byte> span, int offset)
    {
        var end = offset;
        while (end + 1 < span.Length && !(span[end] == 0 && span[end + 1] == 0))
        {
            end += 2;
        }

        return Encoding.Unicode.GetString(span[offset..end]);
    }
}
