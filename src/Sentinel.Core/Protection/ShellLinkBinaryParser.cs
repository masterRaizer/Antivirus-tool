using System.Buffers.Binary;
using System.Text;

namespace Sentinel.Core.Protection;

/// <summary>Разобранные поля ярлыка Shell Link (.lnk) по спецификации [MS-SHLLINK].</summary>
public sealed record ShellLinkDetails(
    string? TargetPath,
    string? RelativePath,
    string? WorkingDirectory,
    string? Arguments,
    string? IconLocation);

/// <summary>
/// Чистый бинарный разбор формата Shell Link (.lnk) по [MS-SHLLINK] без COM (<c>WScript.Shell</c>): работает на Linux и в WinRE.
/// Читает заголовок (<c>HeaderSize = 0x4C</c>, <c>LinkCLSID</c>), <c>LinkFlags</c>, пропускает <c>LinkTargetIDList</c> по размеру,
/// извлекает <c>LocalBasePath</c> из <c>LinkInfo</c> и строки <c>RelativePath</c>/<c>WorkingDir</c>/<c>Arguments</c>/<c>IconLocation</c>
/// из <c>StringData</c> (с учётом флага <c>IsUnicode</c>). Файл читается через <see cref="FileStream"/> с жёстким лимитом.
/// </summary>
public static class ShellLinkBinaryParser
{
    public const int HeaderSize = 0x4C;
    private const int MaxLinkBytes = 1 << 20; // .lnk не бывают большими; защита от подложенного огромного файла

    private static readonly byte[] LinkClsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    private const uint HasLinkTargetIdList = 0x01;
    private const uint HasLinkInfo = 0x02;
    private const uint HasName = 0x04;
    private const uint HasRelativePath = 0x08;
    private const uint HasWorkingDir = 0x10;
    private const uint HasArguments = 0x20;
    private const uint HasIconLocation = 0x40;
    private const uint IsUnicode = 0x80;

    public static bool IsShellLink(ReadOnlySpan<byte> data) =>
        data.Length >= HeaderSize
        && BinaryPrimitives.ReadInt32LittleEndian(data) == HeaderSize
        && data.Slice(4, 16).SequenceEqual(LinkClsid);

    public static ShellLinkDetails? ParseFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
        var length = (int)Math.Min(stream.Length, MaxLinkBytes);
        var buffer = new byte[length];
        stream.ReadExactly(buffer, 0, length);
        return Parse(buffer);
    }

    public static ShellLinkDetails? Parse(byte[] data)
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
            return null;
        }
    }

    private static ShellLinkDetails ParseCore(byte[] data)
    {
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x14));
        var unicode = (flags & IsUnicode) != 0;
        var pos = HeaderSize;

        if ((flags & HasLinkTargetIdList) != 0 && pos + 2 <= data.Length)
        {
            var idListSize = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(pos));
            pos += 2 + idListSize;
        }

        string? target = null;
        if ((flags & HasLinkInfo) != 0)
        {
            target = ParseLinkInfo(data, pos, out var linkInfoSize);
            pos += linkInfoSize;
        }

        string? relative = null, workingDir = null, arguments = null, icon = null;
        if ((flags & HasName) != 0)
        {
            _ = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasRelativePath) != 0)
        {
            relative = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasWorkingDir) != 0)
        {
            workingDir = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasArguments) != 0)
        {
            arguments = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasIconLocation) != 0)
        {
            icon = ReadStringData(data, ref pos, unicode);
        }

        return new ShellLinkDetails(target, relative, workingDir, arguments, icon);
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

        if (headerSize >= 0x24)
        {
            var unicodeOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[28..]);
            if (unicodeOffset > 0 && unicodeOffset < size)
            {
                basePath = ReadUnicodeZ(span, unicodeOffset);
            }
        }

        if (basePath is null)
        {
            return null;
        }

        var suffix = commonPathSuffixOffset > 0 && commonPathSuffixOffset < size ? ReadAnsiZ(span, commonPathSuffixOffset) : null;
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

        var value = unicode ? Encoding.Unicode.GetString(data, pos, byteCount) : Encoding.Latin1.GetString(data, pos, byteCount);
        pos += byteCount;
        return value;
    }

    private static string ReadAnsiZ(ReadOnlySpan<byte> span, int offset)
    {
        var end = span[offset..].IndexOf((byte)0);
        var slice = end < 0 ? span[offset..] : span.Slice(offset, end);
        return Encoding.Latin1.GetString(slice);
    }

    private static string ReadUnicodeZ(ReadOnlySpan<byte> span, int offset)
    {
        var i = offset;
        while (i + 1 < span.Length && !(span[i] == 0 && span[i + 1] == 0))
        {
            i += 2;
        }

        return Encoding.Unicode.GetString(span[offset..i]);
    }
}
