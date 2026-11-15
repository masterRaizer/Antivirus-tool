using System.Buffers.Binary;

namespace Sentinel.Core.Pe;

/// <summary>
/// Чтение таблицы импорта PE (IMAGE_DIRECTORY_ENTRY_IMPORT): имена импортируемых функций по всем библиотекам.
/// Читает только каталог дескрипторов, таблицы thunk и короткие имена; границы файла и количество записей ограничены,
/// поэтому повреждённый или нарочно искажённый образ не приводит ни к исключению, ни к большому расходу памяти.
/// </summary>
public static class PeImportReader
{
    private const int DescriptorSize = 20;
    private const int MaxDescriptors = 1024;
    private const int MaxThunksPerLibrary = 8192;
    private const int MaxTotalNames = 16384;
    private const int MaxNameLength = 128;

    /// <summary>Имена функций (без учёта ординальных импортов) всех импортируемых библиотек.</summary>
    public static IReadOnlySet<string> ReadFunctionNames(Stream stream, PeInfo info)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(info);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (info.DataDirectories.Count < 2 || !info.DataDirectories[1].IsPresent)
        {
            return names;
        }

        var directory = info.DataDirectories[1];
        var tableOffset = RvaToOffset(info, directory.VirtualAddress, stream.Length);
        if (tableOffset < 0)
        {
            return names;
        }

        var tableBytes = (int)Math.Min(directory.Size, (uint)(DescriptorSize * MaxDescriptors));
        var table = new byte[tableBytes];
        if (!ReadAt(stream, tableOffset, table))
        {
            return names;
        }

        var thunkSize = info.Is64Bit ? 8 : 4;
        var ordinalFlag = info.Is64Bit ? 0x8000_0000_0000_0000UL : 0x8000_0000UL;
        Span<byte> thunk = stackalloc byte[8];
        Span<byte> nameBuffer = stackalloc byte[MaxNameLength + 2];
        for (var d = 0; d + DescriptorSize <= table.Length; d += DescriptorSize)
        {
            var original = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(d));
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(d + 12));
            var first = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(d + 16));
            if (nameRva == 0 && first == 0 && original == 0)
            {
                break;
            }

            var thunkRva = original != 0 ? original : first;
            var thunkOffset = RvaToOffset(info, thunkRva, stream.Length);
            if (thunkOffset < 0)
            {
                continue;
            }

            for (var i = 0; i < MaxThunksPerLibrary && names.Count < MaxTotalNames; i++)
            {
                if (!ReadAt(stream, thunkOffset + ((long)i * thunkSize), thunk[..thunkSize]))
                {
                    break;
                }

                var value = info.Is64Bit ? BinaryPrimitives.ReadUInt64LittleEndian(thunk) : BinaryPrimitives.ReadUInt32LittleEndian(thunk);
                if (value == 0)
                {
                    break;
                }

                if ((value & ordinalFlag) != 0)
                {
                    continue;
                }

                var nameOffset = RvaToOffset(info, (uint)(value & 0x7FFF_FFFF), stream.Length);
                if (nameOffset < 0)
                {
                    continue;
                }

                var available = (int)Math.Min(nameBuffer.Length, stream.Length - (nameOffset + 2));
                if (available <= 0)
                {
                    continue;
                }

                stream.Position = nameOffset + 2;
                var read = stream.Read(nameBuffer[..available]);
                var span = nameBuffer[..read];
                var end = span.IndexOf((byte)0);
                var raw = end < 0 ? span : span[..end];
                if (raw.Length > 0 && IsPrintableAscii(raw))
                {
                    names.Add(System.Text.Encoding.ASCII.GetString(raw));
                }
            }
        }

        return names;
    }

    private static bool IsPrintableAscii(ReadOnlySpan<byte> raw)
    {
        foreach (var b in raw)
        {
            if (b is < 0x21 or > 0x7E)
            {
                return false;
            }
        }

        return true;
    }

    private static long RvaToOffset(PeInfo info, uint rva, long fileLength)
    {
        foreach (var section in info.Sections)
        {
            var span = Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (rva >= section.VirtualAddress && rva < (ulong)section.VirtualAddress + span)
            {
                var offset = (long)section.PointerToRawData + (rva - section.VirtualAddress);
                return offset < fileLength ? offset : -1;
            }
        }

        // Заголовки (RVA ниже первой секции) отображаются один к одному.
        return rva < (info.Sections.Count > 0 ? info.Sections.Min(s => s.VirtualAddress) : 0) && rva < fileLength ? rva : -1;
    }

    private static bool ReadAt(Stream stream, long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset + buffer.Length > stream.Length)
        {
            return false;
        }

        stream.Position = offset;
        stream.ReadExactly(buffer);
        return true;
    }
}
