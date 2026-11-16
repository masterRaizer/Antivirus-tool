namespace Sentinel.Core.Protection;

/// <summary>Разобранный <c>autorun.inf</c>: команды автозапуска и значок.</summary>
public sealed record AutorunInfo
{
    public string? Open { get; init; }

    public string? ShellExecute { get; init; }

    public string? ShellOpenCommand { get; init; }

    public string? ShellExploreCommand { get; init; }

    public string? Icon { get; init; }

    /// <summary>Исполняемые цели автозапуска (без аргументов), извлечённые из команд.</summary>
    public IReadOnlyList<string> Targets { get; init; } = [];

    public bool HasExecutableDirective => Targets.Count > 0;
}

/// <summary>
/// Потоковый разбор <c>autorun.inf</c> (буфер 64 КБ, без <see cref="File.ReadAllText"/>). Читается только секция
/// <c>[autorun]</c>: ключи <c>open</c>, <c>shellexecute</c>, <c>shell\open\command</c>, <c>shell\explore\command</c>, <c>icon</c>.
/// </summary>
public static class AutorunInfParser
{
    private const int BufferSize = 65536;
    private const long MaxBytes = 1 << 20;

    public static AutorunInfo ParseFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, BufferSize, FileOptions.SequentialScan);
        return Read(stream);
    }

    public static AutorunInfo Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var reader = new StreamReader(stream, System.Text.Encoding.Default, detectEncodingFromByteOrderMarks: true, BufferSize, leaveOpen: true);
        string? open = null, shellExecute = null, shellOpen = null, shellExplore = null, icon = null;
        var inAutorun = false;
        long read = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            read += line.Length + 2;
            if (read > MaxBytes)
            {
                break;
            }

            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] == ';')
            {
                continue;
            }

            if (trimmed[0] == '[')
            {
                inAutorun = trimmed.Equals("[autorun]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (!inAutorun)
            {
                continue;
            }

            var eq = trimmed.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                continue;
            }

            var key = trimmed[..eq].Trim().ToLowerInvariant();
            var value = trimmed[(eq + 1)..].Trim();
            switch (key)
            {
                case "open": open ??= value; break;
                case "shellexecute": shellExecute ??= value; break;
                case @"shell\open\command": shellOpen ??= value; break;
                case @"shell\explore\command": shellExplore ??= value; break;
                case "icon": icon ??= value; break;
            }
        }

        var targets = new List<string>();
        foreach (var command in new[] { open, shellExecute, shellOpen, shellExplore })
        {
            if (!string.IsNullOrWhiteSpace(command))
            {
                targets.Add(ExtractTarget(command));
            }
        }

        return new AutorunInfo
        {
            Open = open,
            ShellExecute = shellExecute,
            ShellOpenCommand = shellOpen,
            ShellExploreCommand = shellExplore,
            Icon = icon,
            Targets = targets,
        };
    }

    private static string ExtractTarget(string command)
    {
        var text = command.Trim();
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            return end > 0 ? text[1..end] : text[1..];
        }

        var space = text.IndexOf(' ', StringComparison.Ordinal);
        return space < 0 ? text : text[..space];
    }
}
