using Sentinel.Core.Ipc;

namespace Sentinel.Service;

/// <summary>Параметры запуска службы (командная строка или <c>binPath</c> службы Windows).</summary>
internal sealed record ServiceOptions(string? DataDirectory, string? RulesDirectory, string PipeName)
{
    public const string ServiceName = "SentinelService";

    public static ServiceOptions Parse(string[] args)
    {
        string? data = null;
        string? rules = null;
        var pipe = IpcProtocol.DefaultPipeName;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--data-dir" when i + 1 < args.Length:
                    data = args[++i];
                    break;
                case "--rules" when i + 1 < args.Length:
                    rules = args[++i];
                    break;
                case "--pipe" when i + 1 < args.Length:
                    pipe = args[++i];
                    break;
                default:
                    throw new ArgumentException($"Неизвестный или неполный параметр '{args[i]}'. Допустимо: --data-dir <каталог>, --rules <каталог>, --pipe <имя>.");
            }
        }

        return new ServiceOptions(data, rules, pipe);
    }
}
