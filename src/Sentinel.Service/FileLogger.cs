using System.Globalization;
using System.Text;

namespace Sentinel.Service;

/// <summary>
/// Диагностический журнал службы в файлах <c>&lt;каталог данных&gt;\Logs\service-ГГГГММДД.log</c> (UTF-8, по файлу на сутки,
/// хранится <see cref="RetentionDays"/> дней). Уровни задаются фильтрами логирования: категории <c>Sentinel.*</c> — с Information
/// (подключение драйвера, синхронизация PID, запуск мониторов), остальные — с Warning. Файл открыт с общим доступом на чтение,
/// поэтому журнал можно копировать, не останавливая службу.
/// </summary>
internal sealed class FileLoggerProvider : ILoggerProvider
{
    public const int RetentionDays = 14;

    private readonly string _directory;
    private readonly object _sync = new();
    private StreamWriter? _writer;
    private DateOnly _day;

    public FileLoggerProvider(string directory)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        _directory = directory;
        try
        {
            Directory.CreateDirectory(directory);
            foreach (var old in Directory.EnumerateFiles(directory, "service-*.log"))
            {
                if (File.GetLastWriteTimeUtc(old) < DateTime.UtcNow.AddDays(-RetentionDays))
                {
                    File.Delete(old);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // каталог журналов недоступен — служба работает дальше, журнал пишется в EventLog/консоль
        }
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    public void Dispose()
    {
        lock (_sync)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    internal void Write(string category, LogLevel level, string message, Exception? exception)
    {
        var now = DateTime.UtcNow;
        var line = new StringBuilder()
            .Append(now.ToString("yyyy-MM-dd HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture))
            .Append(" [").Append(level).Append("] ")
            .Append(category).Append(": ")
            .Append(message.ReplaceLineEndings(" "));
        if (exception is not null)
        {
            line.Append(" | ").Append(exception.GetType().Name).Append(": ").Append(exception.Message.ReplaceLineEndings(" "));
        }

        lock (_sync)
        {
            try
            {
                var today = DateOnly.FromDateTime(now);
                if (_writer is null || today != _day)
                {
                    _writer?.Dispose();
                    var path = Path.Combine(_directory, $"service-{today:yyyyMMdd}.log");
                    var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    _writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
                    _day = today;
                }

                _writer.WriteLine(line.ToString());
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _writer?.Dispose();
                _writer = null; // повторная попытка открыть файл — на следующей записи
            }
        }
    }

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);
            if (IsEnabled(logLevel))
            {
                provider.Write(category, logLevel, formatter(state, exception), exception);
            }
        }
    }
}
