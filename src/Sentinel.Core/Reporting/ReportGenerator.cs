using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Reporting;

/// <summary>
/// Генератор отчётов: структурированный JSON и самодостаточный HTML (один файл, тёмная тема,
/// без внешних ресурсов — ни CDN, ни шрифтов, ни сценариев со стороны). Все значения из системы
/// (пути, командные строки, имена) экранируются: их содержимое контролирует потенциальный злоумышленник.
/// </summary>
public static class ReportGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // Кириллица остаётся читаемой; HTML-чувствительные символы (<, >, &) всё равно экранируются.
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
    };

    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public static string ToJson(SentinelReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return JsonSerializer.Serialize(report, JsonOptions);
    }

    public static void WriteJson(SentinelReport report, string path) => Write(path, ToJson(report));

    public static void WriteHtml(SentinelReport report, string path) => Write(path, ToHtml(report));

    private static void Write(string path, string content)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllText(full, content, Utf8NoBom);
    }

    public static string FormatDuration(TimeSpan duration) =>
        duration.TotalHours >= 1
            ? duration.ToString(@"h\:mm\:ss", CultureInfo.InvariantCulture)
            : duration.TotalMinutes >= 1
                ? duration.ToString(@"m\:ss", CultureInfo.InvariantCulture) + " мин"
                : duration.TotalSeconds.ToString("0.00", CultureInfo.InvariantCulture) + " с";

    public static string ToHtml(SentinelReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var sb = new StringBuilder(64 * 1024);
        sb.Append("<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        // Политика запрещает любые внешние загрузки: отчёт гарантированно автономен.
        sb.Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\">\n");
        sb.Append("<title>").Append(E(report.Title)).Append("</title>\n<style>\n").Append(Css).Append("</style>\n</head>\n<body>\n");

        AppendHeader(sb, report);
        AppendSummary(sb, report);
        AppendAreas(sb, report);
        AppendFindings(sb, report);
        AppendActions(sb, report);

        sb.Append("<footer>Сформировано ").Append(E(report.Product)).Append(" · ")
            .Append(E(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(" UTC · отчёт автономен и не обращается к сети</footer>\n");
        sb.Append("<script>\n").Append(Script).Append("</script>\n</body>\n</html>\n");
        return sb.ToString();
    }

    private static void AppendHeader(StringBuilder sb, SentinelReport r)
    {
        var mode = r.Mode switch
        {
            "remediate" => "нейтрализация",
            "dry-run" => "предпросмотр (dry-run)",
            _ => "аудит",
        };
        sb.Append("<header>\n<div>\n<p class=\"eyebrow\">Sentinel · системный аудитор</p>\n<h1>").Append(E(r.Title)).Append("</h1>\n</div>\n<dl class=\"meta\">\n");
        Meta(sb, "Команда", r.Command);
        Meta(sb, "Узел", r.Host);
        Meta(sb, "Начало (UTC)", r.StartedAtUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        Meta(sb, "Режим", mode);
        sb.Append("</dl>\n</header>\n");
    }

    private static void Meta(StringBuilder sb, string label, string value) =>
        sb.Append("<div><dt>").Append(E(label)).Append("</dt><dd>").Append(E(value)).Append("</dd></div>\n");

    private static void AppendSummary(StringBuilder sb, SentinelReport r)
    {
        sb.Append("<section class=\"cards\" aria-label=\"Сводка\">\n");
        Card(sb, "Всего проверено", r.TotalChecked.ToString(CultureInfo.InvariantCulture), "объектов во всех областях", null);
        Card(sb, "Найдено", r.Found.ToString(CultureInfo.InvariantCulture), "угроз и отклонений", r.Found > 0 ? "warn" : "ok");
        Card(sb, "Изолировано", r.Quarantined.ToString(CultureInfo.InvariantCulture), "файлов в карантине", r.Quarantined > 0 ? "ok" : null);
        Card(sb, "Очищено в конфигурации", r.ConfigCleaned.ToString(CultureInfo.InvariantCulture), "параметров возвращено к эталону", r.ConfigCleaned > 0 ? "ok" : null);
        Card(sb, "Время работы", FormatDuration(r.Duration), "от запуска до отчёта", null);
        sb.Append("</section>\n");
    }

    private static void Card(StringBuilder sb, string label, string value, string hint, string? tone)
    {
        sb.Append("<div class=\"card").Append(tone is null ? string.Empty : " " + tone).Append("\"><span class=\"label\">").Append(E(label))
            .Append("</span><span class=\"value\">").Append(E(value)).Append("</span><span class=\"hint\">").Append(E(hint)).Append("</span></div>\n");
    }

    private static void AppendAreas(StringBuilder sb, SentinelReport r)
    {
        sb.Append("<section>\n<h2>Проверенные области</h2>\n<div class=\"table-wrap\"><table>\n<thead><tr><th>Область</th><th class=\"num\">Проверено</th><th class=\"num\">Найдено</th><th>Примечание</th></tr></thead>\n<tbody>\n");
        if (r.Areas.Count == 0)
        {
            sb.Append("<tr><td colspan=\"4\" class=\"muted\">Области не проверялись.</td></tr>\n");
        }

        foreach (var a in r.Areas)
        {
            sb.Append("<tr><td>").Append(E(a.Name)).Append("</td><td class=\"num\">").Append(a.Checked.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td class=\"num").Append(a.Found > 0 ? " hit" : string.Empty).Append("\">").Append(a.Found.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td class=\"muted\">").Append(E(a.Note ?? "—")).Append("</td></tr>\n");
        }

        sb.Append("</tbody>\n</table></div>\n</section>\n");
    }

    private static void AppendFindings(StringBuilder sb, SentinelReport r)
    {
        sb.Append("<section>\n<div class=\"section-head\"><h2>Находки</h2><span id=\"counter\" class=\"muted\"></span></div>\n");
        if (r.Findings.Count == 0)
        {
            sb.Append("<p class=\"empty\">Угроз и отклонений не обнаружено.</p>\n</section>\n");
            return;
        }

        sb.Append("<div class=\"filters\" role=\"group\" aria-label=\"Фильтр находок\">\n<label>Критичность\n<select id=\"f-severity\">\n<option value=\"\">Все</option>\n");
        foreach (var sev in r.Findings.Select(f => f.Severity).Distinct().OrderByDescending(s => s))
        {
            sb.Append("<option value=\"").Append(E(sev.ToString())).Append("\">").Append(E(SeverityLabel(sev))).Append("</option>\n");
        }

        sb.Append("</select></label>\n<label>Статус действия\n<select id=\"f-status\">\n<option value=\"\">Все</option>\n");
        foreach (var st in r.Findings.Select(f => f.ActionStatus).Distinct().OrderBy(s => s))
        {
            sb.Append("<option value=\"").Append(E(st.ToString())).Append("\">").Append(E(StatusLabel(st))).Append("</option>\n");
        }

        sb.Append("</select></label>\n<label class=\"grow\">Поиск\n<input id=\"f-text\" type=\"search\" placeholder=\"имя, путь, SHA-256, правило\"></label>\n");
        sb.Append("<button id=\"f-reset\" type=\"button\">Сбросить</button>\n</div>\n<div id=\"findings\">\n");

        foreach (var f in r.Findings)
        {
            sb.Append("<article class=\"finding sev-").Append(E(f.Severity.ToString().ToLowerInvariant()))
                .Append("\" data-severity=\"").Append(E(f.Severity.ToString()))
                .Append("\" data-status=\"").Append(E(f.ActionStatus.ToString())).Append("\">\n");
            sb.Append("<div class=\"finding-head\"><h3>").Append(E(f.Name)).Append("</h3><div class=\"badges\"><span class=\"badge sev\">")
                .Append(E(SeverityLabel(f.Severity))).Append("</span><span class=\"badge st st-").Append(E(f.ActionStatus.ToString().ToLowerInvariant())).Append("\">")
                .Append(E(StatusLabel(f.ActionStatus))).Append("</span></div></div>\n");
            if (f.Description.Length > 0)
            {
                sb.Append("<p class=\"desc\">").Append(E(f.Description)).Append("</p>\n");
            }

            sb.Append("<dl class=\"props\">\n");
            Prop(sb, "Область", f.Area, mono: false);
            Prop(sb, "Полный путь", f.Path ?? "—", mono: true);
            Prop(sb, "SHA-256", f.Sha256 ?? "—", mono: true);
            Prop(sb, "Энтропия", f.Entropy is { } h ? h.ToString("F4", CultureInfo.InvariantCulture) + " бит/байт" : "—", mono: false);
            Prop(sb, "Цифровая подпись", f.SignatureStatus, mono: false);
            Prop(sb, "Правило / эвристика", f.Rule, mono: true);
            Prop(sb, "Критичность", SeverityLabel(f.Severity), mono: false);
            Prop(sb, "Итог действия", StatusLabel(f.ActionStatus) + (string.IsNullOrEmpty(f.ActionMessage) ? string.Empty : " — " + f.ActionMessage), mono: false);
            sb.Append("</dl>\n");

            if (f.Evidence.Count > 0)
            {
                sb.Append("<details><summary>Доказательства (").Append(f.Evidence.Count.ToString(CultureInfo.InvariantCulture)).Append(")</summary><dl class=\"props evidence\">\n");
                foreach (var e in f.Evidence)
                {
                    Prop(sb, e.Key, e.Value, mono: true);
                }

                sb.Append("</dl></details>\n");
            }

            sb.Append("</article>\n");
        }

        sb.Append("</div>\n<p id=\"no-match\" class=\"empty\" hidden>Нет находок, подходящих под фильтр.</p>\n</section>\n");
    }

    private static void Prop(StringBuilder sb, string label, string value, bool mono) =>
        sb.Append("<div><dt>").Append(E(label)).Append("</dt><dd").Append(mono ? " class=\"mono\"" : string.Empty).Append('>').Append(E(value)).Append("</dd></div>\n");

    private static void AppendActions(StringBuilder sb, SentinelReport r)
    {
        if (r.Actions.Count == 0)
        {
            return;
        }

        sb.Append("<section>\n<h2>Журнал действий</h2>\n<div class=\"table-wrap\"><table>\n<thead><tr><th>Действие</th><th>Объект</th><th>Статус</th><th>Результат</th><th>Запись отката</th></tr></thead>\n<tbody>\n");
        foreach (var a in r.Actions)
        {
            sb.Append("<tr><td>").Append(E(a.Kind.ToString())).Append("</td><td class=\"mono\">").Append(E(a.Target)).Append("</td><td>")
                .Append(E(a.Status.ToString())).Append("</td><td>").Append(E(a.Message)).Append("</td><td class=\"mono\">").Append(E(a.RollbackId ?? "—")).Append("</td></tr>\n");
        }

        sb.Append("</tbody>\n</table></div>\n</section>\n");
    }

    public static string SeverityLabel(Severity severity) => severity switch
    {
        Severity.Critical => "Критическая",
        Severity.High => "Высокая",
        Severity.Medium => "Средняя",
        Severity.Low => "Низкая",
        _ => "Информация",
    };

    public static string StatusLabel(FindingActionStatus status) => status switch
    {
        FindingActionStatus.Detected => "Обнаружено",
        FindingActionStatus.Planned => "Запланировано (dry-run)",
        FindingActionStatus.Quarantined => "Изолировано",
        FindingActionStatus.Terminated => "Процесс завершён",
        FindingActionStatus.Cleaned => "Очищено",
        FindingActionStatus.Blocked => "Защищено белым списком",
        FindingActionStatus.Skipped => "Пропущено",
        _ => "Ошибка",
    };

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private const string Css = """
        :root{--bg:#0d1117;--panel:#151b23;--panel2:#1b222c;--line:#2a323d;--text:#e6edf3;--muted:#8b98a8;--accent:#4cc2ff;
        --crit:#ff5c7a;--high:#ff8f4d;--med:#f2c94c;--low:#58c4a0;--info:#7d8fa5;--ok:#3fb97f;
        --mono:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;
        --sans:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
        *{box-sizing:border-box}
        html{color-scheme:dark}
        body{margin:0;padding:32px clamp(16px,4vw,48px) 48px;background:var(--bg);color:var(--text);font:15px/1.55 var(--sans);max-width:1240px;margin-inline:auto}
        h1{font-size:26px;line-height:1.2;margin:0;font-weight:650;letter-spacing:-.01em;text-wrap:balance}
        h2{font-size:17px;margin:0 0 14px;font-weight:600}
        h3{font-size:15px;margin:0;font-weight:600;overflow-wrap:anywhere}
        section{margin-top:36px}
        .eyebrow{margin:0 0 6px;color:var(--accent);font-size:12px;letter-spacing:.12em;text-transform:uppercase}
        .muted{color:var(--muted)}
        .mono{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
        header{display:flex;flex-wrap:wrap;gap:20px 40px;justify-content:space-between;align-items:flex-end;padding-bottom:22px;border-bottom:1px solid var(--line)}
        .meta{display:flex;flex-wrap:wrap;gap:8px 28px;margin:0}
        .meta dt{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
        .meta dd{margin:0;font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
        .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:24px}
        .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;display:flex;flex-direction:column;gap:2px}
        .card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}
        .card .value{font-size:30px;font-weight:650;line-height:1.15;font-variant-numeric:tabular-nums}
        .card .hint{font-size:12px;color:var(--muted)}
        .card.warn .value{color:var(--high)}
        .card.ok .value{color:var(--ok)}
        .table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
        table{width:100%;border-collapse:collapse;background:var(--panel)}
        th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
        th{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-weight:600;background:var(--panel2)}
        tbody tr:last-child td{border-bottom:0}
        .num{text-align:right;font-variant-numeric:tabular-nums}
        td.hit{color:var(--high);font-weight:600}
        .section-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px}
        .filters{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:14px}
        .filters label{display:flex;flex-direction:column;gap:5px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
        .filters .grow{flex:1 1 220px}
        select,input,button{font:14px var(--sans);color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:8px 10px;min-height:36px}
        input{width:100%}
        button{cursor:pointer;background:var(--panel2)}
        button:hover{border-color:var(--accent)}
        select:focus-visible,input:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
        .finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;padding:16px 18px;margin-bottom:12px}
        .finding.sev-critical{border-left-color:var(--crit)}
        .finding.sev-high{border-left-color:var(--high)}
        .finding.sev-medium{border-left-color:var(--med)}
        .finding.sev-low{border-left-color:var(--low)}
        .finding-head{display:flex;flex-wrap:wrap;justify-content:space-between;gap:10px;align-items:flex-start}
        .badges{display:flex;flex-wrap:wrap;gap:6px}
        .badge{font-size:12px;padding:3px 9px;border-radius:999px;border:1px solid var(--line);white-space:nowrap}
        .sev-critical .badge.sev{color:var(--crit);border-color:var(--crit)}
        .sev-high .badge.sev{color:var(--high);border-color:var(--high)}
        .sev-medium .badge.sev{color:var(--med);border-color:var(--med)}
        .sev-low .badge.sev{color:var(--low);border-color:var(--low)}
        .badge.st-quarantined,.badge.st-terminated,.badge.st-cleaned{color:var(--ok);border-color:var(--ok)}
        .badge.st-failed{color:var(--crit);border-color:var(--crit)}
        .badge.st-planned,.badge.st-blocked{color:var(--accent);border-color:var(--accent)}
        .desc{margin:10px 0 0;color:#c4ceda;max-width:95ch}
        .props{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px 24px;margin:14px 0 0}
        .props dt{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
        .props dd{margin:2px 0 0;overflow-wrap:anywhere}
        details{margin-top:12px;border-top:1px solid var(--line);padding-top:10px}
        summary{cursor:pointer;color:var(--muted);font-size:13px}
        .empty{background:var(--panel);border:1px dashed var(--line);border-radius:10px;padding:22px;color:var(--muted);text-align:center}
        footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
        [hidden]{display:none!important}
        @media print{body{background:#fff;color:#000}.filters{display:none}.card,.finding,table{background:#fff}}

        """;

    private const string Script = """
        (function () {
          var sev = document.getElementById('f-severity');
          var st = document.getElementById('f-status');
          var text = document.getElementById('f-text');
          var reset = document.getElementById('f-reset');
          var counter = document.getElementById('counter');
          var noMatch = document.getElementById('no-match');
          var cards = Array.prototype.slice.call(document.querySelectorAll('.finding'));
          if (!sev || !st) { return; }
          function apply() {
            var q = text.value.trim().toLowerCase();
            var shown = 0;
            cards.forEach(function (c) {
              var ok = (!sev.value || c.dataset.severity === sev.value)
                && (!st.value || c.dataset.status === st.value)
                && (!q || c.textContent.toLowerCase().indexOf(q) !== -1);
              c.hidden = !ok;
              if (ok) { shown++; }
            });
            counter.textContent = 'Показано ' + shown + ' из ' + cards.length;
            noMatch.hidden = shown !== 0;
          }
          sev.addEventListener('change', apply);
          st.addEventListener('change', apply);
          text.addEventListener('input', apply);
          reset.addEventListener('click', function () { sev.value = ''; st.value = ''; text.value = ''; apply(); });
          apply();
        })();

        """;
}
