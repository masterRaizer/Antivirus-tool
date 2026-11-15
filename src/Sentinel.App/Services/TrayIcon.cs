using System.Runtime.InteropServices;
using Forms = System.Windows.Forms;
using Gdi = System.Drawing;

namespace Sentinel.App.Services;

/// <summary>
/// Значок в системном трее с контекстным меню: «Открыть Sentinel», «Быстрая проверка»,
/// «Защита в реальном времени», «Выход». Значок-щит рисуется программно — файл ресурса не нужен.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _realtimeItem;
    private readonly Gdi.Icon _protectedIcon;
    private readonly Gdi.Icon _pausedIcon;
    private bool _suppressToggle;

    public TrayIcon()
    {
        _protectedIcon = DrawShield(Gdi.Color.FromArgb(0x3F, 0xB9, 0x50));
        _pausedIcon = DrawShield(Gdi.Color.FromArgb(0xD2, 0x99, 0x22));

        var open = new Forms.ToolStripMenuItem("Открыть Sentinel") { Font = new Gdi.Font(Forms.Control.DefaultFont, Gdi.FontStyle.Bold) };
        open.Click += (_, _) => OpenRequested?.Invoke();
        var quick = new Forms.ToolStripMenuItem("Быстрая проверка");
        quick.Click += (_, _) => QuickScanRequested?.Invoke();
        _realtimeItem = new Forms.ToolStripMenuItem("Защита в реальном времени") { CheckOnClick = true, Checked = true };
        _realtimeItem.CheckedChanged += (_, _) =>
        {
            if (!_suppressToggle)
            {
                RealtimeToggled?.Invoke(_realtimeItem.Checked);
            }
        };
        var exit = new Forms.ToolStripMenuItem("Выход");
        exit.Click += (_, _) => ExitRequested?.Invoke();

        var menu = new Forms.ContextMenuStrip
        {
            Renderer = new Forms.ToolStripProfessionalRenderer(new DarkColors()) { RoundedEdges = false },
            ForeColor = Gdi.Color.FromArgb(0xE6, 0xED, 0xF3),
            BackColor = Gdi.Color.FromArgb(0x16, 0x1B, 0x22),
            ShowImageMargin = false,
            ShowCheckMargin = true,
        };
        menu.Items.AddRange([open, quick, new Forms.ToolStripSeparator(), _realtimeItem, new Forms.ToolStripSeparator(), exit]);

        _icon = new Forms.NotifyIcon
        {
            Icon = _protectedIcon,
            Text = "Sentinel — защита активна",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left)
            {
                OpenRequested?.Invoke();
            }
        };
        _icon.BalloonTipClicked += (_, _) => OpenRequested?.Invoke();
    }

    public event Action? OpenRequested;

    public event Action? QuickScanRequested;

    public event Action<bool>? RealtimeToggled;

    public event Action? ExitRequested;

    /// <summary>Отражает состояние защиты в значке, подсказке и пункте меню.</summary>
    public void SetProtection(bool enabled, int pendingDecisions)
    {
        _suppressToggle = true;
        _realtimeItem.Checked = enabled;
        _suppressToggle = false;
        _icon.Icon = enabled ? _protectedIcon : _pausedIcon;
        var text = enabled ? "Sentinel — защита активна" : "Sentinel — защита приостановлена";
        _icon.Text = pendingDecisions > 0 ? $"{text}\nЖдут решения: {pendingDecisions}" : text;
    }

    /// <summary>Всплывающее уведомление Windows (об автоматически нейтрализованной угрозе).</summary>
    public void Notify(string title, string text, bool warning)
    {
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = text.Length > 250 ? text[..250] + "…" : text;
        _icon.BalloonTipIcon = warning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info;
        _icon.ShowBalloonTip(5000);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.ContextMenuStrip?.Dispose();
        _icon.Dispose();
        DestroyIcon(_protectedIcon.Handle);
        DestroyIcon(_pausedIcon.Handle);
        _protectedIcon.Dispose();
        _pausedIcon.Dispose();
    }

    private static Gdi.Icon DrawShield(Gdi.Color color)
    {
        using var bitmap = new Gdi.Bitmap(32, 32, Gdi.Imaging.PixelFormat.Format32bppArgb);
        using (var g = Gdi.Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = Gdi.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Gdi.Color.Transparent);
            using var path = new Gdi.Drawing2D.GraphicsPath();
            path.AddLines(
            [
                new Gdi.PointF(16, 2), new Gdi.PointF(28, 6.5f), new Gdi.PointF(28, 15),
                new Gdi.PointF(24.5f, 23), new Gdi.PointF(16, 30), new Gdi.PointF(7.5f, 23),
                new Gdi.PointF(4, 15), new Gdi.PointF(4, 6.5f),
            ]);
            path.CloseFigure();
            using var fill = new Gdi.SolidBrush(color);
            g.FillPath(fill, path);
            using var pen = new Gdi.Pen(Gdi.Color.FromArgb(0x0F, 0x11, 0x17), 3f)
            {
                StartCap = Gdi.Drawing2D.LineCap.Round,
                EndCap = Gdi.Drawing2D.LineCap.Round,
                LineJoin = Gdi.Drawing2D.LineJoin.Round,
            };
            g.DrawLines(pen, [new Gdi.PointF(10.5f, 16), new Gdi.PointF(14.5f, 20), new Gdi.PointF(21.5f, 11.5f)]);
        }

        return Gdi.Icon.FromHandle(bitmap.GetHicon());
    }

    [DllImport("user32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);

    /// <summary>Тёмные цвета контекстного меню — в тон основному окну.</summary>
    private sealed class DarkColors : Forms.ProfessionalColorTable
    {
        private static readonly Gdi.Color Surface = Gdi.Color.FromArgb(0x16, 0x1B, 0x22);
        private static readonly Gdi.Color Hover = Gdi.Color.FromArgb(0x22, 0x2A, 0x37);
        private static readonly Gdi.Color Border = Gdi.Color.FromArgb(0x26, 0x2D, 0x3A);

        public override Gdi.Color ToolStripDropDownBackground => Surface;

        public override Gdi.Color ImageMarginGradientBegin => Surface;

        public override Gdi.Color ImageMarginGradientMiddle => Surface;

        public override Gdi.Color ImageMarginGradientEnd => Surface;

        public override Gdi.Color MenuBorder => Border;

        public override Gdi.Color MenuItemBorder => Hover;

        public override Gdi.Color MenuItemSelected => Hover;

        public override Gdi.Color MenuItemSelectedGradientBegin => Hover;

        public override Gdi.Color MenuItemSelectedGradientEnd => Hover;

        public override Gdi.Color SeparatorDark => Border;

        public override Gdi.Color SeparatorLight => Border;

        public override Gdi.Color CheckBackground => Hover;

        public override Gdi.Color CheckSelectedBackground => Hover;

        public override Gdi.Color CheckPressedBackground => Hover;
    }
}
