using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using FontAwesome.Sharp;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;

namespace PROSCANNERCONT.Views
{
    public partial class WidgetPickerWindow : Window
    {
        public List<DashboardWidget> Result { get; private set; }

        private readonly List<DashboardWidget> _widgets;

        // Icon + accent color per widget type
        private static readonly Dictionary<WidgetType, (IconChar Icon, Color Color)> _meta = new()
        {
            [WidgetType.ModuleStatus]    = (IconChar.CircleDot,          Color.FromRgb(33,  150, 243)),
            [WidgetType.RecentFindings]  = (IconChar.ClipboardList,      Color.FromRgb(255, 152, 0)),
            [WidgetType.IDSAlerts]       = (IconChar.TriangleExclamation, Color.FromRgb(244, 67,  54)),
            [WidgetType.TrafficStats]    = (IconChar.Wifi,               Color.FromRgb(156, 39,  176)),
            [WidgetType.TopThreats]      = (IconChar.SkullCrossbones,    Color.FromRgb(244, 67,  54)),
            [WidgetType.SecurityScore]   = (IconChar.ShieldHalved,       Color.FromRgb(0,   188, 212)),
            [WidgetType.NetworkSpeed]    = (IconChar.Gauge,              Color.FromRgb(0,   188, 212)),
            [WidgetType.HostsList]       = (IconChar.Desktop,            Color.FromRgb(76,  175, 80)),
            [WidgetType.ActivityChart]   = (IconChar.ChartBar,           Color.FromRgb(33,  150, 243)),
            [WidgetType.VulnSummary]     = (IconChar.Bug,                Color.FromRgb(156, 39,  176)),
            [WidgetType.QuickActions]    = (IconChar.BoltLightning,      Color.FromRgb(255, 152, 0)),
            [WidgetType.SystemResources] = (IconChar.Server,             Color.FromRgb(0,   188, 212)),
            [WidgetType.OpenPorts]       = (IconChar.NetworkWired,       Color.FromRgb(33,  150, 243)),
            [WidgetType.AlertTrend]      = (IconChar.ChartLine,          Color.FromRgb(244, 67,  54)),
            [WidgetType.HoneypotActivity]= (IconChar.Spider,             Color.FromRgb(233, 30,  99)),
            [WidgetType.CVEExploit]      = (IconChar.Bomb,               Color.FromRgb(244, 67,  54)),
            [WidgetType.AssetChanges]    = (IconChar.ArrowsRotate,       Color.FromRgb(0,  188, 212)),
            [WidgetType.IdsRuleStats]    = (IconChar.Sliders,            Color.FromRgb(33, 150, 243)),
            [WidgetType.LiveTraffic]     = (IconChar.WaveSquare,         Color.FromRgb(76, 175,  80)),
        };

        public WidgetPickerWindow(List<DashboardWidget> current)
        {
            InitializeComponent();
            _widgets = current.Select(w => new DashboardWidget
            {
                Id           = w.Id,
                Type         = w.Type,
                Visible      = w.Visible,
                Order        = w.Order,
                Size         = w.Size,
                CustomWidth  = w.CustomWidth,
                CustomHeight = w.CustomHeight
            }).ToList();

            Loaded += (_, __) => BuildTiles();
        }

        private void BuildTiles()
        {
            TilePanel.Children.Clear();

            foreach (var widget in _widgets.OrderBy(w => w.Order))
            {
                var tile = BuildTile(widget);
                TilePanel.Children.Add(tile);
            }
        }

        private Border BuildTile(DashboardWidget widget)
        {
            _meta.TryGetValue(widget.Type, out var m);
            var accentColor = m.Color != default ? m.Color : Color.FromRgb(100, 100, 100);
            var accentBrush = new SolidColorBrush(accentColor);
            var icon        = m.Icon;

            var tile = new Border
            {
                Tag             = widget,
                Width           = 200,
                Height          = 90,
                Margin          = new Thickness(4),
                CornerRadius    = new CornerRadius(10),
                Cursor          = Cursors.Hand,
                ClipToBounds    = false,
                Effect          = new DropShadowEffect { BlurRadius = 8, ShadowDepth = 1, Opacity = 0.10, Color = Colors.Black }
            };

            ApplyTileStyle(tile, widget, accentBrush, accentColor);

            var content = new Grid();

            // Icon badge (left side)
            var iconBadge = new Border
            {
                Width        = 36, Height   = 36,
                CornerRadius = new CornerRadius(9),
                Background   = new SolidColorBrush(Color.FromArgb(35, accentColor.R, accentColor.G, accentColor.B)),
                Margin       = new Thickness(14, 0, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment   = VerticalAlignment.Center,
                Child = new IconBlock
                {
                    Icon = icon, Width = 16, Height = 16,
                    Foreground = accentBrush,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment   = VerticalAlignment.Center
                }
            };
            content.Children.Add(iconBadge);

            // Name + description (right of icon)
            var textStack = new StackPanel
            {
                Margin              = new Thickness(60, 0, 36, 0),
                VerticalAlignment   = VerticalAlignment.Center
            };
            textStack.Children.Add(new TextBlock
            {
                Text       = DashboardWidget.DisplayName(widget.Type),
                FontSize   = 12, FontWeight = FontWeights.SemiBold,
                Foreground = TextBrush(),
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            textStack.Children.Add(new TextBlock
            {
                Text       = DashboardWidget.Description(widget.Type),
                FontSize   = 10, Opacity = 0.55,
                Foreground = TextBrush(),
                TextWrapping = TextWrapping.Wrap,
                Margin     = new Thickness(0, 3, 0, 0)
            });
            content.Children.Add(textStack);

            // Checkmark (top-right, visible when active)
            var check = new Border
            {
                Width  = 20, Height = 20,
                CornerRadius = new CornerRadius(10),
                Background   = accentBrush,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment   = VerticalAlignment.Top,
                Margin   = new Thickness(0, 8, 8, 0),
                Visibility = widget.Visible ? Visibility.Visible : Visibility.Collapsed,
                Child = new IconBlock
                {
                    Icon = IconChar.Check, Width = 10, Height = 10,
                    Foreground = Brushes.White,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment   = VerticalAlignment.Center
                }
            };
            content.Children.Add(check);

            tile.Child = content;

            tile.MouseLeftButtonDown += (_, __) =>
            {
                widget.Visible = !widget.Visible;
                check.Visibility = widget.Visible ? Visibility.Visible : Visibility.Collapsed;
                ApplyTileStyle(tile, widget, accentBrush, accentColor);
            };

            return tile;
        }

        private static void ApplyTileStyle(Border tile, DashboardWidget widget, Brush accentBrush, Color accentColor)
        {
            var bg     = Application.Current.Resources["SecondaryBackgroundBrush"] as Brush ?? Brushes.DimGray;
            var border = Application.Current.Resources["BorderBrush"]              as Brush ?? Brushes.Gray;

            if (widget.Visible)
            {
                tile.Background      = new SolidColorBrush(Color.FromArgb(15, accentColor.R, accentColor.G, accentColor.B));
                tile.BorderBrush     = accentBrush;
                tile.BorderThickness = new Thickness(2);
                tile.Opacity         = 1.0;
            }
            else
            {
                tile.Background      = bg;
                tile.BorderBrush     = border;
                tile.BorderThickness = new Thickness(1);
                tile.Opacity         = 0.55;
            }
        }

        private static Brush TextBrush() =>
            Application.Current.Resources["TextBrush"] as Brush ?? Brushes.WhiteSmoke;

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed) DragMove();
        }

        private void Done_Click(object sender, RoutedEventArgs e)
        {
            Result = _widgets;
            DialogResult = true;
        }

        private void ResetDefaults_Click(object sender, RoutedEventArgs e)
        {
            var defs = DashboardWidget.Defaults();
            foreach (var w in _widgets)
            {
                var def = defs.FirstOrDefault(d => d.Type == w.Type);
                if (def != null) w.Visible = def.Visible;
            }
            BuildTiles();
        }
    }
}
