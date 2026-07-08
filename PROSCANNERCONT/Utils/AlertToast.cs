using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Threading;

namespace PROSCANNERCONT.Utils
{
    public static class AlertToast
    {
        public static void Show(string title, string message, string hexColor)
        {
            var type = hexColor.Contains("F85149") || hexColor.Contains("f85149") || hexColor.Contains("F44747") ? NotificationType.Error
                     : hexColor.Contains("E3B341") || hexColor.Contains("e3b341") || hexColor.Contains("FF8C00") || hexColor.Contains("FFA500") ? NotificationType.Warning
                     : hexColor.Contains("56D364") || hexColor.Contains("56d364") ? NotificationType.Success
                     : NotificationType.Info;

            NotificationService.Add(title, message, type);

            Application.Current?.Dispatcher.InvokeAsync(() =>
            {
                var mainWindow = Application.Current?.MainWindow;
                var container  = mainWindow?.FindName("ToastContainer") as ItemsControl;
                if (container == null) return;

                Color accent;
                try   { accent = (Color)ColorConverter.ConvertFromString(hexColor); }
                catch { accent = Color.FromRgb(88, 166, 255); }

                var toast = BuildToast(title, message, accent);
                container.Items.Add(toast);

                // Fade in
                toast.Opacity = 0;
                toast.BeginAnimation(UIElement.OpacityProperty,
                    new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));

                void Dismiss()
                {
                    var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(300));
                    fadeOut.Completed += (_, __) => container.Items.Remove(toast);
                    toast.BeginAnimation(UIElement.OpacityProperty, fadeOut);
                }

                var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
                timer.Tick += (_, __) => { timer.Stop(); Dismiss(); };
                timer.Start();

                toast.MouseLeftButtonDown += (_, __) => { timer.Stop(); Dismiss(); };
            });
        }

        // ── Convenience helpers ──────────────────────────────────────────────

        public static void Info(string title, string message)    => Show(title, message, BrushHex("AccentBrush",   "#58A6FF"));
        public static void Success(string title, string message) => Show(title, message, BrushHex("SuccessBrush",  "#56D364"));
        public static void Warn(string title, string message)    => Show(title, message, BrushHex("WarningBrush",  "#E3B341"));
        public static void Error(string title, string message)   => Show(title, message, BrushHex("CriticalBrush", "#F85149"));

        // ── Toast builder ────────────────────────────────────────────────────

        private static Border BuildToast(string title, string message, Color accent)
        {
            SolidColorBrush Br(string key) =>
                Application.Current?.Resources[key] as SolidColorBrush
                ?? new SolidColorBrush(Colors.Gray);

            FontFamily font =
                Application.Current?.Resources["PrimaryFont"] as FontFamily
                ?? new FontFamily("Segoe UI");

            CornerRadius cr =
                Application.Current?.Resources["CornerRadiusNormal"] is CornerRadius c ? c : new CornerRadius(6);

            var accentBrush = new SolidColorBrush(accent);

            var outer = new Border
            {
                Width           = 340,
                Margin          = new Thickness(0, 6, 0, 0),
                Cursor          = System.Windows.Input.Cursors.Hand,
                Effect          = new DropShadowEffect
                {
                    Color       = Colors.Black,
                    BlurRadius  = 16,
                    ShadowDepth = 3,
                    Opacity     = 0.45
                }
            };

            var card = new Border
            {
                Background      = Br("SecondaryBackgroundBrush"),
                BorderBrush     = new SolidColorBrush(
                    Color.FromArgb(80, accent.R, accent.G, accent.B)),
                BorderThickness = new Thickness(1),
                CornerRadius    = cr,
                ClipToBounds    = true
            };

            var row = new Grid();
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left accent bar
            var bar = new Border
            {
                Background = accentBrush
            };
            Grid.SetColumn(bar, 0);
            row.Children.Add(bar);

            // Content
            var content = new StackPanel
            {
                Margin = new Thickness(12, 10, 12, 10)
            };
            content.Children.Add(new TextBlock
            {
                Text       = title,
                Foreground = accentBrush,
                FontFamily = font,
                FontSize   = 12,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            content.Children.Add(new TextBlock
            {
                Text         = message,
                Foreground   = Br("SubtleTextBrush"),
                FontFamily   = font,
                FontSize     = 11,
                Margin       = new Thickness(0, 3, 0, 0),
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth     = 290
            });
            Grid.SetColumn(content, 1);
            row.Children.Add(content);

            card.Child  = row;
            outer.Child = card;

            // Hover: subtle background lift
            outer.MouseEnter += (_, __) => card.Opacity = 0.85;
            outer.MouseLeave += (_, __) => card.Opacity = 1.0;

            return outer;
        }

        private static string BrushHex(string key, string fallback)
        {
            if (Application.Current?.Resources[key] is SolidColorBrush b)
                return $"#{b.Color.R:X2}{b.Color.G:X2}{b.Color.B:X2}";
            return fallback;
        }
    }
}
