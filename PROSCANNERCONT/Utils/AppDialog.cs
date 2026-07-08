using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using FontAwesome.Sharp;

namespace PROSCANNERCONT.Utils
{
    public static class AppDialog
    {
        public static MessageBoxResult Show(string messageBoxText)
            => ShowCore(messageBoxText, string.Empty, MessageBoxButton.OK, MessageBoxImage.None);

        public static MessageBoxResult Show(string messageBoxText, string caption)
            => ShowCore(messageBoxText, caption, MessageBoxButton.OK, MessageBoxImage.None);

        public static MessageBoxResult Show(string messageBoxText, string caption,
            MessageBoxButton button)
            => ShowCore(messageBoxText, caption, button, MessageBoxImage.None);

        public static MessageBoxResult Show(string messageBoxText, string caption,
            MessageBoxButton button, MessageBoxImage icon)
            => ShowCore(messageBoxText, caption, button, icon);

        private static MessageBoxResult ShowCore(string message, string title,
            MessageBoxButton buttons, MessageBoxImage icon)
        {
            if (Application.Current?.Dispatcher.CheckAccess() == false)
                return Application.Current.Dispatcher.Invoke(
                    () => ShowCore(message, title, buttons, icon));

            // Simple OK notifications → non-blocking toast (no dialog needed)
            if (buttons == MessageBoxButton.OK &&
                (icon == MessageBoxImage.Information || icon == MessageBoxImage.None))
            {
                var toastType = icon == MessageBoxImage.Information
                    ? NotificationType.Info
                    : NotificationType.Info;
                var hex = ColorHex(icon == MessageBoxImage.Information ? "AccentBrush" : "AccentBrush");
                AlertToast.Show(string.IsNullOrEmpty(title) ? "Notice" : title, message, hex);
                return MessageBoxResult.OK;
            }

            var dlg = new ThemedDialogWindow(title, message, buttons, icon);
            dlg.ShowDialog();
            return dlg.Result;
        }

        private static string ColorHex(string resourceKey)
        {
            if (Application.Current?.Resources[resourceKey] is System.Windows.Media.SolidColorBrush b)
                return $"#{b.Color.R:X2}{b.Color.G:X2}{b.Color.B:X2}";
            return "#58A6FF";
        }
    }

    internal class ThemedDialogWindow : Window
    {
        public MessageBoxResult Result { get; private set; } = MessageBoxResult.None;

        private static SolidColorBrush Br(string key) =>
            Application.Current?.Resources[key] as SolidColorBrush
            ?? new SolidColorBrush(Colors.Gray);

        private static FontFamily Font() =>
            Application.Current?.Resources["PrimaryFont"] as FontFamily
            ?? new FontFamily("Segoe UI");

        private static double Sz(string key) =>
            Application.Current?.Resources[key] is double d ? d : 13.0;

        private static CornerRadius Cr(string key) =>
            Application.Current?.Resources[key] is CornerRadius cr ? cr : new CornerRadius(6);

        public ThemedDialogWindow(string title, string message,
            MessageBoxButton buttons, MessageBoxImage icon)
        {
            WindowStyle           = WindowStyle.None;
            AllowsTransparency    = true;
            Background            = Brushes.Transparent;
            ResizeMode            = ResizeMode.NoResize;
            SizeToContent         = SizeToContent.Height;
            Width                 = 420;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            ShowInTaskbar         = true;
            Title                 = "PrivaCore";

            var font     = Font();
            var fsNormal = Sz("FontSizeNormal");
            var fsSmall  = Sz("FontSizeSmall");
            var crLarge  = Cr("CornerRadiusLarge");
            var crNormal = Cr("CornerRadiusNormal");

            var (iconChar, accentKey) = icon switch
            {
                MessageBoxImage.Error       => (IconChar.CircleXmark,        "CriticalBrush"),
                MessageBoxImage.Warning     => (IconChar.TriangleExclamation, "WarningBrush"),
                MessageBoxImage.Question    => (IconChar.CircleQuestion,      "AccentBrush"),
                MessageBoxImage.Information => (IconChar.CircleInfo,          "AccentBrush"),
                _                           => (IconChar.None,                "AccentBrush")
            };

            var accentBrush = Br(accentKey);
            var accentGlow  = new SolidColorBrush(
                Color.FromArgb(30, accentBrush.Color.R, accentBrush.Color.G, accentBrush.Color.B));

            // ── outer shadow wrapper ──────────────────────────────────────────
            var shadow = new Border
            {
                Margin = new Thickness(14),
                Effect = new DropShadowEffect
                {
                    Color       = Colors.Black,
                    BlurRadius  = 32,
                    ShadowDepth = 6,
                    Opacity     = 0.55
                }
            };

            // ── card ──────────────────────────────────────────────────────────
            var card = new Border
            {
                Background      = Br("SecondaryBackgroundBrush"),
                BorderBrush     = Br("BorderBrush"),
                BorderThickness = new Thickness(1),
                CornerRadius    = crLarge,
                ClipToBounds    = true
            };

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // title bar
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // content
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1) }); // divider
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // buttons

            // ── title bar (draggable, no close button — use Escape to dismiss) ──
            var titleBar = new Border
            {
                Background      = Br("BackgroundBrush"),
                BorderBrush     = Br("BorderBrush"),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding         = new Thickness(16, 0, 16, 0),
                Height          = 42,
                Cursor          = Cursors.SizeAll
            };
            titleBar.MouseLeftButtonDown += (_, e) =>
            {
                if (e.ButtonState == MouseButtonState.Pressed) DragMove();
            };
            Grid.SetRow(titleBar, 0);

            var tbGrid = new Grid();
            tbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            tbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left: branding
            var brand = new StackPanel
            {
                Orientation       = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };
            brand.Children.Add(new Border
            {
                Width        = 20,
                Height       = 20,
                CornerRadius = new CornerRadius(4),
                Background   = Br("AccentBrush"),
                Margin       = new Thickness(0, 0, 7, 0),
                Child        = new IconBlock
                {
                    Icon                = IconChar.Shield,
                    Foreground          = Brushes.White,
                    FontSize            = 9,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment   = VerticalAlignment.Center
                }
            });
            brand.Children.Add(new TextBlock
            {
                Text              = "Priva",
                Foreground        = Br("AccentBrush"),
                FontFamily        = font,
                FontSize          = 12,
                FontWeight        = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            });
            brand.Children.Add(new TextBlock
            {
                Text              = "Core",
                Foreground        = Br("TextBrush"),
                FontFamily        = font,
                FontSize          = 12,
                FontWeight        = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            });
            Grid.SetColumn(brand, 0);
            tbGrid.Children.Add(brand);

            // Right: dialog title (subtle)
            var titleLabel = new TextBlock
            {
                Text                = string.IsNullOrEmpty(title) ? string.Empty : title,
                Foreground          = Br("SubtleTextBrush"),
                FontFamily          = font,
                FontSize            = fsSmall,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment   = VerticalAlignment.Center,
                TextTrimming        = TextTrimming.CharacterEllipsis
            };
            Grid.SetColumn(titleLabel, 1);
            tbGrid.Children.Add(titleLabel);

            titleBar.Child = tbGrid;
            root.Children.Add(titleBar);

            // ── content: icon + message ───────────────────────────────────────
            var contentBorder = new Border { Padding = new Thickness(20, 20, 20, 20) };
            Grid.SetRow(contentBorder, 1);

            var contentRow = new StackPanel { Orientation = Orientation.Horizontal };

            if (iconChar != IconChar.None)
            {
                contentRow.Children.Add(new Border
                {
                    Width             = 42,
                    Height            = 42,
                    CornerRadius      = crNormal,
                    Background        = accentGlow,
                    Margin            = new Thickness(0, 1, 16, 0),
                    VerticalAlignment = VerticalAlignment.Top,
                    Child             = new IconBlock
                    {
                        Icon                = iconChar,
                        Foreground          = accentBrush,
                        FontSize            = 19,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment   = VerticalAlignment.Center
                    }
                });
            }

            contentRow.Children.Add(new TextBlock
            {
                Text              = message,
                Foreground        = Br("TextBrush"),
                FontFamily        = font,
                FontSize          = fsNormal,
                TextWrapping      = TextWrapping.Wrap,
                MaxWidth          = iconChar != IconChar.None ? 298 : 358,
                LineHeight        = fsNormal * 1.65,
                VerticalAlignment = VerticalAlignment.Center
            });

            contentBorder.Child = contentRow;
            root.Children.Add(contentBorder);

            // ── divider ───────────────────────────────────────────────────────
            var divider = new Border { Background = Br("BorderBrush"), Opacity = 0.5 };
            Grid.SetRow(divider, 2);
            root.Children.Add(divider);

            // ── button row ────────────────────────────────────────────────────
            var btnRow = new Border { Padding = new Thickness(16, 12, 16, 14) };
            Grid.SetRow(btnRow, 3);

            var btnPanel = new StackPanel
            {
                Orientation         = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            Border MakeBtn(string text, bool isPrimary, MessageBoxResult res)
            {
                var bg = isPrimary ? accentBrush : Br("HoverBrush");
                var fg = isPrimary ? (Brush)Brushes.White : Br("TextBrush");
                var bd = isPrimary ? (Brush)accentBrush   : Br("BorderBrush");

                var btn = new Border
                {
                    Background      = bg,
                    BorderBrush     = bd,
                    BorderThickness = new Thickness(1),
                    CornerRadius    = crNormal,
                    Width           = 82,
                    Height          = 34,
                    Cursor          = Cursors.Hand,
                    Margin          = new Thickness(8, 0, 0, 0),
                    Child           = new TextBlock
                    {
                        Text                = text,
                        Foreground          = fg,
                        FontFamily          = font,
                        FontSize            = fsNormal,
                        FontWeight          = FontWeights.SemiBold,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment   = VerticalAlignment.Center
                    }
                };

                var resultCopy = res;
                btn.MouseLeftButtonUp += (_, __) => { Result = resultCopy; Close(); };
                btn.MouseEnter += (_, __) => btn.Opacity = 0.82;
                btn.MouseLeave += (_, __) => btn.Opacity = 1.0;
                return btn;
            }

            switch (buttons)
            {
                case MessageBoxButton.OK:
                    Result = MessageBoxResult.OK;
                    btnPanel.Children.Add(MakeBtn("OK", true, MessageBoxResult.OK));
                    break;
                case MessageBoxButton.OKCancel:
                    Result = MessageBoxResult.Cancel;
                    btnPanel.Children.Add(MakeBtn("Cancel", false, MessageBoxResult.Cancel));
                    btnPanel.Children.Add(MakeBtn("OK",     true,  MessageBoxResult.OK));
                    break;
                case MessageBoxButton.YesNo:
                    Result = MessageBoxResult.No;
                    btnPanel.Children.Add(MakeBtn("No",  false, MessageBoxResult.No));
                    btnPanel.Children.Add(MakeBtn("Yes", true,  MessageBoxResult.Yes));
                    break;
                case MessageBoxButton.YesNoCancel:
                    Result = MessageBoxResult.Cancel;
                    btnPanel.Children.Add(MakeBtn("Cancel", false, MessageBoxResult.Cancel));
                    btnPanel.Children.Add(MakeBtn("No",     false, MessageBoxResult.No));
                    btnPanel.Children.Add(MakeBtn("Yes",    true,  MessageBoxResult.Yes));
                    break;
            }

            btnRow.Child = btnPanel;
            root.Children.Add(btnRow);

            card.Child   = root;
            shadow.Child = card;
            Content      = shadow;

            KeyDown += (_, e) =>
            {
                if (e.Key == Key.Escape) Close();
                else if (e.Key == Key.Return && buttons == MessageBoxButton.OK)
                { Result = MessageBoxResult.OK; Close(); }
            };
        }
    }
}
