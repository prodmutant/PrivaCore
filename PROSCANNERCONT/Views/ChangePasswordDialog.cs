using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace PROSCANNERCONT.Views
{
    public class ChangePasswordDialog : Window
    {
        private readonly PasswordBox _currentPwd = new();
        private readonly PasswordBox _newPwd     = new();
        private readonly PasswordBox _confirmPwd = new();
        private readonly TextBlock   _errorText  = new();

        public ChangePasswordDialog()
        {
            Title = "Change Password";
            Width = 400; Height = 340;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = Brushes.Transparent;
            ResizeMode = ResizeMode.NoResize;

            var bg   = Application.Current.Resources["BackgroundBrush"]          as Brush ?? new SolidColorBrush(Color.FromRgb(26, 26, 26));
            var sec  = Application.Current.Resources["SecondaryBackgroundBrush"] as Brush ?? new SolidColorBrush(Color.FromRgb(37, 37, 38));
            var acc  = Application.Current.Resources["AccentBrush"]              as Brush ?? new SolidColorBrush(Color.FromRgb(0, 122, 204));
            var txt  = Application.Current.Resources["TextBrush"]                as Brush ?? new SolidColorBrush(Color.FromRgb(224, 224, 224));
            var bdr  = Application.Current.Resources["BorderBrush"]              as Brush ?? new SolidColorBrush(Color.FromRgb(62, 62, 66));

            var outer = new Border
            {
                Background = bg, BorderBrush = bdr, BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6)
            };

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(44) });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Title bar
            var titleBar = new Border { Background = sec, CornerRadius = new CornerRadius(6, 6, 0, 0) };
            titleBar.MouseLeftButtonDown += (_, e) => { if (e.LeftButton == MouseButtonState.Pressed) DragMove(); };
            var titleGrid = new Grid { Margin = new Thickness(16, 0, 0, 0) };
            titleGrid.Children.Add(new TextBlock
            {
                Text = "Change Password", Foreground = txt, FontSize = 13, FontWeight = FontWeights.SemiBold,
                FontFamily = new FontFamily("Segoe UI"), VerticalAlignment = VerticalAlignment.Center
            });
            var closeBtn = new Button
            {
                Content = "✕", HorizontalAlignment = HorizontalAlignment.Right,
                Background = Brushes.Transparent, BorderThickness = new Thickness(0),
                Foreground = new SolidColorBrush(Color.FromRgb(100, 100, 100)),
                FontSize = 14, Padding = new Thickness(12, 0, 12, 0), Cursor = Cursors.Hand,
                IsCancel = true
            };
            closeBtn.Click += (_, __) => DialogResult = false;
            titleGrid.Children.Add(closeBtn);
            titleBar.Child = titleGrid;
            Grid.SetRow(titleBar, 0);
            root.Children.Add(titleBar);

            // Fields
            var content = new StackPanel { Margin = new Thickness(24, 16, 24, 16) };
            content.Children.Add(MakeLabel("Current password", txt));
            content.Children.Add(StylePwd(_currentPwd, sec, txt, bdr, acc));
            content.Children.Add(MakeLabel("New password  (min 8 characters)", txt));
            content.Children.Add(StylePwd(_newPwd, sec, txt, bdr, acc));
            content.Children.Add(MakeLabel("Confirm new password", txt));
            content.Children.Add(StylePwd(_confirmPwd, sec, txt, bdr, acc));

            _errorText.Foreground = new SolidColorBrush(Color.FromRgb(244, 71, 71));
            _errorText.FontSize = 11; _errorText.FontFamily = new FontFamily("Segoe UI");
            _errorText.Margin = new Thickness(0, 8, 0, 0); _errorText.Visibility = Visibility.Collapsed;
            content.Children.Add(_errorText);

            Grid.SetRow(content, 1);
            root.Children.Add(content);

            // Footer buttons
            var footer = new Border
            {
                Background = sec, BorderBrush = bdr, BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(20, 10, 20, 12), CornerRadius = new CornerRadius(0, 0, 6, 6)
            };
            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var cancelBtn = MakeButton("Cancel", sec, txt, bdr); cancelBtn.Click += (_, __) => DialogResult = false; cancelBtn.Margin = new Thickness(0, 0, 8, 0);
            var okBtn = MakeButton("Change Password", acc, new SolidColorBrush(Colors.White), Brushes.Transparent); okBtn.Click += OnOk;
            btnRow.Children.Add(cancelBtn); btnRow.Children.Add(okBtn);
            footer.Child = btnRow;
            Grid.SetRow(footer, 2);
            root.Children.Add(footer);

            outer.Child = root;
            Content = outer;
        }

        private static TextBlock MakeLabel(string text, Brush fg) => new TextBlock
        {
            Text = text, Foreground = fg, FontSize = 10, FontWeight = FontWeights.Bold,
            FontFamily = new FontFamily("Segoe UI"), Margin = new Thickness(0, 10, 0, 4),
            Opacity = 0.7
        };

        private static PasswordBox StylePwd(PasswordBox pb, Brush bg, Brush fg, Brush bdr, Brush acc)
        {
            pb.Background = bg; pb.Foreground = fg;
            pb.BorderBrush = bdr; pb.BorderThickness = new Thickness(1);
            pb.Padding = new Thickness(8, 7, 8, 7);
            pb.FontFamily = new FontFamily("Segoe UI");
            return pb;
        }

        private static Button MakeButton(string text, Brush bg, Brush fg, Brush border)
        {
            var b = new Button
            {
                Content = text, Background = bg, Foreground = fg,
                BorderBrush = border, BorderThickness = new Thickness(1),
                Padding = new Thickness(16, 7, 16, 7), Cursor = Cursors.Hand,
                FontFamily = new FontFamily("Segoe UI"), FontSize = 12
            };
            // Use a simple styled template so background/border respect the passed-in brushes
            var t = new ControlTemplate(typeof(Button));
            var f = new FrameworkElementFactory(typeof(Border));
            f.SetValue(Border.BackgroundProperty,        bg);
            f.SetValue(Border.BorderBrushProperty,       border);
            f.SetValue(Border.BorderThicknessProperty,   new Thickness(1));
            f.SetValue(Border.CornerRadiusProperty,      new CornerRadius(4));
            f.SetValue(Border.PaddingProperty,           new Thickness(16, 7, 16, 7));
            var cp = new FrameworkElementFactory(typeof(ContentPresenter));
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            f.AppendChild(cp);
            t.VisualTree = f;
            b.Template = t;
            return b;
        }

        private void OnOk(object sender, RoutedEventArgs e)
        {
            _errorText.Visibility = Visibility.Collapsed;
            if (string.IsNullOrEmpty(_currentPwd.Password)) { ShowError("Current password is required."); return; }
            if (_newPwd.Password.Length < 8)               { ShowError("New password must be at least 8 characters."); return; }
            if (_newPwd.Password != _confirmPwd.Password)  { ShowError("New passwords do not match."); return; }
            DialogResult = true;
        }

        private void ShowError(string msg) { _errorText.Text = msg; _errorText.Visibility = Visibility.Visible; }
    }
}
