using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// A themed modal to change a module's operator credentials (username + password). Built in code
    /// so it links into the standalone module apps (IDS / SIEM). Returns the new username/password.
    /// </summary>
    public sealed class ModuleCredentialsDialog : Window
    {
        private readonly TextBox _user = new();
        private readonly PasswordBox _pass = new();
        private readonly PasswordBox _pass2 = new();
        private readonly TextBlock _err = new();

        public string Username { get; private set; } = "";
        public string Password { get; private set; } = "";

        private ModuleCredentialsDialog(Window? owner, string currentUser)
        {
            if (owner != null) Owner = owner;
            Title = "Change credentials";
            Width = 440; SizeToContent = SizeToContent.Height;
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.ToolWindow;
            ResizeMode = ResizeMode.NoResize;
            Background = (Brush)FindResource("BackgroundBrush");

            var root = new StackPanel { Margin = new Thickness(22) };
            root.Children.Add(new TextBlock
            {
                Text = "Set the username and password operators use to connect to this module.",
                FontSize = 12, Foreground = (Brush)FindResource("SubtleTextBrush"),
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4),
            });

            root.Children.Add(Label("USERNAME"));
            _user.Style = (Style)FindResource("InputBoxStyle");
            _user.Text = currentUser;
            root.Children.Add(_user);

            root.Children.Add(Label("NEW PASSWORD"));
            _pass.Style = (Style)FindResource("PasswordBoxStyle");
            root.Children.Add(_pass);

            root.Children.Add(Label("CONFIRM PASSWORD"));
            _pass2.Style = (Style)FindResource("PasswordBoxStyle");
            root.Children.Add(_pass2);

            _err.Foreground = (Brush)FindResource("CriticalBrush");
            _err.FontSize = 11; _err.Margin = new Thickness(0, 10, 0, 0);
            _err.TextWrapping = TextWrapping.Wrap; _err.Visibility = Visibility.Collapsed;
            root.Children.Add(_err);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
            var cancel = new Button { Content = "Cancel", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 90 };
            cancel.Click += (_, _) => { DialogResult = false; };
            var ok = new Button { Content = "Save", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 110 };
            ok.Click += Ok_Click;
            buttons.Children.Add(cancel); buttons.Children.Add(ok);
            root.Children.Add(buttons);

            Content = root;
            Loaded += (_, _) => _pass.Focus();
        }

        private TextBlock Label(string text) => new()
        {
            Text = text, FontSize = 10, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 12, 0, 4),
        };

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            if (_user.Text.Trim().Length == 0) { Err("Enter a username."); return; }
            if (_pass.Password.Length < 4) { Err("Password must be at least 4 characters."); return; }
            if (_pass.Password != _pass2.Password) { Err("Passwords do not match."); return; }
            Username = _user.Text.Trim();
            Password = _pass.Password;
            DialogResult = true;
        }

        private void Err(string msg) { _err.Text = msg; _err.Visibility = Visibility.Visible; }

        /// <summary>Show the dialog. Returns (username, password) on save, or null if cancelled.</summary>
        public static (string user, string pass)? Show(Window? owner, string currentUser)
        {
            var dlg = new ModuleCredentialsDialog(owner, currentUser);
            return dlg.ShowDialog() == true ? (dlg.Username, dlg.Password) : null;
        }
    }
}
