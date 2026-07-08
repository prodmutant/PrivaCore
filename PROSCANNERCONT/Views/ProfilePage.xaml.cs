using System;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using PROSCANNERCONT.Security.Auth;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// Shows the currently signed-in console account (from <see cref="SessionService"/>). Lets the user
    /// edit their display name, change their password securely (verified + persisted via <see cref="UserStore"/>),
    /// and sign out. No fake stats, licence tiers, or placeholder data.
    /// </summary>
    public partial class ProfilePage : Page
    {
        private AppUser? _user;

        public ProfilePage()
        {
            InitializeComponent();
            LoadUser();
        }

        private void LoadUser()
        {
            _user = SessionService.Instance.Current;
            if (_user == null) return;

            AvatarInitials.Text   = Initials(_user.DisplayName, _user.Username);
            DisplayNameText.Text  = string.IsNullOrWhiteSpace(_user.DisplayName) ? _user.Username : _user.DisplayName;
            UsernameSubtitle.Text = "@" + _user.Username;
            UsernameValue.Text    = _user.Username;
            DisplayNameBox.Text   = _user.DisplayName;
            RoleText.Text         = RoleLabel(_user.Role);
            RoleValue.Text        = RoleLabel(_user.Role);
            CreatedValue.Text     = _user.CreatedUtc.ToLocalTime().ToString("MMM dd, yyyy");
            LastLoginValue.Text   = _user.LastLoginUtc.HasValue
                ? _user.LastLoginUtc.Value.ToLocalTime().ToString("MMM dd, yyyy - HH:mm")
                : "This is your first sign-in";
        }

        private static string RoleLabel(AppRole role) => role switch
        {
            AppRole.Admin         => "Administrator",
            AppRole.SeniorAnalyst => "Senior Analyst",
            AppRole.Analyst       => "Analyst",
            _                     => "Viewer",
        };

        private static string Initials(string? displayName, string username)
        {
            var source = string.IsNullOrWhiteSpace(displayName) ? username : displayName;
            if (string.IsNullOrWhiteSpace(source)) return "?";
            var parts = source.Split(new[] { ' ', '-', '_', '.' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return "?";
            if (parts.Length == 1) return parts[0].Substring(0, 1).ToUpperInvariant();
            return (parts[0].Substring(0, 1) + parts[^1].Substring(0, 1)).ToUpperInvariant();
        }

        private void SaveName_Click(object sender, RoutedEventArgs e)
        {
            if (_user == null) return;

            var newName = (DisplayNameBox.Text ?? "").Trim();
            if (newName.Length == 0) { DisplayNameBox.Text = _user.DisplayName; return; }
            if (newName == _user.DisplayName) return;

            _user.DisplayName = newName;
            UserStore.Instance.Update(_user);

            // Reflect the change in this page and the nav bar's profile chip.
            DisplayNameText.Text = newName;
            AvatarInitials.Text  = Initials(newName, _user.Username);
            if (Application.Current.MainWindow is MainWindow mw)
                mw.RefreshProfileChip();

            AppDialog.Show("Display name updated.", "Saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ChangePassword_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new ChangePasswordDialog { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() == true)
                AppDialog.Show("Your password has been changed.", "Password updated",
                               MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void SignOut_Click(object sender, RoutedEventArgs e)
        {
            var result = AppDialog.Show("Sign out of PrivaCore? You'll need to log in again.", "Sign out",
                                        MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result != MessageBoxResult.Yes) return;

            SessionService.Instance.SignOut();

            // Relaunch to return to the login screen; fall back to a clean shutdown.
            try
            {
                var exe = Environment.ProcessPath;
                if (!string.IsNullOrEmpty(exe))
                    Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
            }
            catch { /* best effort */ }
            Application.Current.Shutdown();
        }
    }
}
