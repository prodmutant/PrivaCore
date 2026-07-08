using System;
using System.Windows;
using PROSCANNERCONT.Security.Auth;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// Modal for creating a user (username + display + role + password) or resetting a password.
    /// Validates locally; the caller performs the actual <see cref="UserStore"/> mutation.
    /// </summary>
    public partial class UserEditDialog : Window
    {
        private const int MinPasswordLength = 8;
        private readonly bool _resetOnly;

        public string Username => UsernameBox.Text.Trim();
        public string DisplayName => string.IsNullOrWhiteSpace(DisplayBox.Text) ? Username : DisplayBox.Text.Trim();
        public string Password => PasswordBox.Password;
        public AppRole Role => RoleBox.SelectedItem is AppRole r ? r : AppRole.Viewer;

        /// <summary>Create mode. Pass an existing username to run in reset-password mode.</summary>
        public UserEditDialog(string? resetForUser = null)
        {
            InitializeComponent();
            RoleBox.ItemsSource = Enum.GetValues(typeof(AppRole));
            RoleBox.SelectedItem = AppRole.Analyst;

            _resetOnly = resetForUser != null;
            if (_resetOnly)
            {
                TitleText.Text = $"Reset password — {resetForUser}";
                IdentityFields.Visibility = Visibility.Collapsed;
                OkButton.Content = "Reset password";
            }
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            if (!_resetOnly && Username.Length == 0) { ShowError("Enter a username."); return; }
            if (Password.Length < MinPasswordLength) { ShowError($"Password must be at least {MinPasswordLength} characters."); return; }
            if (Password != ConfirmBox.Password) { ShowError("Passwords do not match."); return; }
            DialogResult = true;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

        private void ShowError(string msg) { ErrorText.Text = msg; ErrorBanner.Visibility = Visibility.Visible; }
    }
}
