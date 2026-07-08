using System.Windows;
using System.Windows.Input;
using PROSCANNERCONT.Security.Auth;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// The console sign-in gate. One window, three modes: first-run admin creation (when the user
    /// store is empty), normal login, and a forced change-password step. On success,
    /// <see cref="AuthenticatedUser"/> is set and <c>DialogResult</c> is true.
    /// </summary>
    public partial class LoginWindow : Window
    {
        private const int MinPasswordLength = 8;

        private enum Mode { Login, FirstRun, ChangePassword }
        private Mode _mode;
        private AppUser? _pendingChange;   // user mid forced-password-change

        private readonly UserStore _store;
        private readonly IIdentityProvider _provider;

        /// <summary>The signed-in user, once authentication succeeds.</summary>
        public AppUser? AuthenticatedUser { get; private set; }

        public LoginWindow(UserStore? store = null, IIdentityProvider? provider = null)
        {
            InitializeComponent();
            _store = store ?? UserStore.Instance;
            _provider = provider ?? new LocalIdentityProvider(_store);

            _mode = _store.IsEmpty ? Mode.FirstRun : Mode.Login;
            UsernameBox.Text = SessionService.Instance.LastUsername ?? "";
            ApplyMode();

            Loaded += (_, _) =>
            {
                if (UsernameBox.Text.Length == 0 && _mode != Mode.ChangePassword) UsernameBox.Focus();
                else PasswordBox.Focus();
            };
            PreviewKeyDown += (_, e) => { if (e.Key == Key.Enter) Primary_Click(this, new RoutedEventArgs()); };
        }

        private void ApplyMode()
        {
            ClearError();
            switch (_mode)
            {
                case Mode.FirstRun:
                    TitleText.Text = "Create administrator";
                    SubtitleText.Text = "Set up the first PrivaCore account.";
                    UserLabel.Text = "Username";
                    PasswordLabel.Text = "Password";
                    ConfirmPanel.Visibility = Visibility.Visible;
                    UserLabel.Visibility = UsernameBox.Visibility = Visibility.Visible;
                    PrimaryButton.Content = "Create account";
                    HintText.Text = "This account has full control (Admin). Password must be at least "
                                    + MinPasswordLength + " characters.";
                    break;

                case Mode.ChangePassword:
                    TitleText.Text = "Set a new password";
                    SubtitleText.Text = "Your password must be changed before continuing.";
                    PasswordLabel.Text = "New password";
                    ConfirmPanel.Visibility = Visibility.Visible;
                    UserLabel.Visibility = UsernameBox.Visibility = Visibility.Collapsed;
                    PrimaryButton.Content = "Save & continue";
                    HintText.Text = "Choose a password of at least " + MinPasswordLength + " characters.";
                    PasswordBox.Clear(); ConfirmBox.Clear();
                    break;

                default: // Login
                    TitleText.Text = "Welcome back";
                    SubtitleText.Text = "Sign in to your PrivaCore console.";
                    UserLabel.Text = "Username";
                    PasswordLabel.Text = "Password";
                    ConfirmPanel.Visibility = Visibility.Collapsed;
                    UserLabel.Visibility = UsernameBox.Visibility = Visibility.Visible;
                    PrimaryButton.Content = "Sign in";
                    HintText.Text = "";
                    break;
            }
        }

        private void Primary_Click(object sender, RoutedEventArgs e)
        {
            switch (_mode)
            {
                case Mode.FirstRun: DoFirstRun(); break;
                case Mode.ChangePassword: DoChangePassword(); break;
                default: DoLogin(); break;
            }
        }

        private void DoLogin()
        {
            var user = UsernameBox.Text.Trim();
            var pass = PasswordBox.Password;
            if (user.Length == 0 || pass.Length == 0) { ShowError("Enter your username and password."); return; }

            var result = _provider.Authenticate(user, pass);
            if (!result.Ok || result.User == null) { ShowError(result.Message ?? "Sign-in failed."); return; }

            if (result.User.MustChangePassword)
            {
                _pendingChange = result.User;
                _mode = Mode.ChangePassword;
                ApplyMode();
                return;
            }

            AuthenticatedUser = result.User;
            DialogResult = true;
        }

        private void DoFirstRun()
        {
            var user = UsernameBox.Text.Trim();
            var pass = PasswordBox.Password;
            if (user.Length == 0) { ShowError("Enter a username for the admin account."); return; }
            if (pass.Length < MinPasswordLength) { ShowError($"Password must be at least {MinPasswordLength} characters."); return; }
            if (pass != ConfirmBox.Password) { ShowError("Passwords do not match."); return; }

            var created = _store.Create(user, pass, AppRole.Admin, displayName: user, mustChangePassword: false);
            if (created == null) { ShowError("Could not create the account."); return; }

            AuthenticatedUser = created;
            DialogResult = true;
        }

        private void DoChangePassword()
        {
            if (_pendingChange == null) { _mode = Mode.Login; ApplyMode(); return; }
            var pass = PasswordBox.Password;
            if (pass.Length < MinPasswordLength) { ShowError($"Password must be at least {MinPasswordLength} characters."); return; }
            if (pass != ConfirmBox.Password) { ShowError("Passwords do not match."); return; }

            _store.SetPassword(_pendingChange.Username, pass);
            AuthenticatedUser = _store.Get(_pendingChange.Username);
            DialogResult = true;
        }

        private void ShowError(string msg) { ErrorText.Text = msg; ErrorBanner.Visibility = Visibility.Visible; }
        private void ClearError() { ErrorBanner.Visibility = Visibility.Collapsed; ErrorText.Text = ""; }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed) DragMove();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            // Cancelling the gate (or first-run) means the console does not open.
            DialogResult = false;
        }
    }
}
