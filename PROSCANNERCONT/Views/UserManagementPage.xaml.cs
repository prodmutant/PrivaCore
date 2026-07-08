using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using PROSCANNERCONT.Security.Auth;
using PROSCANNERCONT.Services.Siem;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// Admin-only management of console accounts: create/reset/enable/disable/delete users and assign
    /// roles. Reachable only with <see cref="Permission.ManageUsers"/> (nav + NavigateToPage guard);
    /// every action is re-checked and audited here as defence in depth.
    /// </summary>
    public partial class UserManagementPage : Page
    {
        private readonly UserStore _store = UserStore.Instance;
        private bool _suppressRoleSync;

        public UserManagementPage()
        {
            InitializeComponent();
            RoleBox.ItemsSource = Enum.GetValues(typeof(AppRole));
            UsersGrid.SelectionChanged += (_, _) => SyncRoleBox();
            Refresh();
        }

        private void Refresh()
        {
            var selected = Selected()?.Username;
            UsersGrid.ItemsSource = _store.All();
            if (selected != null)
                UsersGrid.SelectedItem = _store.All().FirstOrDefault(u =>
                    string.Equals(u.Username, selected, StringComparison.OrdinalIgnoreCase));
        }

        private AppUser? Selected() => UsersGrid.SelectedItem as AppUser;

        private void SyncRoleBox()
        {
            _suppressRoleSync = true;
            RoleBox.SelectedItem = Selected()?.Role ?? (object?)null;
            _suppressRoleSync = false;
        }

        private bool Guard() => SessionService.Instance.Require(Permission.ManageUsers, "manage users");

        private bool IsLastEnabledAdmin(AppUser u)
            => u.Role == AppRole.Admin && u.Enabled
               && _store.All().Count(x => x.Role == AppRole.Admin && x.Enabled) <= 1;

        private bool IsSelf(AppUser u)
            => string.Equals(u.Username, SessionService.Instance.CurrentUserName, StringComparison.OrdinalIgnoreCase);

        // ── actions ──────────────────────────────────────────────────────────
        private void NewUser_Click(object sender, RoutedEventArgs e)
        {
            if (!Guard()) return;
            var dlg = new UserEditDialog { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() != true) return;
            var created = _store.Create(dlg.Username, dlg.Password, dlg.Role, dlg.DisplayName);
            if (created == null) { Warn($"A user named '{dlg.Username}' already exists."); return; }
            SiemAudit.Instance.Log("Auth", "Create user", $"{created.Username} ({created.Role})");
            Refresh();
        }

        private void ResetPassword_Click(object sender, RoutedEventArgs e)
        {
            if (!Guard()) return;
            var u = Selected();
            if (u == null) { Warn("Select a user first."); return; }
            var dlg = new UserEditDialog(u.Username) { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() != true) return;
            _store.SetPassword(u.Username, dlg.Password);
            SiemAudit.Instance.Log("Auth", "Reset password", u.Username);
            Refresh();
        }

        private void ToggleEnabled_Click(object sender, RoutedEventArgs e)
        {
            if (!Guard()) return;
            var u = Selected();
            if (u == null) { Warn("Select a user first."); return; }
            if (u.Enabled && IsSelf(u)) { Warn("You cannot disable your own account."); return; }
            if (u.Enabled && IsLastEnabledAdmin(u)) { Warn("You cannot disable the last administrator."); return; }

            u.Enabled = !u.Enabled;
            _store.Update(u);
            SiemAudit.Instance.Log("Auth", u.Enabled ? "Enable user" : "Disable user", u.Username);
            Refresh();
        }

        private void Unlock_Click(object sender, RoutedEventArgs e)
        {
            if (!Guard()) return;
            var u = Selected();
            if (u == null) { Warn("Select a user first."); return; }
            u.LockoutUntilUtc = null; u.FailedAttempts = 0;
            _store.Update(u);
            SiemAudit.Instance.Log("Auth", "Unlock user", u.Username);
            Refresh();
        }

        private void Role_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressRoleSync) return;
            var u = Selected();
            if (u == null || RoleBox.SelectedItem is not AppRole role || role == u.Role) return;
            if (!Guard()) { SyncRoleBox(); return; }
            if (u.Role == AppRole.Admin && role != AppRole.Admin && IsLastEnabledAdmin(u))
            {
                Warn("You cannot remove the last administrator's role.");
                SyncRoleBox();
                return;
            }
            u.Role = role;
            _store.Update(u);
            SiemAudit.Instance.Log("Auth", "Change role", $"{u.Username} → {role}");
            Refresh();
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            if (!Guard()) return;
            var u = Selected();
            if (u == null) { Warn("Select a user first."); return; }
            if (IsSelf(u)) { Warn("You cannot delete your own account."); return; }
            if (IsLastEnabledAdmin(u)) { Warn("You cannot delete the last administrator."); return; }
            if (AppDialog.Show($"Delete user '{u.Username}'?", "Delete user",
                    MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

            _store.Remove(u.Username);
            SiemAudit.Instance.Log("Auth", "Delete user", u.Username);
            Refresh();
        }

        private static void Warn(string msg) => AppDialog.Show(msg, "Users & Roles", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
