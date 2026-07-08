using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Views;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT
{
    /// <summary>
    /// IDS module shell. Named PROSCANNERCONT.MainWindow so the reused IDS pages'
    /// "(Application.Current.MainWindow as MainWindow)?.NavigateDirect(...)" works.
    /// Hosts the real IDS dashboard, runs the engine, and hosts the connection.
    /// </summary>
    public partial class MainWindow : Window
    {
        private const string ModuleKey = "IDS";
        private readonly ModuleHostConfig _config;
        private ModuleHost? _host;

        public MainWindow()
        {
            InitializeComponent();
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                    "PrivaCore", "Modules", "IDS", "config.json");
            _config = ModuleHostConfig.Load(path);
            if (_config.IsConfigured) StartRunning();
            else PortBox.Text = _config.ListenPort.ToString();
        }

        /// <summary>Reused IDS pages navigate through this (e.g. to Host IDS).</summary>
        public void NavigateDirect(Page page) => ContentFrame.Content = page;
        public void NavigateToPageWithState(string pageName, System.Collections.Generic.Dictionary<string, object>? state = null) { }

        private void SaveStart_Click(object sender, RoutedEventArgs e)
        {
            ErrText.Visibility = Visibility.Collapsed;
            if (!int.TryParse(PortBox.Text.Trim(), out var port) || port < 1 || port > 65535) { Err("Enter a valid port (1–65535)."); return; }
            if (UserBox.Text.Trim().Length == 0) { Err("Enter a username."); return; }
            if (PassBox.Password.Length < 4) { Err("Password must be at least 4 characters."); return; }
            if (PassBox.Password != Pass2Box.Password) { Err("Passwords do not match."); return; }
            if (PairBox.Text.Trim().Length < 4) { Err("Enter or generate a pairing code (at least 4 characters)."); return; }

            _config.Configure(port, UserBox.Text.Trim(), PassBox.Password, PairBox.Text.Trim());
            StartRunning();
        }

        private void Generate_Click(object sender, RoutedEventArgs e) => PairBox.Text = NewPairingCode();

        internal static string NewPairingCode()
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            var bytes = ModuleAuth.NewRandomBytes(12);
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < bytes.Length; i++) { if (i == 4 || i == 8) sb.Append('-'); sb.Append(chars[bytes[i] % chars.Length]); }
            return sb.ToString();
        }

        private void NewPairing_Click(object sender, RoutedEventArgs e)
        {
            var code = NewPairingCode();
            _config.SetPairing(code);
            new global::PROSCANNERCONT.Views.PairingCodeDialog(code) { Owner = this }.ShowDialog();
        }

        private void Err(string msg) { ErrText.Text = msg; ErrText.Visibility = Visibility.Visible; }

        private void StartRunning()
        {
            _host = new ModuleHost(ModuleKey, Environment.MachineName, _config);
            _host.ClientsChanged += () => Dispatcher.BeginInvoke(() => ConnInfo.Text = $"{_host!.ConnectedCount} controller(s) connected");
            try { _host.Start(); }
            catch (Exception ex) { Err($"Could not listen on port {_config.ListenPort}: {ex.Message}"); return; }

            IdsModuleBridge.AttachHost(_host);   // apply console commands + stream alerts/state
            ModuleThemeSync.AttachHost(_host, a => Dispatcher.BeginInvoke(a));   // controller can theme us live
            ModuleThemeSync.HostThemeChanged += name => Dispatcher.BeginInvoke(() => ThemeText.Text = $"Theme: {name}  ·  from console");
            ThemeText.Text = $"Theme: {Managers.ThemeManager.CurrentThemeName}";

            ContentFrame.Content = new NetworkIDSDashboardPage();
            RunStatus.Text = $"Listening on port {_config.ListenPort}";
            ConnInfo.Text = "0 controller(s) connected";
            var ips = NetworkReach.LocalIPv4();
            ReachText.Text = ips.Count > 0
                ? "Reachable at  " + string.Join("    ", ips.Select(ip => $"{ip}:{_config.ListenPort}"))
                : $"Listening on all interfaces :{_config.ListenPort}";
            if (!_host.FirewallOpened)
                ReachText.Text += "    ⚠ firewall not opened — run as Administrator (or Allow-Firewall.cmd) so other machines can connect";

            ConfigOverlay.Visibility = Visibility.Collapsed;
            RunningView.Visibility = Visibility.Visible;
        }

        private void Reconfigure_Click(object sender, RoutedEventArgs e)
        {
            // Open a small window to change the operator username + password. The host reads the
            // credential live per login, so new connections use the new credentials immediately —
            // no need to tear down the running sensor / dashboard.
            var result = global::PROSCANNERCONT.Views.ModuleCredentialsDialog.Show(this, _config.Credential?.Username ?? "admin");
            if (result is not { } r) return;
            _config.SetCredential(r.user, r.pass);
            ConnInfo.Text = $"credentials updated for “{r.user}”  ·  {_host?.ConnectedCount ?? 0} controller(s) connected";
        }

        private void Min_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Max_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            MaxBtn.Content = ((char)(WindowState == WindowState.Maximized ? 0xE923 : 0xE922)).ToString();
        }
        private void CloseWin_Click(object sender, RoutedEventArgs e) => Close();

        protected override void OnClosed(EventArgs e) { _host?.Stop(); base.OnClosed(e); }
    }
}
