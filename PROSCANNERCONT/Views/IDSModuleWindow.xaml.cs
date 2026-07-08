using System;
using System.IO;
using System.Windows;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// Standalone IDS module window (shown when the app is launched with --module IDS).
    /// Reuses the real IDS dashboard GUI verbatim, runs the IDS engine locally, and
    /// hosts the connection so a console can drive it and receive live alerts.
    /// </summary>
    public partial class IDSModuleWindow : Window
    {
        private const string ModuleKey = "IDS";
        private readonly ModuleHostConfig _config;
        private ModuleHost? _host;

        public IDSModuleWindow()
        {
            InitializeComponent();
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                    "PrivaCore", "Modules", "IDS", "config.json");
            _config = ModuleHostConfig.Load(path);

            if (_config.IsConfigured) StartRunning();
            else { PortBox.Text = _config.ListenPort.ToString(); }
        }

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

        /// <summary>Make up a readable random pairing code the operator can hand to console users.</summary>
        private void Generate_Click(object sender, RoutedEventArgs e) => PairBox.Text = NewPairingCode();

        private static string NewPairingCode()
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous 0/O/1/I
            var bytes = ModuleAuth.NewRandomBytes(12);
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                if (i == 4 || i == 8) sb.Append('-');
                sb.Append(chars[bytes[i] % chars.Length]);
            }
            return sb.ToString();
        }

        private void NewPairing_Click(object sender, RoutedEventArgs e)
        {
            var code = NewPairingCode();
            _config.SetPairing(code);
            new PairingCodeDialog(code) { Owner = this }.ShowDialog();
        }

        private void Err(string msg) { ErrText.Text = msg; ErrText.Visibility = Visibility.Visible; }

        private void StartRunning()
        {
            _host = new ModuleHost(ModuleKey, Environment.MachineName, _config);
            _host.ClientsChanged += () => Dispatcher.BeginInvoke(() =>
                ConnInfo.Text = $"{_host!.ConnectedCount} controller(s) connected");
            try { _host.Start(); }
            catch (Exception ex) { Err($"Could not listen on port {_config.ListenPort}: {ex.Message}"); return; }

            // Apply console commands (start/stop, rules) and stream alerts/state back.
            IdsModuleBridge.AttachHost(_host);

            // Show the real IDS dashboard GUI.
            ContentFrame.Content = new NetworkIDSDashboardPage();
            RunStatus.Text = $"Listening on port {_config.ListenPort}";
            ConnInfo.Text = "0 controller(s) connected";

            // Tell the operator the address other machines should connect to.
            var ips = NetworkReach.LocalIPv4();
            ReachText.Text = ips.Count > 0
                ? "Reachable at  " + string.Join("    ", ips.ConvertAll(ip => $"{ip}:{_config.ListenPort}"))
                : $"Listening on all interfaces :{_config.ListenPort}";
            if (!_host.FirewallOpened)
                ReachText.Text += "    ⚠ firewall not opened — run as Administrator (or Allow-Firewall.cmd) so other machines can connect";
            ConfigOverlay.Visibility = Visibility.Collapsed;
            RunningView.Visibility = Visibility.Visible;
        }

        private void Reconfigure_Click(object sender, RoutedEventArgs e)
        {
            // Change the operator username + password via a small window. The host reads the
            // credential live per login, so it applies to new connections without a restart.
            var result = ModuleCredentialsDialog.Show(this, _config.Credential?.Username ?? "admin");
            if (result is not { } r) return;
            _config.SetCredential(r.user, r.pass);
            ConnInfo.Text = $"credentials updated for “{r.user}”  ·  {_host?.ConnectedCount ?? 0} controller(s) connected";
        }

        protected override void OnClosed(EventArgs e) { _host?.Stop(); base.OnClosed(e); }
    }
}
