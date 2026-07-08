using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FontAwesome.Sharp;
using PROSCANNERCONT.Models;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// Connect/login gate for a remote module. Probes the target IP, then authenticates
    /// with pairing code + username/password (challenge/response — secrets never sent).
    /// On success it hands the live <see cref="ModuleClient"/> to the caller so the
    /// data-flow view can stream events.
    /// </summary>
    public partial class ModuleConnectPage : Page
    {
        private readonly ManagedModule _module;
        private readonly Action<ModuleClient> _onConnected;
        private ModuleClient? _client;
        private bool _probeOk;

        public ModuleConnectPage(ManagedModule module, Action<ModuleClient> onConnected)
        {
            InitializeComponent();
            _module = module;
            _onConnected = onConnected;

            ModuleIcon.Icon = module.Icon;
            TitleText.Text = $"Connect to {module.DisplayName}";
            HostBox.Text = module.Host;
            PortBox.Text = module.Port.ToString();
            UserBox.Text = module.Username ?? "admin";

            // "Remember me": if a non-expired saved login exists, prefill + auto-reconnect.
            var remembered = Services.RememberedConnections.TryGet(module.InstanceId.ToString());
            if (remembered != null)
            {
                HostBox.Text = remembered.Host;
                PortBox.Text = remembered.Port.ToString();
                UserBox.Text = remembered.Username;
                RememberBox.IsChecked = true;
                Loaded += async (_, _) => await TryAutoConnectAsync(remembered);
            }

            // If we navigated away and back while still connected, dispose only on a fresh failure.
            Unloaded += (_, _) => { if (_module.LiveClient != _client) _client?.Dispose(); };
        }

        private async System.Threading.Tasks.Task TryAutoConnectAsync(Services.RememberedConnection r)
        {
            ShowStatus(null, "Reconnecting with saved login …");
            _client?.Dispose();
            _client = new ModuleClient();
            var probe = await _client.ConnectAndProbeAsync(r.Host, r.Port, _module.Key);
            if (probe.Running)
            {
                var login = await _client.LoginAsync(r.Username, r.Password, r.Pairing);
                if (login.Success)
                {
                    _module.Host = r.Host; _module.Port = r.Port; _module.Username = r.Username;
                    _module.SessionToken = login.Token; _module.LiveClient = _client; _module.IsConnected = true;
                    _onConnected(_client);
                    return;
                }
            }
            // Saved login no longer valid — fall back to manual sign-in.
            _probeOk = probe.Running;
            ShowStatus(false, "Saved login didn't work — please sign in again.");
            if (probe.Running) LoginPanel.Visibility = Visibility.Visible;
        }

        private async void Check_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(PortBox.Text.Trim(), out var port)) { ShowStatus(false, "Enter a valid port."); return; }
            var host = HostBox.Text.Trim();

            CheckButton.IsEnabled = false;
            ShowStatus(null, $"Checking {host}:{port} …");
            _client?.Dispose();
            _client = new ModuleClient();

            var probe = await _client.ConnectAndProbeAsync(host, port, _module.Key);

            if (!probe.Reachable) { ShowStatus(false, probe.Error ?? "Could not reach the host."); _probeOk = false; }
            else if (!probe.Running) { ShowStatus(false, probe.Error ?? "That module is not running there."); _probeOk = false; }
            else
            {
                _probeOk = true;
                ShowStatus(true, $"{_module.DisplayName} is running on {probe.HostName}. Sign in to control it.");
                LoginPanel.Visibility = Visibility.Visible;
            }
            CheckButton.IsEnabled = true;
        }

        private async void Connect_Click(object sender, RoutedEventArgs e)
        {
            if (!_probeOk || _client is null) { ShowStatus(false, "Check the connection first."); return; }
            var user = UserBox.Text.Trim();
            var pass = PassBox.Password;
            var pairing = PairingBox.Password;
            if (user.Length == 0 || pass.Length == 0 || pairing.Length == 0)
            { ShowStatus(false, "Enter username, password and pairing code."); return; }

            ConnectButton.IsEnabled = false;
            ShowStatus(null, "Verifying pairing code and signing in …");

            var result = await _client.LoginAsync(user, pass, pairing);
            if (result.Success)
            {
                _module.Host = HostBox.Text.Trim();
                _module.Port = int.Parse(PortBox.Text.Trim());
                _module.Username = user;
                _module.SessionToken = result.Token;
                _module.LiveClient = _client;
                _module.IsConnected = true;
                if (RememberBox.IsChecked == true)
                    Services.RememberedConnections.Save(_module.InstanceId.ToString(), _module.Host, _module.Port, user, pass, pairing, 14);
                else
                    Services.RememberedConnections.Remove(_module.InstanceId.ToString());
                ShowStatus(true, "Connected. Opening live view …");
                _onConnected(_client);
            }
            else
            {
                ShowStatus(false, result.Error ?? "Login failed.");
                ConnectButton.IsEnabled = true;
            }
        }

        private void ShowStatus(bool? ok, string message)
        {
            StatusBorder.Visibility = Visibility.Visible;
            StatusText.Text = message;
            string brushKey = ok switch { true => "SuccessBrush", false => "CriticalBrush", _ => "SubtleTextBrush" };
            StatusIcon.Icon = ok switch { true => IconChar.CircleCheck, false => IconChar.CircleXmark, _ => IconChar.CircleInfo };
            if (TryFindResource(brushKey) is Brush b) { StatusIcon.Foreground = b; StatusText.Foreground = b; }
        }
    }
}
