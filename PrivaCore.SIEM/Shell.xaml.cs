using System;
using System.IO;
using System.Linq;
using System.Windows;
using PROSCANNERCONT.Managers;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Services.Siem;
using PROSCANNERCONT.Views;
using PrivaCore.ModuleSdk;

namespace PrivaCore.SIEM;

public partial class Shell : Window
{
    private const string ModuleKey = "SIEM";
    private readonly ModuleHostConfig _config;
    private ModuleHost? _host;

    public Shell()
    {
        InitializeComponent();
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                "PrivaCore", "Modules", "SIEM", "config.json");
        _config = ModuleHostConfig.Load(path);
        if (_config.IsConfigured) StartRunning();
        else PortBox.Text = "9720";   // SIEM's default port (distinct from IDS's 9700)
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

    private void Generate_Click(object sender, RoutedEventArgs e) => PairBox.Text = NewPairingCode();

    private static string NewPairingCode()
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
        new PairingCodeDialog(code) { Owner = this }.ShowDialog();
    }

    private void Err(string msg) { ErrText.Text = msg; ErrText.Visibility = Visibility.Visible; }

    private void StartRunning()
    {
        _host = new ModuleHost(ModuleKey, Environment.MachineName, _config);
        _host.ClientsChanged += () => Dispatcher.BeginInvoke(() => ConnInfo.Text = $"{_host!.ConnectedCount} controller(s) connected");
        try { _host.Start(); }
        catch (Exception ex) { Err($"Could not listen on port {_config.ListenPort}: {ex.Message}"); return; }

        SiemModuleBridge.AttachHost(_host);
        ModuleThemeSync.AttachHost(_host, a => Dispatcher.BeginInvoke(a));   // controller can theme us live
        ModuleThemeSync.HostThemeChanged += name => Dispatcher.BeginInvoke(() => ThemeText.Text = $"Theme: {name}  ·  from console");
        ThemeText.Text = $"Theme: {ThemeManager.CurrentThemeName}";
        SiemIngestion.Instance.StartGenerator();   // lively by default; sources are toggleable in the dashboard

        ContentFrame.Content = new SiemDashboardPage();
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
        // no need to tear down the running collector / dashboard.
        var result = ModuleCredentialsDialog.Show(this, _config.Credential?.Username ?? "admin");
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

    protected override void OnClosed(EventArgs e) { _host?.Stop(); SiemIngestion.Instance.StopAll(); base.OnClosed(e); }
}
