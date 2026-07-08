using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Threading;
using PROSCANNERCONT.Managers;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Services.Honeypot;
using PROSCANNERCONT.Views;
using PrivaCore.ModuleSdk;

namespace PrivaCore.Honeypot;

public partial class Shell : Window
{
    private const string ModuleKey = "Honeypot";
    private readonly ModuleHostConfig _config;
    private ModuleHost? _host;
    private readonly HoneypotCaptureService _svc = HoneypotCaptureService.Instance;
    private readonly ObservableCollection<HoneypotHit> _hits = new();
    private DispatcherTimer? _timer;
    private Action<HoneypotHit>? _onHit;

    public Shell()
    {
        InitializeComponent();
        // Window opens maximized — show the "restore" caption glyph to match.
        MaxBtn.Content = ((char)(WindowState == WindowState.Maximized ? 0xE923 : 0xE922)).ToString();
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                "PrivaCore", "Modules", "Honeypot", "config.json");
        _config = ModuleHostConfig.Load(path);
        ServiceKindBox.ItemsSource = Enum.GetValues(typeof(HoneypotServiceKind));
        ServiceKindBox.SelectedIndex = 0;
        HitsGrid.ItemsSource = _hits;
        if (_config.IsConfigured) StartRunning();
        else PortBox.Text = "9710";
    }

    private void SaveStart_Click(object sender, RoutedEventArgs e)
    {
        ErrText.Visibility = Visibility.Collapsed;
        if (!int.TryParse(PortBox.Text.Trim(), out var port) || port < 1 || port > 65535) { Err("Enter a valid port (1-65535)."); return; }
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

        HoneypotModuleBridge.AttachHost(_host);
        ModuleThemeSync.AttachHost(_host, a => Dispatcher.BeginInvoke(a));

        // Start persisted decoys; seed sensible high-port defaults on a fresh sensor.
        var cfg = _svc.StartConfigured();
        if (cfg.Decoys.Count == 0)
        {
            _svc.Start(HoneypotServiceKind.Telnet, 2323);
            _svc.Start(HoneypotServiceKind.Http, 8080);
            _svc.Start(HoneypotServiceKind.Ssh, 2222);
        }

        _onHit = hit => Dispatcher.BeginInvoke(() => OnHit(hit));
        _svc.HitRecorded += _onHit;
        foreach (var h in _svc.RecentHits(500)) _hits.Add(h);

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => RefreshUi();
        _timer.Start();
        RefreshUi();

        RunStatus.Text = $"Listening on port {_config.ListenPort}";
        ConnInfo.Text = "0 controller(s) connected";
        var ips = NetworkReach.LocalIPv4();
        ReachText.Text = ips.Count > 0
            ? "Reachable at  " + string.Join("    ", ips.Select(ip => $"{ip}:{_config.ListenPort}"))
            : $"Listening on all interfaces :{_config.ListenPort}";
        if (!_host.FirewallOpened)
            ReachText.Text += "    (firewall not opened — run as Administrator so the console can connect)";

        ConfigOverlay.Visibility = Visibility.Collapsed;
        RunningView.Visibility = Visibility.Visible;
    }

    private void OnHit(HoneypotHit hit)
    {
        _hits.Insert(0, hit);
        while (_hits.Count > 500) _hits.RemoveAt(_hits.Count - 1);
        RefreshUi();
    }

    private void RefreshUi()
    {
        DecoysList.ItemsSource = null;
        DecoysList.ItemsSource = _svc.Listeners;
        NoDecoysText.Visibility = _svc.Listeners.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        KpiDecoys.Text = _svc.ActiveListeners.ToString();
        KpiHits.Text = _svc.TotalHits.ToString("N0");
        KpiCreds.Text = _svc.CredentialHits.ToString("N0");
        KpiAttackers.Text = _svc.UniqueSources.ToString("N0");
    }

    private void StartDecoy_Click(object sender, RoutedEventArgs e)
    {
        if (ServiceKindBox.SelectedItem is not HoneypotServiceKind kind) return;
        if (!int.TryParse(DecoyPortBox.Text.Trim(), out var port) || port < 1 || port > 65535) return;
        var content = DecoyContentBox.Text?.Trim();
        DecoyOptions? opts = null;
        if (!string.IsNullOrEmpty(content))
            opts = kind == HoneypotServiceKind.Http ? new DecoyOptions { HttpHtml = content } : new DecoyOptions { Banner = content };
        if (!_svc.Start(kind, port, opts))
            MessageBox.Show(this, $"Could not listen on port {port} (in use, or <1024 needs admin).",
                "Honeypot", MessageBoxButton.OK, MessageBoxImage.Warning);
        else DecoyContentBox.Clear();
        RefreshUi();
    }

    private void StopDecoy_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button b && b.Tag is HoneypotListenerInfo info) { _svc.Stop(info.Port); RefreshUi(); }
    }

    private void Reconfigure_Click(object sender, RoutedEventArgs e)
    {
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

    protected override void OnClosed(EventArgs e) { _timer?.Stop(); _svc.StopAll(); _host?.Stop(); base.OnClosed(e); }
}
