using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Honeypot;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// The Live Capture surface: start/stop software decoys, watch attacker interactions stream in,
    /// see top attackers and real stats, and optionally forward every hit to the SIEM. This is the
    /// part that turns the honeypot from a VM list into an actual threat sensor.
    /// </summary>
    public partial class HoneypotCaptureView : UserControl
    {
        public sealed class AttackerRow { public string Ip { get; set; } = ""; public long Count { get; set; } }
        public sealed class CredRow { public string Label { get; set; } = ""; public long Count { get; set; } }

        private readonly HoneypotCaptureService _svc = HoneypotCaptureService.Instance;
        private readonly ObservableCollection<HoneypotHit> _hits = new();
        private readonly DispatcherTimer _timer;
        private Action<HoneypotHit>? _onHit;

        public HoneypotCaptureView()
        {
            InitializeComponent();
            ServiceKindBox.ItemsSource = Enum.GetValues(typeof(HoneypotServiceKind));
            ServiceKindBox.SelectedIndex = 0;
            HitsGrid.ItemsSource = _hits;
            FeedSiemBox.IsChecked = HoneypotSiemBridge.Attached;

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += (_, _) => { RefreshDecoys(); RefreshStats(); };

            Loaded += OnLoaded;
            Unloaded += OnUnloaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            _onHit ??= hit => Dispatcher.Invoke(() => OnHit(hit));
            _svc.HitRecorded += _onHit;
            // Reflect any hits captured while this view wasn't shown.
            _hits.Clear();
            foreach (var h in _svc.RecentHits(500)) _hits.Add(h);
            RefreshDecoys(); RefreshStats(); RefreshTopAttackers();
            _timer.Start();
        }

        private void OnUnloaded(object sender, RoutedEventArgs e)
        {
            if (_onHit != null) _svc.HitRecorded -= _onHit;
            _timer.Stop();
        }

        private void OnHit(HoneypotHit hit)
        {
            _hits.Insert(0, hit);
            while (_hits.Count > 500) _hits.RemoveAt(_hits.Count - 1);
            RefreshStats(); RefreshTopAttackers(); RefreshDecoys();
        }

        // ── actions ──────────────────────────────────────────────────────────
        private void StartDecoy_Click(object sender, RoutedEventArgs e)
        {
            if (ServiceKindBox.SelectedItem is not HoneypotServiceKind kind) return;
            if (!int.TryParse(PortBox.Text.Trim(), out var port) || port < 1 || port > 65535)
            {
                MessageBox.Show(Window.GetWindow(this), "Enter a valid port (1–65535).", "Honeypot", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var content = DecoyContentBox.Text?.Trim();
            DecoyOptions? opts = null;
            if (!string.IsNullOrEmpty(content))
                opts = kind == HoneypotServiceKind.Http
                    ? new DecoyOptions { HttpHtml = content }
                    : new DecoyOptions { Banner = content };

            if (!_svc.Start(kind, port, opts))
            {
                MessageBox.Show(Window.GetWindow(this),
                    $"Could not listen on port {port}.\n\nThe port may be in use, or ports below 1024 need Administrator.",
                    "Honeypot", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            DecoyContentBox.Clear();
            RefreshDecoys(); RefreshStats();
        }

        private void StopDecoy_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is HoneypotListenerInfo info)
            {
                _svc.Stop(info.Port);
                RefreshDecoys(); RefreshStats();
            }
        }

        private void FeedSiem_Changed(object sender, RoutedEventArgs e)
        {
            var on = FeedSiemBox.IsChecked == true;
            if (on) HoneypotSiemBridge.Attach(); else HoneypotSiemBridge.Detach();
            var cfg = HoneypotConfig.Load(); cfg.FeedSiem = on; cfg.Save();   // remember across restarts
        }

        private void ClearHits_Click(object sender, RoutedEventArgs e) => _hits.Clear();

        // ── refresh ──────────────────────────────────────────────────────────
        private void RefreshDecoys()
        {
            var list = _svc.Listeners;
            DecoysList.ItemsSource = null;
            DecoysList.ItemsSource = list;
            NoDecoysText.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void RefreshStats()
        {
            ActiveDecoysText.Text = _svc.ActiveListeners.ToString();
            TotalHitsText.Text = _svc.TotalHits.ToString("N0");
            CredsText.Text = _svc.CredentialHits.ToString("N0");
            UniqueText.Text = _svc.UniqueSources.ToString("N0");
        }

        private void RefreshTopAttackers()
        {
            TopAttackersList.ItemsSource = _svc.TopAttackers(8)
                .Select(t => new AttackerRow { Ip = t.ip, Count = t.count }).ToList();
            TopCredsList.ItemsSource = _svc.TopUsernames(8)
                .Select(t => new CredRow { Label = t.user, Count = t.count }).ToList();
        }
    }
}
