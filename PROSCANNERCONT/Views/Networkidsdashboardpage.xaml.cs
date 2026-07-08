using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class NetworkIDSDashboardPage : Page
    {
        private readonly IDSEngine _engine = IDSManager.Engine;

        // All alerts (master) and filtered view
        private readonly List<IDSAlert> _allAlerts = new();
        private readonly ObservableCollection<IDSAlert> _filteredAlerts = new();

        private readonly ObservableCollection<TrafficSummaryItem> _trafficItems  = new();
        private readonly ObservableCollection<SigHitItem>         _sigItems      = new();
        private readonly ObservableCollection<CorrelationGroup>   _corrItems     = new();
        private readonly ObservableCollection<AllowlistEntry>     _allowlistItems = new();
        private readonly ObservableCollection<BlockedIpEntry>     _blockedItems  = new();

        // ── Live traffic graph ────────────────────────────────────────────
        private record GraphPoint(double PktPerSec, int AlertDelta, DateTime Time);
        private readonly Queue<GraphPoint> _graphBuffer = new();
        private const int GraphCapacity = 60;   // 60 × 2s refresh = 2 minutes
        private long _graphLastPktCount  = 0;
        private int  _graphLastAlertCount = 0;
        // Pre-created drawing elements — reused each frame
        private Polygon?  _pktFill;
        private Polyline? _pktLine;
        private Polyline? _alertLine;

        private readonly DispatcherTimer _refreshTimer = new();
        private int    _selectedDeviceIndex = 0;
        private string _severityFilter = "ALL";
        private int    _minutesFilter  = 0;   // 0 = all time
        private string _searchText     = "";
        private long   _lastPacketCount = 0;
        private DateTime _lastRateTime = DateTime.UtcNow;

        public NetworkIDSDashboardPage()
        {
            InitializeComponent();

            AlertsList.ItemsSource          = _filteredAlerts;
            TrafficAnalysisList.ItemsSource = _trafficItems;
            SignaturesList.ItemsSource      = _sigItems;
            if (RulesGrid       != null) RulesGrid.ItemsSource       = _engine.Rules.ToList();
            if (CorrelationGrid != null) CorrelationGrid.ItemsSource  = _corrItems;
            if (AllowlistGrid   != null) AllowlistGrid.ItemsSource    = _allowlistItems;
            if (BlockedGrid     != null) BlockedGrid.ItemsSource      = _blockedItems;

            _engine.AlertGenerated    += OnAlertGenerated;
            _engine.StatsUpdated      += OnStatsUpdated;
            _engine.KillChainDetected += OnKillChainDetected;
            _engine.RulesChanged      += OnRulesChanged;
            _engine.InterfacesChanged += OnInterfacesChanged;

            _refreshTimer.Interval = TimeSpan.FromSeconds(2);
            _refreshTimer.Tick    += (_, __) => RefreshUI();
            _refreshTimer.Start();

            // Unsubscribe and stop timer when page is unloaded to prevent
            // duplicate handlers accumulating across navigation visits
            Unloaded += (_, __) =>
            {
                _engine.AlertGenerated    -= OnAlertGenerated;
                _engine.StatsUpdated      -= OnStatsUpdated;
                _engine.KillChainDetected -= OnKillChainDetected;
                _engine.RulesChanged      -= OnRulesChanged;
                _engine.InterfacesChanged -= OnInterfacesChanged;
                _refreshTimer.Stop();
            };

            PopulateInterfaces();
            SyncAllAlerts();
            RefreshUI();
            RefreshRulesGrid();
            LoadThresholdUI();
            RefreshAllowlistGrid();
            RefreshBlockedGrid();
            RefreshTimeline();
            RefreshCorrelation();
            InitGraph();
        }

        // ── Sync all alerts from engine into local list ──────────────
        private void SyncAllAlerts()
        {
            _allAlerts.Clear();
            _allAlerts.AddRange(_engine.Alerts);
            ApplyFilters();
        }

        // ── Apply search + severity + time filters ────────────────────
        private void ApplyFilters()
        {
            var cutoff = _minutesFilter > 0
                ? DateTime.Now.AddMinutes(-_minutesFilter)
                : DateTime.MinValue;

            var result = _allAlerts
                .Where(a =>
                    (_severityFilter == "ALL" || a.SeverityText == _severityFilter) &&
                    (cutoff == DateTime.MinValue || a.Timestamp >= cutoff) &&
                    (string.IsNullOrWhiteSpace(_searchText) ||
                     Contains(a.AlertType,       _searchText) ||
                     Contains(a.SourceIP,         _searchText) ||
                     Contains(a.DestinationIP,    _searchText) ||
                     Contains(a.AttackCategory,   _searchText) ||
                     Contains(a.Description,      _searchText) ||
                     Contains(a.RuleId,           _searchText) ||
                     Contains(a.Protocol,         _searchText)))
                .OrderByDescending(a => a.Timestamp)
                .ToList();

            _filteredAlerts.Clear();
            foreach (var a in result) _filteredAlerts.Add(a);

            if (AlertCountText  != null) AlertCountText.Text  = _filteredAlerts.Count.ToString();
            if (AlertCountBadge != null) AlertCountBadge.Visibility = _filteredAlerts.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static bool Contains(string source, string term) =>
            source?.Contains(term, StringComparison.OrdinalIgnoreCase) == true;

        // ── UI refresh ────────────────────────────────────────────────
        private void RefreshUI()
        {
            var stats = _engine.GetStats();
            UpdateGraphData(stats);

            PacketsCapturedText.Text  = stats.TotalPackets.ToString("N0");
            ThreatsDetectedText.Text  = stats.TotalThreats.ToString("N0");
            SignatureMatchesText.Text = stats.SignatureMatches.ToString("N0");

            // Packet rate
            var now = DateTime.UtcNow;
            double elapsed = (now - _lastRateTime).TotalSeconds;
            if (elapsed >= 1.0)
            {
                long delta = stats.TotalPackets - _lastPacketCount;
                double rate = delta / elapsed;
                if (PacketRateText != null)
                    PacketRateText.Text = $"{rate:F0} pkt/s";
                _lastPacketCount = stats.TotalPackets;
                _lastRateTime = now;
            }
            CriticalAlertsText.Text   = stats.CriticalAlerts.ToString();
            HighAlertsText.Text       = stats.HighAlerts.ToString();
            ActiveRulesText.Text      = $"{stats.ActiveRules} / {stats.TotalRules}";

            if (UnackedText != null)
                UnackedText.Text = $"{_engine.Alerts.Count(a => !a.IsAcknowledged)} unacknowledged";

            // Status
            bool running = stats.IsRunning;
            StatusDot.Fill   = new SolidColorBrush(Color.FromRgb(running ? (byte)78  : (byte)244,
                                                                  running ? (byte)201 : (byte)71,
                                                                  running ? (byte)176 : (byte)71));
            StatusLabel.Text = running
                ? $"MONITORING  —  capturing on: {stats.ActiveInterface}"
                : "OFFLINE  —  select an interface and click Start Monitoring";
            MonitoringToggleButton.Content = running ? "⏸  Stop Monitoring" : "▶  Start Monitoring";
            MonitoringToggleButton.Background = running ? new SolidColorBrush(Color.FromRgb(90, 20, 20)) : Br("SecondaryBackgroundBrush");
            MonitoringToggleButton.Foreground = running ? Br("CriticalBrush") : Br("SuccessBrush");

            if (InterfaceLabel != null)
                InterfaceLabel.Text = running
                    ? $"● ACTIVE  —  {stats.ActiveInterface}  ·  {stats.TotalPackets:N0} packets  ·  {stats.TotalThreats:N0} threats"
                    : "No interface selected  ·  click  Interface  to choose, then Start Monitoring";

            // Sync alerts
            var fresh = _engine.Alerts.ToList();
            bool changed = fresh.Count != _allAlerts.Count ||
                           (fresh.Count > 0 && fresh[0].AlertId != (_allAlerts.Count > 0 ? _allAlerts[0].AlertId : Guid.Empty));
            if (changed) { _allAlerts.Clear(); _allAlerts.AddRange(fresh); ApplyFilters(); }

            // Breakdown tab
            _trafficItems.Clear();
            fresh.GroupBy(a => a.AttackCategory ?? "Unknown")
                 .OrderByDescending(g => g.Count()).Take(10)
                 .ToList()
                 .ForEach(g => _trafficItems.Add(new TrafficSummaryItem
                 {
                     Category = g.Key,
                     Count    = g.Count(),
                     LastSeen = g.Max(a => a.Timestamp).ToString("HH:mm:ss")
                 }));

            _sigItems.Clear();
            _engine.Rules.Where(r => r.TriggerCount > 0)
                         .OrderByDescending(r => r.TriggerCount).Take(10)
                         .ToList()
                         .ForEach(r => _sigItems.Add(new SigHitItem
                         {
                             Name     = r.Name,
                             Count    = r.TriggerCount.ToString(),
                             Category = r.AttackCategory
                         }));

            if (RulesGrid != null) RulesGrid.ItemsSource = _engine.Rules.ToList();
        }

        // Rule set changed (locally or pushed from a remote sensor) — refresh the grid.
        private void OnRulesChanged(object? sender, EventArgs e) => Dispatcher.Invoke(RefreshRulesGrid);

        // Remote sensor's interface list arrived — refresh the interface count.
        private void OnInterfacesChanged(object? sender, EventArgs e) => Dispatcher.Invoke(PopulateInterfaces);

        // ── Real-time alert event ─────────────────────────────────────
        private void OnAlertGenerated(object sender, IDSAlert alert)
        {
            Dispatcher.InvokeAsync(() =>
            {
                _allAlerts.Insert(0, alert);
                ApplyFilters();
                ThreatsDetectedText.Text = _engine.GetStats().TotalThreats.ToString("N0");

                if (alert.Severity >= IDSAlertSeverity.High)
                    AlertToast.Show(alert.AlertType, $"{alert.SourceEndpoint}  →  {alert.DstEndpoint}", alert.SeverityColor);
            });
        }

        private void OnStatsUpdated(object sender, IDSStats stats)
        {
            Dispatcher.InvokeAsync(() =>
            {
                PacketsCapturedText.Text  = stats.TotalPackets.ToString("N0");
                ThreatsDetectedText.Text  = stats.TotalThreats.ToString("N0");
                SignatureMatchesText.Text = stats.SignatureMatches.ToString("N0");
            });
        }

        // ── SEARCH ───────────────────────────────────────────────────
        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _searchText = SearchBox.Text?.Trim() ?? "";
            ApplyFilters();
        }

        // ── SEVERITY FILTER ──────────────────────────────────────────
        private void SeverityFilter_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button b) { _severityFilter = b.Tag?.ToString() ?? "ALL"; ApplyFilters(); }
        }

        // ── TIME FILTER ──────────────────────────────────────────────
        private void TimeFilter_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && int.TryParse(b.Tag?.ToString(), out int mins))
            { _minutesFilter = mins; ApplyFilters(); }
        }

        // ── BUTTONS ──────────────────────────────────────────────────
        private void RefreshDashboard_Click(object sender, RoutedEventArgs e)
        {
            SyncAllAlerts();
            RefreshUI();
        }

        // ── RULE GRID SELECTION ───────────────────────────────────────
        private void RulesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            bool hasSelection = RulesGrid.SelectedItem is IDSRule;
            if (EditRuleBtn   != null) EditRuleBtn.IsEnabled   = hasSelection;
            if (DeleteRuleBtn != null) DeleteRuleBtn.IsEnabled = hasSelection;
        }

        private void RulesGrid_DoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (RulesGrid.SelectedItem is IDSRule) EditRule_Click(sender, e);
        }

        // ── CRUD ─────────────────────────────────────────────────────
        /// <summary>
        /// RBAC gate set by the console after sign-in (maps a permission key to the signed-in role).
        /// Null in the standalone IDS module app — which links this page but has no console session —
        /// so the local operator keeps full control there.
        /// </summary>
        public static Func<string, bool>? PermissionGate;

        private bool AllowedTo(string permissionKey, string action)
        {
            if (PermissionGate == null || PermissionGate(permissionKey)) return true;
            AppDialog.Show($"Your role can't {action}.", "Not permitted", MessageBoxButton.OK, MessageBoxImage.Information);
            return false;
        }

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            if (!AllowedTo("ManageIdsRules", "edit IDS rules")) return;
            var dlg = new RuleEditorWindow { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() == true && dlg.Result != null)
            {
                _engine.AddRule(dlg.Result);
                RefreshRulesGrid();
            }
        }

        private void EditRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not IDSRule selected) return;
            if (!AllowedTo("ManageIdsRules", "edit IDS rules")) return;
            var dlg = new RuleEditorWindow(selected) { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() == true && dlg.Result != null)
            {
                _engine.UpdateRule(dlg.Result);
                RefreshRulesGrid();
            }
        }

        private void DeleteRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not IDSRule selected) return;
            if (!AllowedTo("ManageIdsRules", "delete IDS rules")) return;
            if (AppDialog.Show($"Delete rule '{selected.Name}'?", "Confirm Delete",
                    MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            _engine.DeleteRule(selected.Id);
            RefreshRulesGrid();
        }

        // ── IMPORT / EXPORT ──────────────────────────────────────────
        private void ImportRules_Click(object sender, RoutedEventArgs e)
        {
            if (!AllowedTo("ManageIdsRules", "import IDS rules")) return;
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Import Rules",
                Filter = "JSON files (*.json)|*.json",
                DefaultExt = ".json"
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                string json = File.ReadAllText(dlg.FileName);
                var (added, skipped) = _engine.ImportRulesJson(json);
                RefreshRulesGrid();
                AppDialog.Show($"Import complete.\n\n✓ {added} rules added\n⊘ {skipped} skipped (duplicate ID)",
                    "Import Rules", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Import failed:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportRules_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export Rules",
                Filter = "JSON files (*.json)|*.json",
                FileName = $"IDS_Rules_{DateTime.Now:yyyyMMdd_HHmmss}.json"
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                File.WriteAllText(dlg.FileName, _engine.ExportRulesJson(), Encoding.UTF8);
                AppDialog.Show($"Exported {_engine.Rules.Count} rules to:\n{dlg.FileName}",
                    "Export Rules", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Export failed:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ── BULK ENABLE/DISABLE ───────────────────────────────────────
        private void BulkEnable_Click(object sender, RoutedEventArgs e)  => BulkSetEnabled(true);
        private void BulkDisable_Click(object sender, RoutedEventArgs e) => BulkSetEnabled(false);

        private void BulkSetEnabled(bool enabled)
        {
            if (!AllowedTo("ManageIdsRules", "enable/disable IDS rules")) return;
            string cat = (BulkCategoryBox.SelectedItem as ComboBoxItem)?.Content?.ToString()
                      ?? BulkCategoryBox.SelectedItem?.ToString() ?? "";
            var targets = string.IsNullOrEmpty(cat) || cat == "All Categories"
                ? _engine.Rules.ToList()
                : _engine.Rules.Where(r => r.AttackCategory == cat).ToList();
            foreach (var r in targets) _engine.ToggleRule(r.Id, enabled);
            RefreshRulesGrid();
        }

        private void RefreshRulesGrid()
        {
            var rules = _engine.Rules.ToList();
            if (RulesGrid != null) RulesGrid.ItemsSource = rules;
            if (RulesInfoText != null)
                RulesInfoText.Text = $"{rules.Count} rules  ·  {rules.Count(r => r.IsEnabled)} enabled  ·  " +
                                     $"{rules.Count(r => r.RuleKind == RuleKind.Signature)} signature  ·  " +
                                     $"double-click to edit";
            // Rebuild category dropdown
            if (BulkCategoryBox != null)
            {
                BulkCategoryBox.Items.Clear();
                BulkCategoryBox.Items.Add(new ComboBoxItem { Content = "All Categories" });
                foreach (var cat in rules.Select(r => r.AttackCategory).Where(c => !string.IsNullOrEmpty(c)).Distinct().OrderBy(c => c))
                    BulkCategoryBox.Items.Add(new ComboBoxItem { Content = cat });
                BulkCategoryBox.SelectedIndex = 0;
            }
        }

        // ── BEHAVIORAL THRESHOLDS ─────────────────────────────────────
        private void LoadThresholdUI()
        {
            var s = _engine.GetBehavioralSettings();
            if (SynThreshBox      != null) SynThreshBox.Text      = s.SynFloodThreshold.ToString();
            if (SynWindowBox      != null) SynWindowBox.Text      = s.SynFloodWindowSec.ToString();
            if (IcmpThreshBox     != null) IcmpThreshBox.Text     = s.IcmpFloodThreshold.ToString();
            if (IcmpWindowBox     != null) IcmpWindowBox.Text     = s.IcmpFloodWindowSec.ToString();
            if (UdpThreshBox      != null) UdpThreshBox.Text      = s.UdpFloodThreshold.ToString();
            if (UdpWindowBox      != null) UdpWindowBox.Text      = s.UdpFloodWindowSec.ToString();
            if (PortScanThreshBox != null) PortScanThreshBox.Text = s.PortScanThreshold.ToString();
            if (PortScanWindowBox != null) PortScanWindowBox.Text = s.PortScanWindowSec.ToString();
            if (BruteThreshBox    != null) BruteThreshBox.Text    = s.BruteForceThreshold.ToString();
            if (BruteWindowBox    != null) BruteWindowBox.Text    = s.BruteForceWindowSec.ToString();
        }

        private void ApplyThresholds_Click(object sender, RoutedEventArgs e)
        {
            bool Parse(TextBox box, out int val) => int.TryParse(box?.Text, out val) && val > 0;

            if (!Parse(SynThreshBox,      out int st))  { ShowThresholdError("SYN threshold must be > 0");  return; }
            if (!Parse(SynWindowBox,      out int sw))  { ShowThresholdError("SYN window must be > 0");     return; }
            if (!Parse(IcmpThreshBox,     out int it))  { ShowThresholdError("ICMP threshold must be > 0"); return; }
            if (!Parse(IcmpWindowBox,     out int iw))  { ShowThresholdError("ICMP window must be > 0");    return; }
            if (!Parse(UdpThreshBox,      out int ut))  { ShowThresholdError("UDP threshold must be > 0");  return; }
            if (!Parse(UdpWindowBox,      out int uw))  { ShowThresholdError("UDP window must be > 0");     return; }
            if (!Parse(PortScanThreshBox, out int pst)) { ShowThresholdError("Port scan threshold must be > 0"); return; }
            if (!Parse(PortScanWindowBox, out int psw)) { ShowThresholdError("Port scan window must be > 0");    return; }
            if (!Parse(BruteThreshBox,    out int bt))  { ShowThresholdError("Brute force threshold must be > 0"); return; }
            if (!Parse(BruteWindowBox,    out int bw))  { ShowThresholdError("Brute force window must be > 0");    return; }

            _engine.ApplyBehavioralSettings(new BehavioralSettings
            {
                SynFloodThreshold   = st, SynFloodWindowSec   = sw,
                IcmpFloodThreshold  = it, IcmpFloodWindowSec  = iw,
                UdpFloodThreshold   = ut, UdpFloodWindowSec   = uw,
                PortScanThreshold   = pst, PortScanWindowSec  = psw,
                BruteForceThreshold = bt, BruteForceWindowSec = bw
            });

            if (ThresholdStatusText != null)
            {
                ThresholdStatusText.Text = $"✓  Applied at {DateTime.Now:HH:mm:ss}";
                var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
                timer.Tick += (_, __) => { ThresholdStatusText.Text = ""; timer.Stop(); };
                timer.Start();
            }
        }

        private void ResetThresholds_Click(object sender, RoutedEventArgs e)
        {
            _engine.ApplyBehavioralSettings(new BehavioralSettings());
            LoadThresholdUI();
            if (ThresholdStatusText != null) ThresholdStatusText.Text = "✓  Restored to defaults";
        }

        private void ShowThresholdError(string msg)
        {
            if (ThresholdStatusText != null)
            {
                ThresholdStatusText.Foreground = Br("CriticalBrush");
                ThresholdStatusText.Text = $"✗  {msg}";
            }
        }

        private void ClearAlerts_Click(object sender, RoutedEventArgs e)
        {
            if (AppDialog.Show("Clear all alerts?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            _engine.ClearAlerts();
            _allAlerts.Clear();
            _filteredAlerts.Clear();
            DetailPanel.Children.Clear();
            DetailPanel.Children.Add(new TextBlock { Text = "Select an alert to see details", Foreground = Br("SubtleTextBrush"), FontSize = 12, FontFamily = new FontFamily("Segoe UI"), TextWrapping = TextWrapping.Wrap });
            RefreshUI();
        }

        private void AcknowledgeSelected_Click(object sender, RoutedEventArgs e)
        {
            if (AlertsList.SelectedItem is IDSAlert alert)
            {
                _engine.AcknowledgeAlert(alert.AlertId);
                alert.IsAcknowledged = true;
                ApplyFilters();
            }
        }

        private void DeleteSelected_Click(object sender, RoutedEventArgs e)
        {
            if (AlertsList.SelectedItem is IDSAlert alert)
            {
                _engine.DeleteAlert(alert.AlertId);
                _allAlerts.Remove(alert);
                ApplyFilters();
            }
        }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog
                {
                    Title    = "Export Alerts",
                    Filter   = "CSV files (*.csv)|*.csv",
                    FileName = $"IDS_Alerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                };
                if (dlg.ShowDialog() != true) return;

                var sb = new StringBuilder();
                sb.AppendLine("Timestamp,Severity,Alert Type,Source,Destination,Protocol,Category,Rule ID,Description,Acknowledged");
                foreach (var a in _filteredAlerts)
                    sb.AppendLine($"{a.TimestampFormatted},{a.SeverityText},{Q(a.AlertType)},{a.SourceEndpoint},{a.DstEndpoint},{a.Protocol},{a.AttackCategory},{a.RuleId},{Q(a.Description)},{a.IsAcknowledged}");

                File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
                AppDialog.Show($"Exported {_filteredAlerts.Count} alerts to:\n{dlg.FileName}", "Exported",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string Q(string s) => $"\"{s?.Replace("\"","'")}\"";

        private void ToggleMonitoring_Click(object sender, RoutedEventArgs e)
        {
            if (_engine.IsRunning)
            {
                _engine.StopCapture();
            }
            else
            {
                try
                {
                    _engine.StartCapture(_selectedDeviceIndex);
                    var stats = _engine.GetStats();
                    AppDialog.Show($"Network IDS started\n\nInterface: {stats.ActiveInterface}\nActive rules: {stats.ActiveRules}",
                        "Started", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Failed to start capture:\n{ex.Message}\n\nTip: Run as Administrator.",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            RefreshUI();
        }

        private void SelectInterface_Click(object sender, RoutedEventArgs e)
        {
            var ifaces = _engine.GetInterfaces().ToList();
            if (ifaces.Count == 0)
            {
                AppDialog.Show("No interfaces found.\nRun the application as Administrator.", "No Interfaces", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Build a proper WPF dialog (no VB InputBox)
            var dlg = new Window
            {
                Title = "Select Network Interface",
                Width = 600, Height = 320,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Window.GetWindow(this),
                Background = new SolidColorBrush(Col("BackgroundBrush")),
                ResizeMode = ResizeMode.NoResize
            };
            var root = new Grid { Margin = new Thickness(12) };
            root.RowDefinitions.Add(new RowDefinition());
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var lb = new ListBox
            {
                Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")),
                Foreground = new SolidColorBrush(Col("TextBrush")),
                BorderThickness = new Thickness(1),
                BorderBrush = new SolidColorBrush(Col("BorderBrush")),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12
            };
            for (int i = 0; i < ifaces.Count; i++)
                lb.Items.Add(new ListBoxItem { Content = $"[{i}]  {Trunc(ifaces[i], 90)}", Tag = i, Padding = new Thickness(8, 5, 8, 5) });
            if (lb.Items.Count > 0) lb.SelectedIndex = Math.Min(_selectedDeviceIndex, lb.Items.Count - 1);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
            var btnOk = new Button { Content = "Select", Width = 90, Height = 30, IsDefault = true,
                Background = Br("AccentBrush"), Foreground = Brushes.White, BorderThickness = new Thickness(0), Margin = new Thickness(0, 0, 8, 0) };
            var btnCancel = new Button { Content = "Cancel", Width = 80, Height = 30, IsCancel = true,
                Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")), Foreground = new SolidColorBrush(Col("TextBrush")),
                BorderThickness = new Thickness(1), BorderBrush = new SolidColorBrush(Col("BorderBrush")) };

            int chosen = _selectedDeviceIndex;
            btnOk.Click     += (_, __) => { if (lb.SelectedItem is ListBoxItem li && li.Tag is int idx) chosen = idx; dlg.DialogResult = true; };
            btnCancel.Click += (_, __) => dlg.DialogResult = false;
            lb.MouseDoubleClick += (_, __) => { if (lb.SelectedItem is ListBoxItem li && li.Tag is int idx) chosen = idx; dlg.DialogResult = true; };

            btnRow.Children.Add(btnOk);
            btnRow.Children.Add(btnCancel);
            Grid.SetRow(lb, 0); Grid.SetRow(btnRow, 1);
            root.Children.Add(lb); root.Children.Add(btnRow);
            dlg.Content = root;

            if (dlg.ShowDialog() == true)
            {
                _selectedDeviceIndex = chosen;
                ActiveInterfacesText.Text = "1";
                if (InterfaceLabel != null)
                    InterfaceLabel.Text = $"Selected: [{chosen}] {Trunc(ifaces[chosen], 100)}  ·  click Start Monitoring";
            }
        }

        private void RuleToggle_Click(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.DataContext is IDSRule rule)
            {
                if (!AllowedTo("ManageIdsRules", "enable/disable IDS rules")) { cb.IsChecked = !(cb.IsChecked == true); return; }
                _engine.ToggleRule(rule.Id, cb.IsChecked == true);
            }
        }

        private void AcknowledgeAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var alert in _filteredAlerts.Where(a => !a.IsAcknowledged).ToList())
            {
                _engine.AcknowledgeAlert(alert.AlertId);
                alert.IsAcknowledged = true;
            }
            ApplyFilters();
        }

        private void PopulateInterfaces()
        {
            try
            {
                var ifaces = _engine.GetInterfaces().ToList();
                if (ActiveInterfacesText != null) ActiveInterfacesText.Text = ifaces.Count.ToString();
                ProtocolAnalysisList.ItemsSource = ifaces.Select((n, i) =>
                    new SigHitItem { Name = Trunc(n, 80), Count = $"[{i}]", Category = "Available" }).ToList();
            }
            catch (Exception ex)
            {
                if (ActiveInterfacesText != null) ActiveInterfacesText.Text = "0";
                ProtocolAnalysisList.ItemsSource = new[] { new SigHitItem { Name = "Run as Administrator", Count = "", Category = ex.Message[..Math.Min(40, ex.Message.Length)] } };
            }
        }

        private static string Trunc(string s, int max) => s?.Length > max ? s[..max] + "…" : s ?? "";

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title    = "Export IDS Report",
                Filter   = "HTML Report (*.html)|*.html",
                FileName = $"IDS_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html"
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                string html = ReportGenerator.GenerateIDSReport(
                    _engine.Alerts, _engine.Rules, _engine.GetStats(), isNids: true);
                File.WriteAllText(dlg.FileName, html, System.Text.Encoding.UTF8);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SwitchToHids_Click(object sender, RoutedEventArgs e)
        {
            _engine.StopCapture();
            _refreshTimer.Stop();
            (Application.Current.MainWindow as MainWindow)?.NavigateDirect(new HostIDSDashboardPage());
        }

        // ── Config import / export ──────────────────────────────────────
        private void ImportConfig_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            { Title = "Import PrivaCore Config", Filter = "JSON config (*.json)|*.json", DefaultExt = ".json" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                string json = File.ReadAllText(dlg.FileName);

                // If the file is a raw rules array (from Export Rules), route it to the rules importer
                if (json.TrimStart().StartsWith("["))
                {
                    var (added, skipped) = _engine.ImportRulesJson(json);
                    RefreshRulesGrid();
                    AppDialog.Show($"Detected rules array — imported as rules.\n\n✓ {added} added\n⊘ {skipped} skipped (duplicate ID)",
                        "Rules Imported", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var cfg = ConfigManager.Deserialize(json);
                if (cfg == null) { AppDialog.Show("Invalid or empty config file.", "Error", MessageBoxButton.OK, MessageBoxImage.Error); return; }
                var (rulesAdded, rulesSkipped, summary) = ConfigManager.Apply(cfg);
                RefreshRulesGrid();
                RefreshAllowlistGrid();
                RefreshBlockedGrid();
                LoadThresholdUI();
                if (_engine.IpsMode && IpsModeToggle != null)
                {
                    IpsModeToggle.Content    = "⚡ IPS ENABLED — Disable";
                    IpsModeToggle.Background = new SolidColorBrush(Color.FromRgb(58, 0, 0)); // intentional: IPS active = dark red
                    IpsModeToggle.Foreground = Br("CriticalBrush");
                }
                AppDialog.Show($"Config '{cfg.Name}' applied successfully.\n\n{summary}",
                    "Config Imported", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Import failed:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportConfig_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            { Title = "Export PrivaCore Config", Filter = "JSON config (*.json)|*.json", FileName = $"PrivaCore_Config_{DateTime.Now:yyyyMMdd_HHmmss}.json" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                var cfg = ConfigManager.Export();
                File.WriteAllText(dlg.FileName, ConfigManager.Serialize(cfg), Encoding.UTF8);
                AppDialog.Show($"Config exported to:\n{dlg.FileName}\n\n{_engine.Rules.Count} rules · {_engine.Allowlist.Count} allowlist entries · HIDS settings included.",
                    "Exported", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ── Alert detail: GeoIP lookup button ───────────────────────────
        private IDSAlert? _selectedAlert;

        private void AlertsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (AlertsList.SelectedItem is not IDSAlert alert) return;
            _selectedAlert = alert;
            DetailPanel.Children.Clear();

            void AddRow(string label, string value, string? color = null)
            {
                var sp = new StackPanel { Margin = new Thickness(0, 0, 0, 6) };
                sp.Children.Add(new TextBlock { Text = label, Foreground = Br("SubtleTextBrush"), FontSize = 10, FontFamily = new FontFamily("Segoe UI"), FontWeight = FontWeights.Bold });
                Brush valueBrush = color != null
                    ? (Brush)(new BrushConverter().ConvertFrom(color) ?? Br("TextBrush"))
                    : Br("TextBrush");
                sp.Children.Add(new TextBlock { Text = value ?? "—", Foreground = valueBrush, FontSize = 12, FontFamily = new FontFamily("Consolas"), TextWrapping = TextWrapping.Wrap });
                DetailPanel.Children.Add(sp);
            }

            var headerBorder = new Border
            {
                Background = (Brush)new BrushConverter().ConvertFrom(alert.SeverityColor)!,
                CornerRadius = new CornerRadius(4), Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 0, 14)
            };
            headerBorder.Child = new TextBlock { Text = $"  {alert.SeverityText.ToUpper()}  —  {alert.AlertType}", Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 13, FontFamily = new FontFamily("Segoe UI") };
            DetailPanel.Children.Add(headerBorder);

            AddRow("TIMESTAMP",        alert.TimestampFormatted);
            AddRow("RULE ID",          alert.RuleId,           "#4FC3F7");
            AddRow("ATTACK CATEGORY",  alert.AttackCategory,   "#CE9178");
            AddRow("SOURCE",           alert.SourceEndpoint,   "#F44747");
            AddRow("DESTINATION",      alert.DstEndpoint,      "#FF8C00");
            AddRow("PROTOCOL",         alert.Protocol);
            AddRow("PACKET SIZE",      alert.PacketSize > 0 ? $"{alert.PacketSize} bytes" : "—");
            AddRow("ACKNOWLEDGED",     alert.IsAcknowledged ? "Yes" : "No", alert.IsAcknowledged ? "#4EC9B0" : "#F44747");
            AddRow("IPS BLOCKED",      alert.IsBlocked ? "Yes — firewall rule added" : "No", alert.IsBlocked ? "#F44747" : "#D4D4D4");

            // JA3 info if present
            if (!string.IsNullOrEmpty(alert.JA3Hash))
                AddRow("JA3 FINGERPRINT", alert.JA3Info ?? alert.JA3Hash, alert.JA3Info?.Contains("MALICIOUS") == true ? "#F44747" : "#CE9178");

            // GeoIP if already enriched
            if (!string.IsNullOrEmpty(alert.Country))
                AddRow("GEO / ISP", $"{alert.Country} ({alert.CountryCode})  ·  {alert.ISP}  ·  {alert.ASN}", "#9CDCFE");

            DetailPanel.Children.Add(new Border { Background = new SolidColorBrush(Col("BorderBrush")), Height = 1, Margin = new Thickness(0,8,0,8) });
            AddRow("DESCRIPTION", alert.Description);

            if (!string.IsNullOrWhiteSpace(alert.PayloadPreview))
            {
                DetailPanel.Children.Add(new TextBlock { Text = "PAYLOAD PREVIEW", Foreground = Br("SubtleTextBrush"), FontSize = 10, FontFamily = new FontFamily("Segoe UI"), FontWeight = FontWeights.Bold, Margin = new Thickness(0,8,0,4) });
                var pb = new Border { Background = new SolidColorBrush(Col("BackgroundBrush")), CornerRadius = new CornerRadius(3), Padding = new Thickness(8), BorderBrush = new SolidColorBrush(Col("BorderBrush")), BorderThickness = new Thickness(1) };
                pb.Child = new TextBlock { Text = alert.PayloadPreview, Foreground = new SolidColorBrush(Col("WarningBrush")), FontFamily = new FontFamily("Consolas"), FontSize = 11, TextWrapping = TextWrapping.Wrap };
                DetailPanel.Children.Add(pb);
            }

            DetailPanel.Children.Add(new Border { Background = new SolidColorBrush(Col("BorderBrush")), Height = 1, Margin = new Thickness(0,10,0,8) });
            string recommendation = alert.AttackCategory switch
            {
                "Web Attack"     => "Block source IP at WAF. Review web server logs for session context. Check for follow-up exploitation.",
                "Brute Force"    => "Block source IP temporarily. Enable account lockout policy. Check for successful logins from this IP.",
                "DoS/DDoS"       => "Apply rate limiting at firewall. Contact upstream provider if traffic is volumetric.",
                "Reconnaissance" => "Log source IP. Consider blocking if repeated. Check for follow-up attack traffic.",
                "Malware/C2"     => "ISOLATE HOST IMMEDIATELY. Run forensic analysis. Check all outbound connections from this host.",
                "Exploit"        => "Patch immediately. Isolate affected systems. Investigate for indicators of compromise.",
                "Exfiltration"   => "Block outbound connection. Review what data may have been sent. Check DNS logs.",
                "MITM"           => "Check ARP tables. Enable Dynamic ARP Inspection on switch. Identify attacker machine.",
                "Kill Chain"     => "ACTIVE ATTACK IN PROGRESS. Isolate source IP immediately. Escalate to incident response.",
                "Remote Access"  => "Verify if authorised. If unexpected, treat as compromise — isolate and investigate.",
                _                => "Review alert details. Cross-reference with other alerts from same source IP."
            };
            AddRow("RECOMMENDED ACTION", recommendation, "#DCDCAA");

            // GeoIP lookup button
            var geoBtn = new Button
            {
                Content = string.IsNullOrEmpty(alert.Country) ? "🌍 Lookup GeoIP" : "↺ Re-lookup GeoIP",
                Margin = new Thickness(0, 10, 0, 0), Padding = new Thickness(10, 6, 10, 6),
                Background = Br("SecondaryBackgroundBrush"),
                Foreground = Br("AccentBrush"),
                BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1),
                Cursor = System.Windows.Input.Cursors.Hand, FontFamily = new FontFamily("Segoe UI"), FontSize = 11,
                HorizontalAlignment = HorizontalAlignment.Left
            };
            geoBtn.Template = SimpleButtonTemplate();
            geoBtn.Click += async (_, __) => await LookupGeoIp(alert, geoBtn);
            DetailPanel.Children.Add(geoBtn);

            // Quick-block button for Critical/High alerts
            if (alert.Severity >= IDSAlertSeverity.High && !alert.IsBlocked)
            {
                var blockBtn = new Button
                {
                    Content = $"🚫 Block {alert.SourceIP}", Margin = new Thickness(0, 6, 0, 0),
                    Padding = new Thickness(10, 6, 10, 6),
                    Background = new SolidColorBrush(Color.FromRgb(58, 0, 0)), // intentional: danger action = dark red
                    Foreground = Br("CriticalBrush"),
                    BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1),
                    Cursor = System.Windows.Input.Cursors.Hand, FontFamily = new FontFamily("Segoe UI"), FontSize = 11,
                    HorizontalAlignment = HorizontalAlignment.Left
                };
                blockBtn.Template = SimpleButtonTemplate();
                blockBtn.Click += (_, __) =>
                {
                    if (_engine.ManualBlock(alert.SourceIP, alert.AlertType, out string err))
                    {
                        alert.IsBlocked = true;
                        blockBtn.IsEnabled = false;
                        blockBtn.Content = $"✔ Blocked {alert.SourceIP}";
                        RefreshBlockedGrid();
                    }
                    else AppDialog.Show($"Block failed: {err}\n\nTip: Run as Administrator.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                };
                DetailPanel.Children.Add(blockBtn);
            }
        }

        private static ControlTemplate SimpleButtonTemplate()
        {
            var t = new ControlTemplate(typeof(Button));
            var bd = new FrameworkElementFactory(typeof(Border));
            bd.SetBinding(Border.BackgroundProperty, new System.Windows.Data.Binding("Background") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            bd.SetBinding(Border.BorderBrushProperty, new System.Windows.Data.Binding("BorderBrush") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            bd.SetBinding(Border.BorderThicknessProperty, new System.Windows.Data.Binding("BorderThickness") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            bd.SetBinding(Border.PaddingProperty, new System.Windows.Data.Binding("Padding") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            var cp = new FrameworkElementFactory(typeof(ContentPresenter));
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            bd.AppendChild(cp);
            t.VisualTree = bd;
            return t;
        }

        private async Task LookupGeoIp(IDSAlert alert, Button btn)
        {
            btn.IsEnabled = false;
            btn.Content = "Looking up…";
            try
            {
                var result = await GeoIpService.LookupAsync(alert.SourceIP);
                if (result.Success)
                {
                    alert.Country     = result.Country;
                    alert.CountryCode = result.CountryCode;
                    alert.ISP         = result.ISP;
                    alert.ASN         = result.ASN;
                    btn.Content = $"✔ {result.Country} ({result.CountryCode})  ·  {result.ISP}";
                }
                else
                {
                    btn.Content = result.Country == "Private/Local" ? "🏠 Private/Local IP" : "✗ Lookup failed";
                }
            }
            catch { btn.Content = "✗ Lookup failed"; }
            finally { btn.IsEnabled = true; }
        }

        // ── Kill chain event from engine ────────────────────────────────
        private void OnKillChainDetected(object? sender, CorrelationGroup group)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (KillChainBanner != null)
                    KillChainBanner.Text = $"⚠ KILL CHAIN DETECTED from {group.SourceIP} — {group.Categories} — {group.AlertCount} alerts in last 5 min";
                AlertToast.Show("Kill Chain Detected!", $"{group.SourceIP} — {group.Categories}", "#F44747");
                RefreshCorrelation();
            });
        }

        // ── Snort/Suricata rule import ──────────────────────────────────
        private void ImportSnortRules_Click(object sender, RoutedEventArgs e)
        {
            if (!AllowedTo("ManageIdsRules", "import IDS rules")) return;
            var dlg = new Microsoft.Win32.OpenFileDialog
            { Title = "Import Snort/Suricata Rules", Filter = "Rules files (*.rules;*.txt)|*.rules;*.txt|All files (*.*)|*.*", DefaultExt = ".rules" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                string content = File.ReadAllText(dlg.FileName);
                var (rules, errors) = SnortRuleParser.ParseFile(content);
                int added = 0, skipped = 0;
                foreach (var r in rules)
                {
                    if (_engine.Rules.Any(x => x.RuleId == r.RuleId)) { skipped++; continue; }
                    _engine.AddRule(r); added++;
                }
                RefreshRulesGrid();
                string msg = $"Snort/Suricata import complete.\n\n✓ {added} rules added\n⊘ {skipped} skipped (duplicate SID)";
                if (errors.Count > 0)
                    msg += $"\n\n⚠ {errors.Count} parse errors:\n" + string.Join("\n", errors.Take(5));
                AppDialog.Show(msg, "Import Snort Rules", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Import failed:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ── Reset rules: use public method instead of reflection ─────────
        private void ResetDefaultRules_Click(object sender, RoutedEventArgs e)
        {
            if (!AllowedTo("ManageIdsRules", "reset IDS rules")) return;
            if (AppDialog.Show("Reset all rules to factory defaults?\n\nAll custom rules will be removed.",
                    "Reset Rules", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            _engine.ResetToDefaults();
            RefreshRulesGrid();
        }

        // ── Correlation ─────────────────────────────────────────────────
        private void RefreshCorrelation()
        {
            var groups = _engine.GetCorrelationGroups();
            _corrItems.Clear();
            foreach (var g in groups) _corrItems.Add(g);
            if (CorrCountText    != null) CorrCountText.Text    = groups.Count.ToString();
            int killChains = groups.Count(g => g.IsKillChain);
            if (KillChainBanner  != null && killChains == 0 && string.IsNullOrEmpty(KillChainBanner.Text))
                KillChainBanner.Text = "";
        }

        private void RefreshCorrelation_Click(object sender, RoutedEventArgs e) => RefreshCorrelation();

        // ── Allowlist ────────────────────────────────────────────────────
        private void RefreshAllowlistGrid()
        {
            _allowlistItems.Clear();
            foreach (var e in _engine.Allowlist) _allowlistItems.Add(e);
            if (AllowlistCountText != null) AllowlistCountText.Text = _allowlistItems.Count.ToString();
        }

        private void AllowlistGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (RemoveAllowlistBtn != null) RemoveAllowlistBtn.IsEnabled = AllowlistGrid?.SelectedItem is AllowlistEntry;
        }

        private void AddAllowlist_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Window
            {
                Title = "Add Allowlist Entry", Width = 440, Height = 260,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Window.GetWindow(this),
                Background = new SolidColorBrush(Col("BackgroundBrush")), ResizeMode = ResizeMode.NoResize
            };
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(new TextBlock { Text = "IP Address or CIDR (e.g. 192.168.1.5 or 10.0.0.0/8)", Foreground = Br("SubtleTextBrush"), FontSize = 10, FontFamily = new FontFamily("Segoe UI"), FontWeight = FontWeights.Bold, Margin = new Thickness(0,0,0,3) });
            var ipBox = new TextBox { Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")), Foreground = new SolidColorBrush(Col("TextBrush")), BorderBrush = new SolidColorBrush(Col("BorderBrush")), BorderThickness = new Thickness(1), Padding = new Thickness(8,5,8,5), FontFamily = new FontFamily("Consolas"), FontSize = 12, Margin = new Thickness(0,0,0,10) };
            sp.Children.Add(ipBox);
            sp.Children.Add(new TextBlock { Text = "Rule ID to suppress (leave blank = suppress ALL rules)", Foreground = Br("SubtleTextBrush"), FontSize = 10, FontFamily = new FontFamily("Segoe UI"), FontWeight = FontWeights.Bold, Margin = new Thickness(0,0,0,3) });
            var ruleBox = new TextBox { Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")), Foreground = new SolidColorBrush(Col("TextBrush")), BorderBrush = new SolidColorBrush(Col("BorderBrush")), BorderThickness = new Thickness(1), Padding = new Thickness(8,5,8,5), FontFamily = new FontFamily("Consolas"), FontSize = 12, Margin = new Thickness(0,0,0,10) };
            sp.Children.Add(ruleBox);
            sp.Children.Add(new TextBlock { Text = "Note", Foreground = Br("SubtleTextBrush"), FontSize = 10, FontFamily = new FontFamily("Segoe UI"), FontWeight = FontWeights.Bold, Margin = new Thickness(0,0,0,3) });
            var noteBox = new TextBox { Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")), Foreground = new SolidColorBrush(Col("TextBrush")), BorderBrush = new SolidColorBrush(Col("BorderBrush")), BorderThickness = new Thickness(1), Padding = new Thickness(8,5,8,5), FontFamily = new FontFamily("Segoe UI"), FontSize = 12, Margin = new Thickness(0,0,0,14) };
            sp.Children.Add(noteBox);
            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var btnOk  = new Button { Content = "Add", Width = 80, Height = 28, Background = Br("AccentBrush"), Foreground = Brushes.White, BorderThickness = new Thickness(0), Margin = new Thickness(0,0,8,0) };
            btnOk.Click += (_, __) =>
            {
                string ip = ipBox.Text.Trim();
                if (string.IsNullOrEmpty(ip)) { AppDialog.Show("IP/CIDR is required.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
                _engine.AddAllowlistEntry(new AllowlistEntry { IpOrCidr = ip, RuleId = string.IsNullOrWhiteSpace(ruleBox.Text) ? null : ruleBox.Text.Trim(), Note = noteBox.Text.Trim() });
                RefreshAllowlistGrid();
                dlg.Close();
            };
            var btnCancel = new Button { Content = "Cancel", Width = 80, Height = 28, Background = new SolidColorBrush(Col("SecondaryBackgroundBrush")), Foreground = new SolidColorBrush(Col("TextBrush")), BorderThickness = new Thickness(1), BorderBrush = new SolidColorBrush(Col("BorderBrush")) };
            btnCancel.Click += (_, __) => dlg.Close();
            btnRow.Children.Add(btnOk); btnRow.Children.Add(btnCancel);
            sp.Children.Add(btnRow);
            dlg.Content = sp; dlg.ShowDialog();
        }

        private void RemoveAllowlist_Click(object sender, RoutedEventArgs e)
        {
            if (AllowlistGrid?.SelectedItem is not AllowlistEntry entry) return;
            _engine.RemoveAllowlistEntry(entry.Id);
            RefreshAllowlistGrid();
        }

        // ── IPS / Blocked IPs ───────────────────────────────────────────
        private void RefreshBlockedGrid()
        {
            _blockedItems.Clear();
            foreach (var b in _engine.Blocked) _blockedItems.Add(b);
            if (BlockedCountText != null) BlockedCountText.Text = _blockedItems.Count.ToString();
        }

        private void ToggleIpsMode_Click(object sender, RoutedEventArgs e)
        {
            _engine.IpsMode = !_engine.IpsMode;
            if (IpsModeToggle != null)
            {
                IpsModeToggle.Content = _engine.IpsMode ? "⚡ IPS ENABLED — Disable" : "Enable IPS";
                IpsModeToggle.Background = new SolidColorBrush(_engine.IpsMode ? Color.FromRgb(58,0,0) : Color.FromRgb(27,67,50));
                IpsModeToggle.Foreground = new SolidColorBrush(_engine.IpsMode ? Color.FromRgb(244,71,71) : Color.FromRgb(74,222,128));
            }
            if (IpsStatusText != null)
                IpsStatusText.Text = _engine.IpsMode
                    ? "IPS ACTIVE — Critical alerts will auto-block source IP via Windows Firewall"
                    : "IPS disabled — detection only";
        }

        private void ManualBlock_Click(object sender, RoutedEventArgs e)
        {
            string ip = ManualBlockIpBox?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(ip)) return;
            if (_engine.ManualBlock(ip, "Manual block", out string err))
            {
                if (IpsStatusText != null) IpsStatusText.Text = $"✔ Blocked {ip}";
                if (ManualBlockIpBox != null) ManualBlockIpBox.Text = "";
                RefreshBlockedGrid();
            }
            else
            {
                AppDialog.Show($"Block failed: {err}\n\nTip: Run as Administrator.", "Block Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UnblockOne_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string ip)
            {
                if (_engine.ManualUnblock(ip, out string err))
                {
                    if (IpsStatusText != null) IpsStatusText.Text = $"✔ Unblocked {ip}";
                    RefreshBlockedGrid();
                }
                else AppDialog.Show($"Unblock failed: {err}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UnblockAll_Click(object sender, RoutedEventArgs e)
        {
            if (AppDialog.Show("Remove all Windows Firewall block rules added by PrivaCore?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            foreach (var b in _engine.Blocked.ToList())
                _engine.ManualUnblock(b.IP, out _);
            RefreshBlockedGrid();
            if (IpsStatusText != null) IpsStatusText.Text = "✔ All blocks removed";
        }

        // ── Timeline ────────────────────────────────────────────────────
        private void RefreshTimeline()
        {
            if (TimelineChart == null) return;
            var alerts = _engine.Alerts.ToList();
            var buckets = new List<TimelineBucket>();
            var now = DateTime.Now;

            for (int h = 23; h >= 0; h--)
            {
                var start = now.AddHours(-h - 1);
                var end   = now.AddHours(-h);
                var inHour = alerts.Where(a => a.Timestamp >= start && a.Timestamp < end).ToList();
                int count = inHour.Count;

                string color = count == 0 ? "#252525" :
                    inHour.Any(a => a.Severity == IDSAlertSeverity.Critical) ? "#F44747" :
                    inHour.Any(a => a.Severity == IDSAlertSeverity.High)     ? "#FF8C00" :
                    inHour.Any(a => a.Severity == IDSAlertSeverity.Medium)   ? "#FFA500" : "#4EC9B0";

                int maxCount = alerts.Count > 0 ? Math.Max(1, alerts.GroupBy(a => a.Timestamp.Hour).Max(g => g.Count())) : 1;
                double barH  = count == 0 ? 4 : Math.Max(8, (double)count / maxCount * 140);

                string maxSev = inHour.Count == 0 ? "none" :
                    inHour.Any(a => a.Severity == IDSAlertSeverity.Critical) ? "CRITICAL" :
                    inHour.Any(a => a.Severity == IDSAlertSeverity.High)     ? "HIGH" : "other";

                buckets.Add(new TimelineBucket
                {
                    Hour    = start.ToString("HH:00"),
                    Count   = count,
                    Color   = color,
                    BarHeight = barH,
                    Tooltip = $"{start:HH:00}–{end:HH:00}\n{count} alerts\nMax severity: {maxSev}"
                });
            }

            TimelineChart.ItemsSource = buckets;
        }

        private void RefreshTimeline_Click(object sender, RoutedEventArgs e) => RefreshTimeline();

        // ══════════════════════════════════════════════════════════════════
        // LIVE TRAFFIC GRAPH
        // ══════════════════════════════════════════════════════════════════

        // ── Theme-aware color helpers ────────────────────────────────────────
        private static SolidColorBrush Br(string key) =>
            Application.Current.Resources[key] as SolidColorBrush
            ?? new SolidColorBrush(Colors.Gray);

        private static Color Col(string key) =>
            (Application.Current.Resources[key] as SolidColorBrush)?.Color
            ?? Colors.Gray;

        private void InitGraph()
        {
            if (TrafficCanvas == null) return;

            // Packet-rate fill (semi-transparent accent area under the line)
            var ac = Col("AccentBrush");
            _pktFill = new Polygon
            {
                Fill = new SolidColorBrush(Color.FromArgb(28, ac.R, ac.G, ac.B)),
                StrokeThickness = 0
            };

            // Packet-rate line
            _pktLine = new Polyline
            {
                Stroke = Br("AccentBrush"),
                StrokeThickness = 1.5,
                StrokeLineJoin = PenLineJoin.Round,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            };

            // Alert-rate line (thinner, critical color)
            _alertLine = new Polyline
            {
                Stroke = Br("CriticalBrush"),
                StrokeThickness = 1,
                StrokeLineJoin = PenLineJoin.Round
            };

            TrafficCanvas.Children.Add(_pktFill);
            TrafficCanvas.Children.Add(_pktLine);
            TrafficCanvas.Children.Add(_alertLine);
        }

        // Called from SizeChanged XAML event
        private void TrafficCanvas_SizeChanged(object sender, SizeChangedEventArgs e) => RedrawGraph();

        // Called every 2s from RefreshUI (already on UI thread via DispatcherTimer)
        private void UpdateGraphData(IDSStats stats)
        {
            // Compute deltas
            long   pktDelta   = stats.TotalPackets - _graphLastPktCount;
            int    alertCount = stats.TotalAlerts;
            int    alertDelta = Math.Max(0, alertCount - _graphLastAlertCount);
            double pktPerSec  = pktDelta / Math.Max(1.0, _refreshTimer.Interval.TotalSeconds);

            _graphLastPktCount  = stats.TotalPackets;
            _graphLastAlertCount = alertCount;

            _graphBuffer.Enqueue(new GraphPoint(pktPerSec, alertDelta, DateTime.Now));
            if (_graphBuffer.Count > GraphCapacity) _graphBuffer.Dequeue();

            RedrawGraph();

            // Update live-value labels
            if (GraphPktRate   != null) GraphPktRate.Text   = $"{pktPerSec:F0} pkt/s";
            if (GraphAlertRate != null) GraphAlertRate.Text = $"{alertDelta} /s";
            if (GraphTimespan  != null)
            {
                int secs = (int)(_graphBuffer.Count * _refreshTimer.Interval.TotalSeconds);
                GraphTimespan.Text = secs >= 60 ? $"last {secs/60}m {secs%60}s" : $"last {secs}s";
            }
        }

        private void RedrawGraph()
        {
            if (TrafficCanvas == null || _pktLine == null || _pktFill == null || _alertLine == null) return;

            double w = TrafficCanvas.ActualWidth;
            double h = TrafficCanvas.ActualHeight;
            if (w < 2 || h < 2) return;

            var pts = _graphBuffer.ToArray();
            if (pts.Length == 0)
            {
                _pktLine.Points  = new PointCollection();
                _pktFill.Points  = new PointCollection();
                _alertLine.Points = new PointCollection();
                return;
            }

            // ── Scale ──────────────────────────────────────────────────────
            double maxPkt   = Math.Max(1, pts.Max(p => p.PktPerSec));
            double maxAlert = Math.Max(1, pts.Max(p => p.AlertDelta));
            const double pad = 0.12; // 12% top padding so line doesn't touch the top edge

            // ── Gridlines ─────────────────────────────────────────────────
            // Remove old gridlines (they're added after the pre-created elements)
            while (TrafficCanvas.Children.Count > 3)
                TrafficCanvas.Children.RemoveAt(3);

            for (int gi = 1; gi <= 3; gi++)
            {
                double gy = h * gi / 4.0;
                var gl = new Line
                {
                    X1 = 0, Y1 = gy, X2 = w, Y2 = gy,
                    Stroke = new SolidColorBrush(Col("BorderBrush")),
                    StrokeThickness = 1,
                    StrokeDashArray = new DoubleCollection { 4, 4 }
                };
                TrafficCanvas.Children.Add(gl);
            }

            // ── Map data → pixel points ────────────────────────────────────
            double step = w / Math.Max(1, GraphCapacity - 1);

            var pktPts   = new PointCollection(pts.Length);
            var alertPts = new PointCollection(pts.Length);

            for (int i = 0; i < pts.Length; i++)
            {
                // X: right-align — newest point is always at the far right
                double x = w - (pts.Length - 1 - i) * step;

                double pktY   = h - h * (1 - pad) * (pts[i].PktPerSec  / maxPkt);
                double alertY = h - h * (1 - pad) * (pts[i].AlertDelta  / maxAlert);

                pktPts.Add(new Point(x, pktY));
                alertPts.Add(new Point(x, alertY));
            }

            // Packet-rate line
            _pktLine.Points = pktPts;

            // Fill polygon: line points + bottom-right + bottom-left
            var fillPts = new PointCollection(pktPts);
            fillPts.Add(new Point(pktPts[pktPts.Count - 1].X, h));
            fillPts.Add(new Point(pktPts[0].X, h));
            _pktFill.Points = fillPts;

            // Alert spikes (only draw if any alerts happened)
            if (pts.Any(p => p.AlertDelta > 0))
                _alertLine.Points = alertPts;
            else
                _alertLine.Points = new PointCollection();

            // ── Y-axis labels ──────────────────────────────────────────────
            if (YAxisCanvas != null)
            {
                YAxisCanvas.Children.Clear();
                double yh = YAxisCanvas.ActualHeight;
                if (yh > 0)
                {
                    for (int li = 0; li <= 3; li++)
                    {
                        double labelY = yh * li / 4.0;
                        double value  = maxPkt * (1.0 - (double)li / 4.0);
                        var tb = new TextBlock
                        {
                            Text       = value >= 1000 ? $"{value/1000:F0}k" : $"{value:F0}",
                            Foreground = new SolidColorBrush(Col("SubtleTextBrush")),
                            FontSize   = 9,
                            FontFamily = new FontFamily("Consolas")
                        };
                        Canvas.SetTop(tb, labelY - 6);
                        Canvas.SetRight(tb, 2);
                        YAxisCanvas.Children.Add(tb);
                    }
                }
            }
        }
    }

    public class TrafficSummaryItem { public string Category { get; set; } = ""; public int Count { get; set; } public string LastSeen { get; set; } = ""; }
    public class SigHitItem         { public string Name { get; set; } = "";     public string Count { get; set; } = ""; public string Category { get; set; } = ""; }
}
