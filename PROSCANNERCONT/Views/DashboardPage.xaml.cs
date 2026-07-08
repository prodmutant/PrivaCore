using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Security;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    // -------------------------------------------------------------------------
    // View-model helper classes
    // -------------------------------------------------------------------------
    public class QueryResultItem
    {
        public string Time        { get; set; }
        public string Module      { get; set; }
        public string Status      { get; set; }
        public string Title       { get; set; }
        public string Description { get; set; }
        public Brush  StatusColor { get; set; }
    }

    public class ActivityFeedItem
    {
        public DateTime Timestamp   { get; set; }
        public string   TimeText    { get; set; }
        public string   Module      { get; set; }
        public string   ModuleShort { get; set; }
        public Brush    ModuleColor { get; set; }
        public string   Title       { get; set; }
        public string   Description { get; set; }
        public string   Status      { get; set; }
        public Brush    StatusBrush { get; set; }
        public ScanResult SourceScanResult { get; set; }
    }

    public class ThreatItem
    {
        public string SeverityText  { get; set; }
        public string SeverityColor { get; set; }
        public Brush  SeverityBrush { get; set; }
        public string Source        { get; set; }
        public string Category      { get; set; }
        public string Description   { get; set; }
        public string Time          { get; set; }
        public string Module        { get; set; }
        public bool   IsAcknowledged{ get; set; }
    }

    public class ModuleStatusItem
    {
        public string ModuleName  { get; set; }
        public string StatusText  { get; set; }
        public string StatusDot   { get; set; } = "â—";
        public Brush  DotColor    { get; set; }
        public string LastActivity{ get; set; }
        public string IconKind    { get; set; }
    }

    // -------------------------------------------------------------------------
    // DashboardPage code-behind
    // -------------------------------------------------------------------------
    public partial class DashboardPage : Page, INotifyPropertyChanged
    {
        // ---- services -------------------------------------------------------
        private readonly StateService _stateService;

        // ---- data stores ----------------------------------------------------
        private ObservableCollection<ScanResult>    _scanResults;
        private Dictionary<DateTime, List<ScanResult>> _scanHistory;

        // ---- bound collections ----------------------------------------------
        public ObservableCollection<QueryResultItem>  QueryResults { get; } = new();
        public ObservableCollection<ThreatItem>       ThreatsView  { get; } = new();

        // ---- UI state -------------------------------------------------------
        private int     _currentTabIndex = 0;
        private string  _activityModuleFilter = "All";
        private string  _threatSeverityFilter = "All";
        private DispatcherTimer _autoRefreshTimer;
        private DispatcherTimer _rebuildDebounce;
        private DispatcherTimer _fastRefreshTimer;

        // ---- preserved brushes ----------------------------------------------
        private readonly SolidColorBrush GreenBrush  = new(Color.FromRgb( 76, 175,  80));
        private readonly SolidColorBrush YellowBrush = new(Color.FromRgb(255, 193,   7));
        private readonly SolidColorBrush RedBrush    = new(Color.FromRgb(244,  67,  54));

        // ---- old dashboard state kept for compat ----------------------------
        private Dictionary<string, Status> _hostStatuses = new();

        // ---- IDS alert sound tracking ----------------------------------------
        private int _lastKnownAlertCount = 0;

        // =========================================================================
        // Constructor
        // =========================================================================
        public DashboardPage()
        {
            InitializeComponent();
            DataContext = this;

            _stateService = StateService.Instance;
            _stateService.LoadNetworkScanResults();
            _stateService.LoadScanResults();

            try { _stateService.LoadHostCount(); } catch { /* optional */ }

            _scanHistory = ScanHistoryManager.LoadScanHistory();
            _scanResults = new ObservableCollection<ScanResult>();

            // Wire collection-changed events â€” debounced so rapid scans don't cause rebuild storms
            _stateService.NetworkScanResults.CollectionChanged += (s, e) => ScheduleDebouncedRefresh();
            _stateService.RecentScanResults.CollectionChanged  += (s, e) => ScheduleDebouncedRefresh();

            // Setup auto-refresh every 30 s
            _autoRefreshTimer          = new DispatcherTimer();
            _autoRefreshTimer.Interval = TimeSpan.FromSeconds(30);
            _autoRefreshTimer.Tick    += (s, e) => RefreshDashboard();
            _autoRefreshTimer.Start();

            // Fast timer (5 s) â€” refreshes live widgets in-place without full panel rebuild
            _fastRefreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            _fastRefreshTimer.Tick += (s, e) =>
            {
                UpdateSecurityStatusBar();
                var liveTypes = new[] { WidgetType.IDSAlerts, WidgetType.LiveTraffic, WidgetType.AlertTrend, WidgetType.HoneypotActivity, WidgetType.TrafficStats };
                foreach (var wt in liveTypes)
                {
                    var w = _widgets.FirstOrDefault(x => x.Type == wt && x.Visible && !_detachedWindows.ContainsKey(x.Type));
                    if (w != null) RefreshWidgetContent(w);
                }
            };
            _fastRefreshTimer.Start();

            // Initial data load
            RefreshRecentFindings();
            RecentVulnerabilities.ItemsSource = _scanResults;
            InitializeCalendar();
            RefreshDashboard();
            LoadWidgets();
            UpdateSecurityStatusBar();
        }

        // =========================================================================
        // Tab switching
        // =========================================================================
        private void Tab_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.Tag is string tagStr && int.TryParse(tagStr, out int idx))
                SwitchTab(idx);
        }

        private void SwitchTab(int tabIndex)
        {
            _currentTabIndex = tabIndex;

            OverviewTab.Visibility  = tabIndex == 0 ? Visibility.Visible : Visibility.Collapsed;
            AnalyticsTab.Visibility = tabIndex == 1 ? Visibility.Visible : Visibility.Collapsed;
            ActivityTab.Visibility  = tabIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
            ThreatsTab.Visibility   = tabIndex == 3 ? Visibility.Visible : Visibility.Collapsed;
            QueryTab.Visibility     = tabIndex == 4 ? Visibility.Visible : Visibility.Collapsed;

            if (tabIndex == 1)
            {
                // Defer chart draw so canvas has layout pass
                Dispatcher.BeginInvoke(DrawAllCharts, DispatcherPriority.Loaded);
            }
            if (tabIndex == 2)  RefreshActivityFeed();
            if (tabIndex == 3)  RefreshThreatsGrid();
        }

        // =========================================================================
        // Main refresh
        // =========================================================================
        public void RefreshDashboard()
        {
            try
            {
                RefreshKPIs();
                RefreshModuleStatus();
                RefreshRecentFindings();
                RefreshAllWidgetContents();
                UpdateSecurityStatusBar();
                CheckAndPlayAlertSound();

                if (_currentTabIndex == 1) DrawAllCharts();
                if (_currentTabIndex == 2) RefreshActivityFeed();
                if (_currentTabIndex == 3) RefreshThreatsGrid();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Dashboard] RefreshDashboard error: {ex.Message}");
            }
        }

        private void ScheduleDebouncedRefresh()
        {
            if (_rebuildDebounce == null)
            {
                _rebuildDebounce = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
                _rebuildDebounce.Tick += (_, __) => { _rebuildDebounce.Stop(); RefreshDashboard(); };
            }
            _rebuildDebounce.Stop();
            _rebuildDebounce.Start();
        }

        private void UpdateSecurityStatusBar()
        {
            if (SecurityStatusStrip == null) return;
            try
            {
                bool idsRunning = false; int critHigh = 0;
                try { idsRunning = IDSManager.Engine.IsRunning; var st = IDSManager.Engine.GetStats(); critHigh = st.CriticalAlerts + st.HighAlerts; } catch { }

                bool capturing = false;
                try { capturing = TrafficCaptureService.Instance.IsCapturing; } catch { }

                int hosts = _stateService.NetworkScanResults.Count;

                var sp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

                void AddSep()
                {
                    sp.Children.Add(new Border
                    {
                        Width = 1, Height = 14, VerticalAlignment = VerticalAlignment.Center,
                        Background = W_Border(), Margin = new Thickness(12, 0, 12, 0)
                    });
                }

                void AddPill(string dot, string label, Brush dotColor)
                {
                    var row = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                    row.Children.Add(new TextBlock { Text = dot, FontSize = 9, Foreground = dotColor, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 5, 0) });
                    row.Children.Add(new TextBlock { Text = label, FontSize = 10, Foreground = W_TextBrush(), Opacity = 0.85, VerticalAlignment = VerticalAlignment.Center });
                    sp.Children.Add(row);
                }

                var greenBrush  = new SolidColorBrush(Color.FromRgb( 76, 175,  80));
                var yellowBrush = new SolidColorBrush(Color.FromRgb(255, 193,   7));
                var grayBrush   = new SolidColorBrush(Color.FromRgb(120, 120, 120));
                var blueBrush   = new SolidColorBrush(Color.FromRgb( 33, 150, 243));

                AddPill(idsRunning ? "â—" : "â—‹", idsRunning ? "IDS Running" : "IDS Stopped",   idsRunning ? greenBrush : yellowBrush);
                AddSep();
                AddPill(capturing  ? "â—" : "â—‹", capturing  ? "Capture Live" : "Capture Idle", capturing  ? greenBrush : grayBrush);
                AddSep();
                AddPill("â—‰", $"{hosts} Host{(hosts == 1 ? "" : "s")}", blueBrush);

                if (critHigh > 0)
                {
                    AddSep();
                    var badge = new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(244, 67, 54)),
                        CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 2, 8, 2),
                        VerticalAlignment = VerticalAlignment.Center,
                        Child = new TextBlock
                        {
                            Text = $"âš   {critHigh} Critical / High",
                            FontSize = 10, FontWeight = FontWeights.SemiBold,
                            Foreground = Brushes.White
                        }
                    };
                    sp.Children.Add(badge);
                }

                SecurityStatusStrip.Child = sp;
            }
            catch { }
        }

        private void CheckAndPlayAlertSound()
        {
            if (!SettingsPage.AlertSoundsEnabled) return;
            try
            {
                int critHigh = 0;
                try
                {
                    var stats = IDSManager.Engine.GetStats();
                    critHigh = stats.CriticalAlerts + stats.HighAlerts;
                }
                catch { return; }

                if (critHigh > _lastKnownAlertCount)
                    System.Media.SystemSounds.Exclamation.Play();

                _lastKnownAlertCount = critHigh;
            }
            catch { }
        }

        // =========================================================================
        // KPI Cards
        // =========================================================================
        private void RefreshKPIs()
        {
            // Total scans
            var historyScans = _scanHistory.Values.SelectMany(v => v).ToList();
            var allScans = historyScans.Concat(_stateService.RecentScanResults).ToList();
            KpiTotalScans.Text = allScans.Count.ToString();

            // Critical threats (IDS critical + high)
            try
            {
                var stats = IDSManager.Engine.GetStats();
                KpiCriticalThreats.Text = (stats.CriticalAlerts + stats.HighAlerts).ToString();
            }
            catch { KpiCriticalThreats.Text = "?"; }

            // Hosts discovered
            KpiHostsDiscovered.Text = _stateService.NetworkScanResults.Count.ToString();

            // Open ports â€” extracted from port scan result descriptions
            var allScansForPorts = _scanHistory.Values.SelectMany(v => v)
                .Concat(_stateService.RecentScanResults)
                .Where(r => r.Type != null && r.Type.Contains("Port", StringComparison.OrdinalIgnoreCase))
                .ToList();
            int portCount = allScansForPorts
                .Sum(r => r.Details?.Count(d => d.Contains("Open Port", StringComparison.OrdinalIgnoreCase)) ?? 0);
            KpiOpenPorts.Text = portCount.ToString();

            // Traffic packets
            try
            {
                KpiTrafficPackets.Text = TrafficCaptureService.Instance.Statistics.TotalPackets.ToString("N0");
            }
            catch { KpiTrafficPackets.Text = "0"; }

            // Security score: kept in SecurityScoreText (updated by UpdateSecurityScore)
        }

        // =========================================================================
        // Module Status
        // =========================================================================
        private void RefreshModuleStatus()
        {
            var items = new List<ModuleStatusItem>();

            // Port Scanner
            var portScans = _stateService.RecentScanResults.Count(r =>
                r.Type.Contains("Port", StringComparison.OrdinalIgnoreCase));
            items.Add(new ModuleStatusItem
            {
                ModuleName   = "Port Scanner",
                StatusText   = portScans > 0 ? "Active" : "Idle",
                DotColor     = portScans > 0 ? GreenBrush : YellowBrush,
                LastActivity = $"{portScans} scans",
                IconKind     = "NetworkWired"
            });

            // Network Discovery
            var hostCount = _stateService.NetworkScanResults.Count;
            items.Add(new ModuleStatusItem
            {
                ModuleName   = "Network Discovery",
                StatusText   = hostCount > 0 ? "Active" : "Idle",
                DotColor     = hostCount > 0 ? GreenBrush : YellowBrush,
                LastActivity = $"{hostCount} hosts",
                IconKind     = "Globe"
            });

            // Traffic Analysis
            bool isCapturing = false;
            long pktCount    = 0;
            try
            {
                isCapturing = TrafficCaptureService.Instance.IsCapturing;
                pktCount    = TrafficCaptureService.Instance.Statistics.TotalPackets;
            }
            catch { }
            items.Add(new ModuleStatusItem
            {
                ModuleName   = "Traffic Analysis",
                StatusText   = isCapturing ? "Capturing" : "Idle",
                DotColor     = isCapturing ? GreenBrush : YellowBrush,
                LastActivity = $"{pktCount:N0} pkts",
                IconKind     = "Wifi"
            });

            // IDS
            bool idsRunning  = false;
            int  idsAlerts   = 0;
            try
            {
                idsRunning = IDSManager.Engine.IsRunning;
                idsAlerts  = IDSManager.Engine.Alerts.Count;
            }
            catch { }
            items.Add(new ModuleStatusItem
            {
                ModuleName   = "IDS Engine",
                StatusText   = idsRunning ? "Running" : "Stopped",
                DotColor     = idsAlerts > 0 ? RedBrush : (idsRunning ? GreenBrush : YellowBrush),
                LastActivity = $"{idsAlerts} alerts",
                IconKind     = "Shield"
            });

            // Vulnerability
            var vulnScans = _stateService.RecentScanResults.Count(r =>
                r.Type.Contains("Vuln", StringComparison.OrdinalIgnoreCase) ||
                r.Type.Contains("CVE",  StringComparison.OrdinalIgnoreCase));
            items.Add(new ModuleStatusItem
            {
                ModuleName   = "Vulnerability Scanner",
                StatusText   = vulnScans > 0 ? "Active" : "Idle",
                DotColor     = vulnScans > 0 ? YellowBrush : GreenBrush,
                LastActivity = $"{vulnScans} scans",
                IconKind     = "Bug"
            });

            // Security Check
            var secScans = _stateService.RecentScanResults.Count(r =>
                r.Type.Contains("Security", StringComparison.OrdinalIgnoreCase));
            items.Add(new ModuleStatusItem
            {
                ModuleName   = "Security Check",
                StatusText   = secScans > 0 ? "Done" : "Idle",
                DotColor     = secScans > 0 ? GreenBrush : YellowBrush,
                LastActivity = $"{secScans} checks",
                IconKind     = "ShieldHalved"
            });

            ModuleStatusList.ItemsSource = items;
        }

        // =========================================================================
        // Recent Findings (Overview tab)
        // =========================================================================
        private void RefreshRecentFindings()
        {
            try
            {
                var historyScans = _scanHistory.Values.SelectMany(v => v).ToList();
                var stateScans   = _stateService.RecentScanResults.ToList();
                var combined = historyScans.Concat(stateScans)
                    .GroupBy(s => $"{s.Timestamp:yyyyMMddHHmmss}_{s.Type}_{s.Description}")
                    .Select(g => g.First())
                    .OrderByDescending(s => s.Timestamp)
                    .Take(15)
                    .ToList();

                _scanResults.Clear();
                foreach (var r in combined) _scanResults.Add(r);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Dashboard] RefreshRecentFindings error: {ex.Message}");
            }
        }

        // =========================================================================
        // Activity Feed (Tab 2)
        // =========================================================================
        private void RefreshActivityFeed()
        {
            ApplyFilters();
        }

        private void ApplyFilters()
        {
            try
            {
                var searchText   = ActivitySearchBox?.Text?.ToLower() ?? "";
                var moduleFilter = _activityModuleFilter;

                // Build activity items from ScanResults
                var historyScans = _scanHistory.Values.SelectMany(v => v).ToList();
                var allScans = historyScans.Concat(_stateService.RecentScanResults)
                    .GroupBy(s => $"{s.Timestamp:yyyyMMddHHmmss}_{s.Type}_{s.Description}")
                    .Select(g => g.First())
                    .ToList();

                // Build activity items from IDS alerts
                List<ActivityFeedItem> idsItems = new();
                try
                {
                    idsItems = IDSManager.Engine.Alerts
                        .Select(a => new ActivityFeedItem
                        {
                            Timestamp   = a.Timestamp,
                            TimeText    = FormatRelativeTime(a.Timestamp),
                            Module      = "IDS",
                            ModuleShort = "IDS",
                            ModuleColor = new SolidColorBrush(Color.FromRgb(244, 67, 54)),
                            Title       = a.AlertType ?? "IDS Alert",
                            Description = a.Description ?? "",
                            Status      = a.SeverityText,
                            StatusBrush = new SolidColorBrush(
                                (Color)ColorConverter.ConvertFromString(a.SeverityColor ?? "#666666"))
                        }).ToList();
                }
                catch { }

                // Combine all scan results into feed items
                var scanItems = allScans.Select(s => new ActivityFeedItem
                {
                    Timestamp      = s.Timestamp,
                    TimeText       = FormatRelativeTime(s.Timestamp),
                    Module         = DetermineModule(s.Type, s.PageType),
                    ModuleShort    = DetermineModuleShort(s.Type, s.PageType),
                    ModuleColor    = GetModuleColor(DetermineModule(s.Type, s.PageType)),
                    Title          = s.Type,
                    Description    = s.Description,
                    Status         = s.Status,
                    StatusBrush    = GetStatusBrush(s.Status),
                    SourceScanResult = s
                });

                var combined = scanItems.Concat(idsItems)
                    .OrderByDescending(i => i.Timestamp)
                    .ToList();

                // Apply module filter
                if (moduleFilter != "All")
                {
                    combined = combined
                        .Where(i => i.Module.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                }

                // Apply search filter
                if (!string.IsNullOrWhiteSpace(searchText))
                {
                    combined = combined
                        .Where(i =>
                            i.Title.ToLower().Contains(searchText) ||
                            i.Description.ToLower().Contains(searchText) ||
                            i.Module.ToLower().Contains(searchText))
                        .ToList();
                }

                ActivityFeedList.ItemsSource = combined;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Dashboard] ApplyFilters error: {ex.Message}");
            }
        }

        // =========================================================================
        // Threats Grid (Tab 3)
        // =========================================================================
        private void RefreshThreatsGrid()
        {
            try
            {
                var items = new List<ThreatItem>();

                // From IDS
                try
                {
                    foreach (var a in IDSManager.Engine.Alerts)
                    {
                        var hexColor = a.SeverityColor ?? "#666666";
                        items.Add(new ThreatItem
                        {
                            SeverityText   = a.SeverityText,
                            SeverityColor  = hexColor,
                            SeverityBrush  = ParseHexBrush(hexColor),
                            Source         = a.SourceEndpoint,
                            Category       = a.AttackCategory ?? a.AlertType ?? "Unknown",
                            Description    = a.Description ?? "",
                            Time           = a.TimestampFormatted,
                            Module         = "IDS",
                            IsAcknowledged = a.IsAcknowledged
                        });
                    }
                }
                catch { }

                // From Traffic Alerts
                try
                {
                    foreach (var ta in TrafficCaptureService.Instance.Alerts)
                    {
                        if (ta.Severity == ThreatLevel.None) continue;
                        var hexColor = GetThreatLevelColor(ta.Severity);
                        items.Add(new ThreatItem
                        {
                            SeverityText   = ta.Severity.ToString(),
                            SeverityColor  = hexColor,
                            SeverityBrush  = ParseHexBrush(hexColor),
                            Source         = ta.SourceIP ?? "Unknown",
                            Category       = ta.Category ?? "Traffic",
                            Description    = ta.Description ?? ta.Title,
                            Time           = ta.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                            Module         = "Traffic",
                            IsAcknowledged = ta.IsAcknowledged
                        });
                    }
                }
                catch { }

                // Apply severity filter
                if (_threatSeverityFilter != "All")
                {
                    items = items
                        .Where(t => t.SeverityText.Equals(_threatSeverityFilter, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                }

                items = items.OrderByDescending(t => t.Time).ToList();

                ThreatsView.Clear();
                foreach (var t in items) ThreatsView.Add(t);

                if (ThreatCountText != null)
                    ThreatCountText.Text = $"{items.Count} threats";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Dashboard] RefreshThreatsGrid error: {ex.Message}");
            }
        }

        // =========================================================================
        // Query Engine (Tab 4)
        // =========================================================================
        private void ExecuteQuery(string query)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(query))
                {
                    QueryResults.Clear();
                    UpdateQueryCount();
                    return;
                }

                query = query.Trim().ToLower();

                // Parse prefixes
                string moduleFilter   = ExtractPrefix(ref query, "module:");
                string statusFilter   = ExtractPrefix(ref query, "status:");
                string severityFilter = ExtractPrefix(ref query, "severity:");
                string typeFilter     = ExtractPrefix(ref query, "type:");
                string ipFilter       = ExtractPrefix(ref query, "ip:");
                bool   todayOnly      = query.Contains("today");
                if (todayOnly) query  = query.Replace("today", "").Trim();

                var results = new List<QueryResultItem>();

                // --- From ScanResults ---
                var historyScans = _scanHistory.Values.SelectMany(v => v).ToList();
                var allScans = historyScans.Concat(_stateService.RecentScanResults)
                    .GroupBy(s => $"{s.Timestamp:yyyyMMddHHmmss}_{s.Type}_{s.Description}")
                    .Select(g => g.First()).ToList();

                foreach (var s in allScans)
                {
                    if (todayOnly && s.Timestamp.Date != DateTime.Today) continue;

                    var mod = DetermineModule(s.Type, s.PageType);
                    if (!string.IsNullOrEmpty(moduleFilter) && !mod.ToLower().Contains(moduleFilter)) continue;
                    if (!string.IsNullOrEmpty(statusFilter) && !s.Status.ToLower().Contains(statusFilter)) continue;
                    if (!string.IsNullOrEmpty(typeFilter)   && !s.Type.ToLower().Contains(typeFilter)) continue;

                    var combined = s.Type + " " + s.Description + " " + string.Join(" ", s.Details ?? new List<string>());
                    if (!string.IsNullOrEmpty(ipFilter) && !combined.Contains(ipFilter)) continue;
                    if (!string.IsNullOrEmpty(query)    && !combined.ToLower().Contains(query)) continue;

                    // Skip severity filter for non-IDS items (no severity concept)
                    if (!string.IsNullOrEmpty(severityFilter)) continue;

                    results.Add(new QueryResultItem
                    {
                        Time        = s.Timestamp.ToString("yyyy-MM-dd HH:mm"),
                        Module      = mod,
                        Status      = s.Status,
                        StatusColor = GetStatusBrush(s.Status),
                        Title       = s.Type,
                        Description = s.Description
                    });
                }

                // --- From IDS Alerts ---
                try
                {
                    foreach (var a in IDSManager.Engine.Alerts)
                    {
                        if (todayOnly && a.Timestamp.Date != DateTime.Today) continue;
                        if (!string.IsNullOrEmpty(moduleFilter) && !"ids".Contains(moduleFilter)) continue;
                        if (!string.IsNullOrEmpty(statusFilter)) continue; // IDS has no status field
                        if (!string.IsNullOrEmpty(severityFilter) &&
                            !a.SeverityText.ToLower().Contains(severityFilter)) continue;

                        var combined = a.AlertType + " " + a.Description + " " +
                                       a.SourceIP + " " + a.DestinationIP;
                        if (!string.IsNullOrEmpty(ipFilter) &&
                            !combined.ToLower().Contains(ipFilter)) continue;
                        if (!string.IsNullOrEmpty(query) &&
                            !combined.ToLower().Contains(query)) continue;
                        if (!string.IsNullOrEmpty(typeFilter) &&
                            !"ids alert".Contains(typeFilter)) continue;

                        results.Add(new QueryResultItem
                        {
                            Time        = a.TimestampFormatted,
                            Module      = "IDS",
                            Status      = a.SeverityText,
                            StatusColor = new SolidColorBrush(
                                (Color)ColorConverter.ConvertFromString(a.SeverityColor ?? "#666666")),
                            Title       = a.AlertType ?? "IDS Alert",
                            Description = a.Description ?? ""
                        });
                    }
                }
                catch { }

                QueryResults.Clear();
                foreach (var r in results.OrderByDescending(r => r.Time).Take(500))
                    QueryResults.Add(r);

                UpdateQueryCount();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Dashboard] ExecuteQuery error: {ex.Message}");
            }
        }

        private string ExtractPrefix(ref string query, string prefix)
        {
            var idx = query.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";
            var rest  = query.Substring(idx + prefix.Length);
            var end   = rest.IndexOf(' ');
            var value = end < 0 ? rest : rest.Substring(0, end);
            query     = query.Remove(idx, prefix.Length + value.Length).Trim();
            return value.ToLower();
        }

        private void UpdateQueryCount()
        {
            if (QueryResultCountText != null)
                QueryResultCountText.Text = QueryResults.Count.ToString();
        }

        // =========================================================================
        // Charts (Tab 1 - Analytics)
        // =========================================================================
        private void DrawAllCharts()
        {
            DrawChart7Days();
            DrawChartScanTypes();
            DrawChartThreatSeverity();
            DrawChartProtocols();
        }

        private void DrawChart7Days()
        {
            if (Chart7Days == null) return;

            var data = new List<(string label, double value, Color barColor)>();
            for (int i = 6; i >= 0; i--)
            {
                var date  = DateTime.Today.AddDays(-i);
                var count = _stateService.RecentScanResults.Count(r => r.Timestamp.Date == date) +
                            (_scanHistory.ContainsKey(date) ? _scanHistory[date].Count : 0);
                data.Add((date.ToString("ddd"), count, Color.FromRgb(33, 150, 243)));
            }
            DrawDayBarChart(Chart7Days, data);
        }

        private void DrawChartScanTypes()
        {
            if (ChartScanTypes == null) return;

            var historyScans = _scanHistory.Values.SelectMany(v => v).ToList();
            var allScans = historyScans.Concat(_stateService.RecentScanResults)
                .GroupBy(s => DetermineModule(s.Type, s.PageType))
                .Select(g => (label: g.Key, value: (double)g.Count(),
                              barColor: ParseModuleColor(g.Key)))
                .OrderByDescending(x => x.value)
                .Take(8)
                .ToList();

            if (!allScans.Any())
                allScans = new List<(string, double, Color)> { ("No data", 0, Colors.Gray) };

            double maxVal = allScans.Max(x => x.value);
            DrawHorizontalBarChart(ChartScanTypes, allScans, maxVal == 0 ? 1 : maxVal);
        }

        private void DrawChartThreatSeverity()
        {
            if (ChartThreatSeverity == null) return;

            int critical = 0, high = 0, medium = 0, low = 0;
            try
            {
                var stats = IDSManager.Engine.GetStats();
                critical  = stats.CriticalAlerts;
                high      = stats.HighAlerts;
                medium    = stats.MediumAlerts;
                low       = stats.LowAlerts;
            }
            catch { }

            var data = new List<(string label, double value, Color barColor)>
            {
                ("Critical", critical, Color.FromRgb(244, 67,  54)),
                ("High",     high,     Color.FromRgb(255, 140,  0)),
                ("Medium",   medium,   Color.FromRgb(255, 165,  0)),
                ("Low",      low,      Color.FromRgb( 78, 201, 176))
            };
            double maxVal = data.Max(x => x.value);
            DrawHorizontalBarChart(ChartThreatSeverity, data, maxVal == 0 ? 1 : maxVal);
        }

        private void DrawChartProtocols()
        {
            if (ChartProtocols == null) return;

            var data = new List<(string label, double value, Color barColor)>();
            try
            {
                var counts = TrafficCaptureService.Instance.Statistics.ProtocolPacketCounts;
                if (counts != null && counts.Any())
                {
                    var colorPalette = new[]
                    {
                        Color.FromRgb(33, 150, 243),
                        Color.FromRgb( 76, 175,  80),
                        Color.FromRgb(255, 152,   0),
                        Color.FromRgb(244,  67,  54),
                        Color.FromRgb(156,  39, 176),
                        Color.FromRgb(  0, 188, 212),
                        Color.FromRgb(255, 193,   7),
                        Color.FromRgb(121,  85, 72)
                    };
                    int ci = 0;
                    foreach (var kv in counts.OrderByDescending(x => x.Value).Take(8))
                    {
                        data.Add((kv.Key, (double)kv.Value, colorPalette[ci++ % colorPalette.Length]));
                    }
                }
            }
            catch { }

            if (!data.Any())
                data.Add(("No traffic data", 0, Colors.Gray));

            DrawDayBarChart(ChartProtocols, data);
        }

        // ---- Theme-aware color helpers for canvas drawing -------------------
        private Color ThemeText()
        {
            try { return ((SolidColorBrush)Application.Current.Resources["TextBrush"]).Color; }
            catch { return Color.FromRgb(220, 220, 220); }
        }

        private Color ThemeSubtle()
        {
            try { return ((SolidColorBrush)Application.Current.Resources["SubtleTextBrush"]).Color; }
            catch { return Color.FromRgb(136, 136, 136); }
        }

        // ---- Chart drawing helpers ------------------------------------------
        private void DrawDayBarChart(Canvas canvas,
            List<(string label, double value, Color barColor)> data)
        {
            canvas.Children.Clear();
            double w = canvas.ActualWidth;
            double h = canvas.ActualHeight;
            if (w < 10 || h < 10) return;

            Color textColor   = ThemeText();
            Color subtleColor = ThemeSubtle();

            if (!data.Any() || data.All(d => d.value == 0))
            {
                AddNoDataText(canvas, w, h);
                return;
            }

            double paddingLeft   = 10;
            double paddingRight  = 10;
            double paddingTop    = 22;
            double paddingBottom = 32;
            double chartW  = w - paddingLeft - paddingRight;
            double chartH  = h - paddingTop - paddingBottom;
            double maxVal  = data.Max(d => d.value);
            if (maxVal == 0) maxVal = 1;

            int    n        = data.Count;
            double barWidth = chartW / n * 0.62;
            double gap      = chartW / n;

            // Subtle horizontal grid lines
            for (int i = 0; i <= 4; i++)
            {
                double gy = paddingTop + chartH - (chartH * i / 4.0);
                var line = new Line
                {
                    X1 = paddingLeft, Y1 = gy, X2 = paddingLeft + chartW, Y2 = gy,
                    Stroke = new SolidColorBrush(Color.FromArgb(40, subtleColor.R, subtleColor.G, subtleColor.B)),
                    StrokeThickness = 1
                };
                canvas.Children.Add(line);

                // Y-axis value label
                if (i > 0)
                {
                    var yLab = new TextBlock
                    {
                        Text       = ((maxVal * i / 4)).ToString("0"),
                        FontSize   = 8,
                        Foreground = new SolidColorBrush(Color.FromArgb(160, subtleColor.R, subtleColor.G, subtleColor.B))
                    };
                    yLab.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                    Canvas.SetLeft(yLab, 0);
                    Canvas.SetTop(yLab, gy - yLab.DesiredSize.Height / 2);
                    canvas.Children.Add(yLab);
                }
            }

            for (int i = 0; i < n; i++)
            {
                var (label, value, barColor) = data[i];
                double barH = chartH * (value / maxVal);
                double x    = paddingLeft + i * gap + (gap - barWidth) / 2.0;
                double y    = paddingTop + chartH - barH;

                // Bar
                var rect = new Rectangle
                {
                    Width   = barWidth,
                    Height  = Math.Max(barH, 2),
                    Fill    = new SolidColorBrush(barColor),
                    RadiusX = 3,
                    RadiusY = 3
                };
                Canvas.SetLeft(rect, x);
                Canvas.SetTop(rect, y);
                canvas.Children.Add(rect);

                // Value label above bar
                if (value > 0)
                {
                    var valTb = new TextBlock
                    {
                        Text       = value.ToString("0"),
                        FontSize   = 9,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = new SolidColorBrush(textColor)
                    };
                    valTb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                    Canvas.SetLeft(valTb, x + barWidth / 2 - valTb.DesiredSize.Width / 2);
                    Canvas.SetTop(valTb, Math.Max(y - 16, paddingTop));
                    canvas.Children.Add(valTb);
                }

                // X-axis label (below bar)
                var labelTb = new TextBlock
                {
                    Text         = label,
                    FontSize     = 9,
                    Foreground   = new SolidColorBrush(subtleColor),
                    MaxWidth     = gap,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    TextAlignment = TextAlignment.Center
                };
                labelTb.Measure(new Size(gap, double.PositiveInfinity));
                Canvas.SetLeft(labelTb, x + barWidth / 2 - Math.Min(labelTb.DesiredSize.Width, gap) / 2);
                Canvas.SetTop(labelTb, paddingTop + chartH + 5);
                canvas.Children.Add(labelTb);
            }
        }

        private void DrawHorizontalBarChart(Canvas canvas,
            List<(string label, double value, Color barColor)> data,
            double maxValue)
        {
            canvas.Children.Clear();
            double w = canvas.ActualWidth;
            double h = canvas.ActualHeight;
            if (w < 10 || h < 10) return;

            Color textColor   = ThemeText();
            Color subtleColor = ThemeSubtle();

            if (!data.Any() || data.All(d => d.value == 0))
            {
                AddNoDataText(canvas, w, h);
                return;
            }

            double labelW       = 120;
            double valueW       = 36;
            double paddingV     = 4;
            int    n            = data.Count;
            double rowH         = (h - paddingV * 2) / n;
            double barAreaW     = w - labelW - valueW;

            for (int i = 0; i < n; i++)
            {
                var (label, value, barColor) = data[i];
                double y       = paddingV + i * rowH;
                double barH    = Math.Max(rowH * 0.45, 8);
                double barYOff = (rowH - barH) / 2.0;
                double barW    = value <= 0 ? 2 : barAreaW * (value / maxValue);

                // Row hover background (subtle)
                var rowBg = new Rectangle
                {
                    Width  = w,
                    Height = rowH - 2,
                    Fill   = new SolidColorBrush(Color.FromArgb(i % 2 == 0 ? (byte)0 : (byte)15,
                        subtleColor.R, subtleColor.G, subtleColor.B))
                };
                Canvas.SetLeft(rowBg, 0);
                Canvas.SetTop(rowBg, y + 1);
                canvas.Children.Add(rowBg);

                // Label
                var labelTb = new TextBlock
                {
                    Text         = label,
                    FontSize     = 10,
                    Foreground   = new SolidColorBrush(textColor),
                    Width        = labelW - 6,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    VerticalAlignment = VerticalAlignment.Center
                };
                labelTb.Measure(new Size(labelW - 6, double.PositiveInfinity));
                Canvas.SetLeft(labelTb, 4);
                Canvas.SetTop(labelTb, y + barYOff + (barH - labelTb.DesiredSize.Height) / 2);
                canvas.Children.Add(labelTb);

                // Bar background track
                var track = new Rectangle
                {
                    Width   = barAreaW,
                    Height  = barH,
                    Fill    = new SolidColorBrush(Color.FromArgb(30, barColor.R, barColor.G, barColor.B)),
                    RadiusX = 3, RadiusY = 3
                };
                Canvas.SetLeft(track, labelW);
                Canvas.SetTop(track, y + barYOff);
                canvas.Children.Add(track);

                // Bar fill
                var rect = new Rectangle
                {
                    Width   = Math.Max(barW, 3),
                    Height  = barH,
                    Fill    = new SolidColorBrush(barColor),
                    RadiusX = 3, RadiusY = 3
                };
                Canvas.SetLeft(rect, labelW);
                Canvas.SetTop(rect, y + barYOff);
                canvas.Children.Add(rect);

                // Value text
                var valTb = new TextBlock
                {
                    Text       = value.ToString("0"),
                    FontSize   = 9,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(textColor)
                };
                valTb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                Canvas.SetLeft(valTb, labelW + barAreaW + 4);
                Canvas.SetTop(valTb, y + barYOff + (barH - valTb.DesiredSize.Height) / 2);
                canvas.Children.Add(valTb);
            }
        }

        private void AddNoDataText(Canvas canvas, double w, double h)
        {
            var tb = new TextBlock
            {
                Text       = "No data yet â€” run a scan first",
                FontSize   = 12,
                Foreground = new SolidColorBrush(ThemeSubtle()),
                HorizontalAlignment = HorizontalAlignment.Center
            };
            tb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            Canvas.SetLeft(tb, (w - tb.DesiredSize.Width) / 2);
            Canvas.SetTop(tb,  (h - tb.DesiredSize.Height) / 2);
            canvas.Children.Add(tb);
        }

        // =========================================================================
        // Universal Search
        // =========================================================================
        private void UniversalSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Lightweight: only auto-run if on Query tab, otherwise wait for Enter/button
            if (_currentTabIndex == 4)
                ExecuteQuery(UniversalSearchBox.Text);
        }

        private void UniversalSearch_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var text = UniversalSearchBox.Text;
                // Mirror to query tab and run
                QueryInputBox.Text = text;
                SwitchTab(4);
                TabQuery.IsChecked = true;
                ExecuteQuery(text);
            }
        }

        private void UniversalSearchGo_Click(object sender, RoutedEventArgs e)
        {
            var text = UniversalSearchBox.Text;
            QueryInputBox.Text = text;
            SwitchTab(4);
            TabQuery.IsChecked = true;
            ExecuteQuery(text);
        }

        // =========================================================================
        // Filter event handlers
        // =========================================================================
        private void ActivityFilter_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.Tag is string tag)
            {
                _activityModuleFilter = tag;
                ApplyFilters();
            }
        }

        private void ActivitySearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplyFilters();
        }

        private void ThreatFilter_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.Tag is string tag)
            {
                _threatSeverityFilter = tag;
                RefreshThreatsGrid();
            }
        }

        // =========================================================================
        // Query event handlers
        // =========================================================================
        private void QueryInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) ExecuteQuery(QueryInputBox.Text);
        }

        private void QueryRun_Click(object sender, RoutedEventArgs e)
        {
            ExecuteQuery(QueryInputBox.Text);
        }

        private void QueryClear_Click(object sender, RoutedEventArgs e)
        {
            QueryInputBox.Text = "";
            QueryResults.Clear();
            UpdateQueryCount();
        }

        private void QueryChip_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string preset)
            {
                QueryInputBox.Text = preset;
                ExecuteQuery(preset);
            }
        }

        // =========================================================================
        // Canvas SizeChanged / Loaded â€” redraw all analytics charts
        // =========================================================================
        private void ChartCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            if (_currentTabIndex == 1)
                Dispatcher.BeginInvoke(DrawAllCharts, DispatcherPriority.Render);
        }

        private void ChartCanvas_Loaded(object sender, RoutedEventArgs e)
        {
            // Re-fire draw after a layout pass so ActualWidth/Height are real values
            Dispatcher.BeginInvoke(DrawAllCharts, DispatcherPriority.Loaded);
        }

        // =========================================================================
        // Calendar
        // =========================================================================
        private void InitializeCalendar()
        {
            ScanHistoryCalendar.SelectedDate = DateTime.Today;
            ScanHistoryCalendar.DisplayDate  = DateTime.Today;
            LoadScanResultsForDate(DateTime.Today);
        }

        private void LoadScanResultsForDate(DateTime date)
        {
            var historyResults = _scanHistory.ContainsKey(date.Date)
                ? _scanHistory[date.Date] : new List<ScanResult>();

            var stateResults = _stateService.RecentScanResults
                .Where(r => r.Timestamp.Date == date.Date).ToList();

            var combined = historyResults.Concat(stateResults)
                .GroupBy(s => $"{s.Timestamp:yyyyMMddHHmmss}_{s.Type}_{s.Description}")
                .Select(g => g.First())
                .OrderByDescending(s => s.Timestamp)
                .ToList();

            _scanResults.Clear();
            foreach (var r in combined) _scanResults.Add(r);
        }

        private void CalendarButton_Click(object sender, RoutedEventArgs e)
        {
            CalendarPopup.IsOpen = true;
        }

        private void ScanHistoryCalendar_SelectedDatesChanged(object sender, SelectionChangedEventArgs e)
        {
            var selected = ScanHistoryCalendar.SelectedDate;
            if (selected.HasValue) LoadScanResultsForDate(selected.Value);
            CalendarPopup.IsOpen = false;
        }

        private void UpdateCalendarHighlights()
        {
            try
            {
                var allDates = new HashSet<DateTime>();
                foreach (var d in _scanHistory.Keys) allDates.Add(d);
                foreach (var r in _stateService.RecentScanResults) allDates.Add(r.Timestamp.Date);

                foreach (var date in allDates)
                {
                    var btn = ScanHistoryCalendar.FindDayButton(date);
                    if (btn != null)
                    {
                        int cnt = (_scanHistory.ContainsKey(date) ? _scanHistory[date].Count : 0) +
                                  _stateService.RecentScanResults.Count(r => r.Timestamp.Date == date);
                        ToolTipService.SetToolTip(btn, $"{cnt} result(s) on {date:MM/dd/yyyy}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Dashboard] UpdateCalendarHighlights error: {ex.Message}");
            }
        }

        // =========================================================================
        // Expandable finding cards
        // =========================================================================
        private void ExpandCard_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border)
            {
                if (border.DataContext is ScanResult scanResult && scanResult.Type == "No Scans Found")
                    return;

                var expandedBorder = FindChildByName(border, "ExpandedContent");
                if (expandedBorder is Border eb)
                {
                    bool expand = eb.Visibility == Visibility.Collapsed;
                    eb.Visibility = expand ? Visibility.Visible : Visibility.Collapsed;

                    // Animate the arrow icon (FontAwesome.Sharp IconBlock)
                    var arrowObj = FindChildByName(border, "ExpandArrow");
                    if (arrowObj is FrameworkElement arrowEl)
                    {
                        var rot = arrowEl.RenderTransform as RotateTransform
                                  ?? FindRotateTransform(arrowEl);
                        if (rot != null)
                        {
                            var anim = new DoubleAnimation
                            {
                                To = expand ? 180 : 0,
                                Duration = TimeSpan.FromSeconds(0.2),
                                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                            };
                            rot.BeginAnimation(RotateTransform.AngleProperty, anim);
                        }
                    }
                }
            }
        }

        private RotateTransform FindRotateTransform(FrameworkElement el)
        {
            if (el.RenderTransform is RotateTransform rt) return rt;
            if (el.RenderTransform is TransformGroup tg)
                return tg.Children.OfType<RotateTransform>().FirstOrDefault();
            return null;
        }

        // =========================================================================
        // Navigation / navigation buttons
        // =========================================================================
        private void NavigateToPage_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is ScanResult sr)
                HandleScanResultNavigation(sr);
        }

        private void HandleScanResultNavigation(ScanResult scanResult)
        {
            try
            {
                var mainWindow = Application.Current.MainWindow as MainWindow;
                if (mainWindow == null) return;

                if (string.IsNullOrEmpty(scanResult.PageType) || scanResult.PageType == PageTypes.Dashboard)
                {
                    AppDialog.Show("This scan was performed on the Dashboard page.",
                        "Navigation Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var result = AppDialog.Show(
                    $"Navigate to {scanResult.PageType} page?\n\nRestores state from {scanResult.Timestamp:MMM dd, HH:mm}",
                    "Navigate to Source", MessageBoxButton.YesNo, MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    mainWindow.NavigateToPageWithState(scanResult.PageType, scanResult.PageState);
                    mainWindow.AddAssistantMessage(
                        $"Navigated to {scanResult.PageType} with restored state from {scanResult.Timestamp:yyyy-MM-dd HH:mm:ss}.");
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Navigation error: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowScanResultDetails(ScanResult scanResult)
        {
            SolidColorBrush DynBr(string key) => Application.Current.Resources[key] as SolidColorBrush ?? new SolidColorBrush(Colors.Gray);
            var win = new Window
            {
                Title  = $"Scan Details â€” {scanResult.Type}",
                Width  = 640, Height = 500,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner  = Application.Current.MainWindow,
                Background = DynBr("BackgroundBrush")
            };

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var scroll = new ScrollViewer { Padding = new Thickness(24), VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            var sp = new StackPanel();

            sp.Children.Add(new TextBlock { Text = scanResult.Type, FontSize = 18, FontWeight = FontWeights.Bold,
                Foreground = DynBr("TextBrush"), Margin = new Thickness(0, 0, 0, 12) });

            var meta = new TextBlock
            {
                Text = $"Time: {scanResult.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
                       $"Source: {scanResult.PageType}\nStatus: {scanResult.Status}\n\n{scanResult.Description}",
                Foreground = DynBr("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 12)
            };
            sp.Children.Add(meta);

            if (scanResult.Details?.Count > 0)
            {
                sp.Children.Add(new TextBlock { Text = "Details", FontSize = 14, FontWeight = FontWeights.SemiBold,
                    Foreground = DynBr("TextBrush"), Margin = new Thickness(0, 0, 0, 8) });
                foreach (var d in scanResult.Details)
                    sp.Children.Add(new TextBlock { Text = $"â€¢ {d}", Foreground = DynBr("SubtleTextBrush"),
                        FontSize = 12, Margin = new Thickness(12, 2, 0, 2) });
            }

            scroll.Content = sp;
            Grid.SetRow(scroll, 0);
            grid.Children.Add(scroll);

            var btnPanel = new StackPanel { Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(24, 12, 24, 24) };
            var closeBtn = new Button { Content = "Close", Width = 80, Height = 30,
                Background = DynBr("AccentBrush"), Foreground = Brushes.White, BorderThickness = new Thickness(0) };
            closeBtn.Click += (s, _) => win.Close();
            btnPanel.Children.Add(closeBtn);
            Grid.SetRow(btnPanel, 1);
            grid.Children.Add(btnPanel);

            win.Content = grid;
            win.ShowDialog();
        }

        // =========================================================================
        // Security Check
        // =========================================================================
        private void SecurityCheckButton_Click(object sender, RoutedEventArgs e)
        {
            _ = RunSecurityCheck();
        }

        private async Task RunSecurityCheck()
        {
            try
            {
                SecurityLoadingPanel.Visibility = Visibility.Visible;
                SecurityScorePanel.Visibility   = Visibility.Collapsed;
                LastScanText.Text               = "Scanning...";

                var mainWindow = Application.Current.MainWindow as MainWindow;
                if (mainWindow == null) return;

                var checker = new SecurityCheck(mainWindow);
                var result  = await checker.PerformSecurityCheck("127.0.0.1");
                UpdateSecurityScore(result);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Security check error: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SecurityLoadingPanel.Visibility = Visibility.Collapsed;
                SecurityScorePanel.Visibility   = Visibility.Visible;
                LastScanText.Text               = $"Last scan: {DateTime.Now:g}";
            }
        }

        private void UpdateSecurityScore(SecurityCheck.SecurityCheckResult result)
        {
            int maxPossible = 100;
            double norm     = Math.Max(0, Math.Min(100, (1 - (result.TotalScore / (double)maxPossible)) * 100));
            SecurityScoreText.Text = $"{norm:F0}";
            LastScanText.Text      = $"Last scan: {DateTime.Now:g}";

            byte red, green;
            if (norm < 50) { red = 255; green = (byte)(255 * norm / 50.0); }
            else           { green = 255; red = (byte)(255 * (100 - norm) / 50.0); }
            var scoreColor = Color.FromRgb(red, green, 0);

            string emoji, risk;
            if      (norm >= 90) { emoji = "ðŸ¥³"; risk = "Excellent Security"; }
            else if (norm >= 80) { emoji = "ðŸ˜Ž"; risk = "Very Good Security"; }
            else if (norm >= 70) { emoji = "ðŸ˜Š"; risk = "Good Security"; }
            else if (norm >= 60) { emoji = "ðŸ¤”"; risk = "Moderate Risk"; }
            else if (norm >= 40) { emoji = "ðŸ˜°"; risk = "High Risk"; }
            else if (norm >= 20) { emoji = "ðŸ˜±"; risk = "Very High Risk"; }
            else                 { emoji = "â˜ ï¸"; risk = "Critical Risk"; }

            SecurityEmoji.Text        = emoji;
            SecurityRiskLevelText.Text = risk;

            var brush = new SolidColorBrush(scoreColor);
            SecurityIconBorder.Background = brush;
            SecurityScoreText.Foreground  = brush;

            // Save result to history
            var mainWindow = Application.Current.MainWindow as MainWindow;
            var currentPage = mainWindow?.GetCurrentPage();

            var scanResult = _stateService.CreateScanResultWithContext(
                type:        $"Security Check {emoji}",
                description: $"Security Score: {norm:F0}/100 â€” {risk}",
                status:      norm >= 70 ? "Good" : norm >= 50 ? "Warning" : "Error",
                details:     new List<string>
                {
                    $"Score: {norm:F0}/100",
                    $"Risk Level: {risk}",
                    $"Scan Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}"
                },
                pageType:    PageTypes.Dashboard,
                currentPage: currentPage
            );

            _scanResults.Insert(0, scanResult);
            var date = DateTime.Now.Date;
            if (!_scanHistory.ContainsKey(date)) _scanHistory[date] = new List<ScanResult>();
            _scanHistory[date].Add(scanResult);
            ScanHistoryManager.SaveScanHistory(_scanHistory);
            _stateService.AddScanResult(scanResult);
            UpdateCalendarHighlights();
            RefreshKPIs();
        }

        // =========================================================================
        // Speed test (preserved)
        // =========================================================================
        private void TestSpeedButton_Click(object sender, RoutedEventArgs e)
        {
            _ = RunSpeedTest();
        }

        private async Task RunSpeedTest()
        {
            TestSpeedButton.IsEnabled  = false;
            ScanProgressBar.Visibility = Visibility.Visible;
            TestSpeedButton.Visibility = Visibility.Collapsed;
            try
            {
                double speed = await MeasureNetworkSpeed();
                UpdateUIBasedOnSpeed(speed);
                AddSpeedTestResult(speed);
            }
            catch (Exception ex)
            {
                StatusText.Text = "Test Failed";
                SpeedText.Text  = "Error";
                UpdateSpeedColors(RedBrush);
                AppDialog.Show($"Speed test failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                TestSpeedButton.IsEnabled  = true;
                ScanProgressBar.Visibility = Visibility.Collapsed;
                TestSpeedButton.Visibility = Visibility.Visible;
            }
        }

        private async Task<double> MeasureNetworkSpeed()
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
            string url = "https://download.microsoft.com/download/2/0/E/20E90413-712F-438C-988E-FDAA79A8AC3D/dotnetfx35.exe";

            var speeds = new List<double>();
            var start  = DateTime.Now;
            StatusText.Text = "Starting speed test...";
            await Task.Delay(500);

            while ((DateTime.Now - start).TotalSeconds < 8)
            {
                using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
                if (!resp.IsSuccessStatusCode) throw new Exception($"HTTP {resp.StatusCode}");
                byte[] buf  = new byte[8192];
                long   read = 0;
                var    t0   = DateTime.Now;
                using var stream = await resp.Content.ReadAsStreamAsync();
                int n;
                while ((n = await stream.ReadAsync(buf, 0, buf.Length)) > 0)
                {
                    read += n;
                    if ((DateTime.Now - t0).TotalSeconds >= 1)
                    {
                        double mbps = read * 8.0 / 1_000_000.0 / (DateTime.Now - t0).TotalSeconds;
                        speeds.Add(mbps);
                        SpeedText.Text  = $"{mbps:F1} Mbps";
                        StatusText.Text = $"Testing... {speeds.Count}s";
                        read = 0; t0 = DateTime.Now;
                    }
                }
            }

            if (speeds.Count == 0) throw new Exception("No speed data recorded.");
            if (speeds.Count > 3) { speeds.Remove(speeds.Max()); speeds.Remove(speeds.Min()); }
            return speeds.Average();
        }

        private void UpdateUIBasedOnSpeed(double mbps)
        {
            SpeedText.Text = $"{mbps:F1} Mbps";
            if      (mbps >= 30) { StatusText.Text = "Excellent Connection"; UpdateSpeedColors(GreenBrush); }
            else if (mbps >= 10) { StatusText.Text = "Moderate Connection";  UpdateSpeedColors(YellowBrush); }
            else                 { StatusText.Text = "Poor Connection";       UpdateSpeedColors(RedBrush); }
        }

        private void UpdateSpeedColors(SolidColorBrush brush)
        {
            if (SpeedText  != null) SpeedText.Foreground  = brush;
            if (StatusText != null) StatusText.Foreground = brush;
        }

        private void AddSpeedTestResult(double mbps)
        {
            string status = mbps >= 30 ? "Good" : mbps >= 10 ? "Warning" : "Error";
            var mainWindow  = Application.Current.MainWindow as MainWindow;
            var currentPage = mainWindow?.GetCurrentPage();

            var r = _stateService.CreateScanResultWithContext(
                type:        "Network Speed Test",
                description: $"Speed: {mbps:F1} Mbps",
                status:      status,
                details:     new List<string>
                {
                    $"Quality: {(mbps >= 30 ? "Excellent" : mbps >= 10 ? "Moderate" : "Poor")}",
                    $"Speed: {mbps:F1} Mbps",
                    $"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}"
                },
                pageType:    PageTypes.Dashboard,
                currentPage: currentPage
            );

            _scanResults.Insert(0, r);
            var date = DateTime.Now.Date;
            if (!_scanHistory.ContainsKey(date)) _scanHistory[date] = new List<ScanResult>();
            _scanHistory[date].Add(r);
            ScanHistoryManager.SaveScanHistory(_scanHistory);
            _stateService.AddScanResult(r);
            UpdateCalendarHighlights();
        }

        // =========================================================================
        // Refresh button click
        // =========================================================================
        private void RefreshDashboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _scanHistory = ScanHistoryManager.LoadScanHistory();
                _stateService.LoadScanResults();
                _stateService.LoadNetworkScanResults();
                RefreshDashboard();
                try { _stateService.SaveScanResults(); } catch { }
                try { _stateService.SaveNetworkScanResults(); } catch { }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Refresh error: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // =========================================================================
        // Ask Assistant
        // =========================================================================
        private void AskAssistant_Click(object sender, RoutedEventArgs e)
        {
            ScanResult sr = null;
            if (sender is Button btn && btn.Tag is ScanResult r1) sr = r1;
            else if (sender is MenuItem mi && mi.Tag is ScanResult r2) sr = r2;

            if (sr == null) return;

            try
            {
                var mainWindow = Application.Current.MainWindow as MainWindow;
                if (mainWindow == null) return;

                string msg = $"Please analyse this scan result:\n\n" +
                             $"Type: {sr.Type}\nStatus: {sr.Status}\n" +
                             $"Time: {sr.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
                             $"Description: {sr.Description}\n\n";
                if (sr.Details?.Count > 0)
                    msg += "Details:\n" + string.Join("\n", sr.Details.Select(d => $"â€¢ {d}"));
                msg += "\n\nProvide: risk assessment, recommended actions, security implications, next steps.";

                mainWindow.AddAssistantMessage($"Analysis Request: {sr.Type}\n\n{msg}");
                AppDialog.Show("Sent to AI Assistant â€” check the chat panel.",
                    "AI Assistant", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Assistant error: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // =========================================================================
        // Utility helpers
        // =========================================================================
        private string DetermineModule(string type, string pageType)
        {
            if (string.IsNullOrEmpty(type)) return pageType ?? "Unknown";
            var t = type.ToLower();
            if (t.Contains("port") || t.Contains("scan port"))    return "Port Scanner";
            if (t.Contains("network") || t.Contains("discovery")) return "Network Discovery";
            if (t.Contains("traffic") || t.Contains("speed"))     return "Traffic Analysis";
            if (t.Contains("ids") || t.Contains("intrusion"))     return "IDS";
            if (t.Contains("vuln") || t.Contains("cve"))          return "Vulnerability";
            if (t.Contains("security") || t.Contains("check"))    return "Security";
            if (!string.IsNullOrEmpty(pageType))                  return pageType;
            return "General";
        }

        private string DetermineModuleShort(string type, string pageType)
        {
            var mod = DetermineModule(type, pageType);
            return mod switch
            {
                "Port Scanner"       => "PORT",
                "Network Discovery"  => "NET",
                "Traffic Analysis"   => "TRAF",
                "IDS"                => "IDS",
                "Vulnerability"      => "VULN",
                "Security"           => "SEC",
                _                   => mod.Length > 4 ? mod.Substring(0, 4).ToUpper() : mod.ToUpper()
            };
        }

        private Brush GetModuleColor(string module)
        {
            return module switch
            {
                "Port Scanner"       => new SolidColorBrush(Color.FromRgb( 33, 150, 243)),
                "Network Discovery"  => new SolidColorBrush(Color.FromRgb( 76, 175,  80)),
                "Traffic Analysis"   => new SolidColorBrush(Color.FromRgb(255, 152,   0)),
                "IDS"                => new SolidColorBrush(Color.FromRgb(244,  67,  54)),
                "Vulnerability"      => new SolidColorBrush(Color.FromRgb(156,  39, 176)),
                "Security"           => new SolidColorBrush(Color.FromRgb(  0, 188, 212)),
                _                   => new SolidColorBrush(Colors.Gray)
            };
        }

        private Color ParseModuleColor(string module)
        {
            return module switch
            {
                "Port Scanner"       => Color.FromRgb( 33, 150, 243),
                "Network Discovery"  => Color.FromRgb( 76, 175,  80),
                "Traffic Analysis"   => Color.FromRgb(255, 152,   0),
                "IDS"                => Color.FromRgb(244,  67,  54),
                "Vulnerability"      => Color.FromRgb(156,  39, 176),
                "Security"           => Color.FromRgb(  0, 188, 212),
                _                   => Colors.Gray
            };
        }

        private Brush GetStatusBrush(string status)
        {
            return status?.ToLower() switch
            {
                "good"    => GreenBrush,
                "warning" => YellowBrush,
                "error"   => RedBrush,
                _         => new SolidColorBrush(Colors.Gray)
            };
        }

        private SolidColorBrush ParseHexBrush(string hex)
        {
            try
            {
                var color = (Color)ColorConverter.ConvertFromString(hex);
                return new SolidColorBrush(color);
            }
            catch
            {
                return new SolidColorBrush(Colors.Gray);
            }
        }

        private string GetThreatLevelColor(ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.Critical => "#F44336",
                ThreatLevel.High     => "#FF8C00",
                ThreatLevel.Medium   => "#FFA500",
                ThreatLevel.Low      => "#4EC9B0",
                _                   => "#666666"
            };
        }

        private string FormatRelativeTime(DateTime dt)
        {
            var diff = DateTime.Now - dt;
            if (diff.TotalSeconds < 60)  return $"{(int)diff.TotalSeconds}s ago";
            if (diff.TotalMinutes < 60)  return $"{(int)diff.TotalMinutes}m ago";
            if (diff.TotalHours   < 24)  return $"{(int)diff.TotalHours}h ago";
            if (diff.TotalDays    < 7)   return $"{(int)diff.TotalDays}d ago";
            return dt.ToString("MMM dd");
        }

        // =========================================================================
        // Visual-tree helpers
        // =========================================================================
        private FrameworkElement FindChildByName(DependencyObject parent, string name)
        {
            if (parent == null) return null;
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is FrameworkElement fe && fe.Name == name) return fe;
                var found = FindChildByName(child, name);
                if (found != null) return found;
            }
            return null;
        }

        private T FindChild<T>(DependencyObject parent, string childName = null) where T : DependencyObject
        {
            if (parent == null) return null;
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T result)
                {
                    if (childName == null || (result is FrameworkElement fe && fe.Name == childName))
                        return result;
                }
                var found = FindChild<T>(child, childName);
                if (found != null) return found;
            }
            return null;
        }

        // =========================================================================
        // INotifyPropertyChanged
        // =========================================================================
        public event PropertyChangedEventHandler PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

        // =========================================================================
        // Legacy private enum (kept for old CheckHostStatus logic)
        // =========================================================================
        private enum Status { Unknown, Checking, Online, Offline }
    }
}

