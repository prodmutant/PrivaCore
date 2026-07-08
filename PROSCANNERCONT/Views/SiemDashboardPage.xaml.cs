using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using PROSCANNERCONT.ValueConverters;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// The SIEM workspace: a tabbed, responsive dashboard (Overview tiles / Search / Sources &amp;
    /// Agents / Pipeline). Replaces the old free-drag canvas with a clean Grafana-style tiled
    /// layout. Shares the singleton SiemStore so console and collector render the same data.
    /// </summary>
    public partial class SiemDashboardPage : Page
    {
        private sealed class TileCtx
        {
            public SiemWidget W = null!;
            public Border Card = null!;
            public Border Host = null!;
            public ObservableCollection<SiemEvent>? Rows;   // for the watchlist tile
            public DataGrid? Grid;
        }

        private readonly ISiemStore _store = SiemStoreProvider.Current;
        private readonly SiemIngestion _ing = SiemIngestion.Instance;
        private readonly HexToBrushConverter _hex = new();
        private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };

        private List<SiemWidget> _tiles;
        private readonly Dictionary<string, TileCtx> _tileCtx = new();
        private SiemDashboardDoc _dashDoc = null!;
        private SiemDashboard _dash = null!;

        private SiemPipeline _pipeline = null!;        // the pipeline currently being edited
        private SiemPipelineSet _pipelineSet = null!;  // all named pipelines (C11)
        private ComboBox? _pipelineSelector;
        private SiemIndexSettings _indexSettings = null!;

        // Index management tab
        private TextBlock? _indexStats;
        private TextBox? _capBox, _ageBox;
        private ToggleButton? _persistChip;
        private DataGrid? _indexSrcGrid;
        private ObservableCollection<SiemSourceStat>? _indexSrcRows;
        private TabItem? _indexTab;
        private DataGrid? _auditGrid;
        private ObservableCollection<SiemAuditEntry>? _auditRows;

        // tab references (so navigation is order-independent)
        private TabItem? _securityTab, _overviewTab, _searchTab, _sourcesTab, _pipelineTab;

        // Entities tab (host/user analytics + risk)
        private TabItem? _entitiesTab;
        private DataGrid? _hostGrid, _userGrid;
        private ObservableCollection<SiemEntityStat>? _hostRows, _userRows;

        // Cases tab (SOC case management)
        private StackPanel? _caseListPanel;
        private Border? _caseDetailHost;
        private SiemCase? _selectedCase;

        // Timeline tab (investigation workspace)
        private StackPanel? _timelinePanel;
        private TextBlock? _timelineSummary;

        // Threat Intel tab
        private TabItem? _threatTab;
        private DataGrid? _indicatorGrid;
        private ObservableCollection<SiemIndicator>? _indicatorRows;
        private DataGrid? _tiMatchGrid;
        private ObservableCollection<SiemEvent>? _tiMatchRows;
        private TextBlock? _tiSummary;
        private TextBox? _tiValueBox;
        private ComboBox? _tiTypeBox;

        // Network tab
        private TabItem? _networkTab;
        private readonly List<(Border host, Func<UIElement> build)> _networkCards = new();
        private TextBlock? _networkKpis;

        private SiemQuery _query = SiemQuery.Parse(null);
        private SiemRange? _window = SiemRange.Rolling(TimeSpan.FromMinutes(15));
        private int _rangeMin = 15;
        private long _lastTotal; private DateTime _lastTick = DateTime.Now; private double _rate;

        private const double TileW = 384, TileH = 300, FeedCap = 400;

        // KPI value labels (updated each tick)
        private readonly Dictionary<string, TextBlock> _kpi = new();

        // Search tab (Discover)
        private DataGrid? _searchGrid;
        private ObservableCollection<SiemEvent>? _searchRows;
        private TextBlock? _searchCount;
        private readonly List<string> _columns = new();              // selected document columns
        private StackPanel? _fieldsPanel;
        private TextBox? _fieldSearch;
        private Border? _histoHost;
        private WrapPanel? _filterBar;
        private readonly HashSet<string> _openFieldPopovers = new();
        private readonly FieldValueConverter _fieldConv = new();

        // Saved searches (Discover saved objects)
        private Border? _savedSearchLabel;
        private TextBlock? _savedSearchText;
        private string? _currentSearchName;

        /// <summary>Binds a grid cell to any flat field of the row's SiemEvent (or its document summary).</summary>
        private sealed class FieldValueConverter : System.Windows.Data.IValueConverter
        {
            public object Convert(object value, Type t, object p, System.Globalization.CultureInfo c)
                => value is SiemEvent e ? ((p as string) == "__doc" ? e.Summary() : e.Get((string)p!) ?? "") : "";
            public object ConvertBack(object value, Type t, object p, System.Globalization.CultureInfo c) => throw new NotSupportedException();
        }

        // Sources tab
        private DataGrid? _machineGrid;
        private ObservableCollection<SiemSourceStat>? _machineRows;
        private DataGrid? _agentGrid;
        private ObservableCollection<AgentInfo>? _agentRows;
        private ToggleButton? _winChip, _sysChip, _sysTcpChip, _genChip, _httpChip;
        private WrapPanel? _tailHost;
        private Border? _localSourcesCard;
        private TextBlock? _droppedLabel;

        // Pipeline tab
        private ItemsControl? _pipelineList;
        private TextBlock? _pipelineSummary;
        private TextBlock? _pipelineTestResult;

        // Guide tab (animated onboarding)
        private readonly List<FrameworkElement> _guideCards = new();
        private readonly List<FontAwesome.Sharp.IconBlock> _guideChevrons = new();

        // Alerts tab (detection rules + triggered alerts)
        private readonly SiemRuleEngine _rules = SiemRuleEngine.Instance;
        private DataGrid? _alertGrid;
        private ObservableCollection<SiemAlert>? _alertRows;
        private ComboBox? _alertFilter;          // triage status filter (All/Open/Acknowledged/Closed)
        private ItemsControl? _rulesList;
        private TextBlock? _alertsSummary;
        private StackPanel? _toastHost;
        private TabItem? _alertsTab;
        private Border? _coverageHost;
        private TextBlock? _coverageSummary;

        public SiemDashboardPage()
        {
            InitializeComponent();

            _pipelineSet = SiemPipelineSetStore.Load();
            _pipeline = _pipelineSet.Main();   // the pipeline currently being edited (defaults to "main")
            _store.Pipeline = _pipelineSet.Main();

            _indexSettings = SiemIndexSettings.Load();
            _store.Capacity = _indexSettings.Capacity;
            _store.MaxAge = _indexSettings.MaxAgeMinutes > 0 ? TimeSpan.FromMinutes(_indexSettings.MaxAgeMinutes) : TimeSpan.Zero;
            _ing.HttpToken = _indexSettings.HttpIngestToken ?? "";
            SiemPersistence.Initialize(_indexSettings.PersistToDisk);

            _dashDoc = SiemDashboardStore.Load();
            _dash = _dashDoc.CurrentDashboard();
            _dash.Tiles = _dash.Tiles.Where(w => w.Type is not (SiemWidgetType.Stats or SiemWidgetType.Feed)).ToList();
            if (_dash.Tiles.Count == 0) _dash.Tiles = SiemWidget.Default();
            _tiles = _dash.Tiles;

            BuildKpis();
            BuildDashboardSwitcher();
            foreach (var w in _tiles) BuildTile(w);
            BuildSearchTab();
            BuildSourcesTab();
            BuildPipelineTab();
            BuildIndexTab();
            BuildEntitiesTab();
            BuildNetworkTab();
            BuildThreatIntelTab();
            BuildAlertsTab();
            BuildCasesTab();
            BuildTimelineTab();
            BuildGuideTab();
            // resolve tab references for order-independent navigation
            _securityTab = (SecurityHost.Parent as ScrollViewer)?.Parent as TabItem;
            _overviewTab = ((TilesHost.Parent as ScrollViewer)?.Parent as Grid)?.Parent as TabItem;
            _searchTab = SearchHost.Parent as TabItem;
            _sourcesTab = (SourcesHost.Parent as ScrollViewer)?.Parent as TabItem;
            _pipelineTab = PipelineHost.Parent as TabItem;
            BuildSecurityTab();
            SetupToastHost();

            RefreshAll();

            _store.EventAdded += OnEventAdded;
            _rules.AlertRaised += OnAlertRaised;
            _rules.AlertsChanged += OnAlertsChanged;
            _rules.RulesChanged += OnRulesChanged;
            SiemAgentRegistry.Instance.Changed += OnAgentsChanged;
            _rules.Start();
            _timer.Tick += (_, _) => RefreshAll();
            _timer.Start();
            Loaded += (_, _) => { HighlightRange(_rangeMin); AnimateGuide(); if (SiemWelcome.ShouldShow()) ShowWelcome(); };   // visual tree is realised by now
            Tabs.SelectionChanged += (s, e) =>
            {
                if (e.Source is not TabControl) return;
                if (ReferenceEquals(Tabs.SelectedItem, _securityTab)) RefreshSecurity();
                if (ReferenceEquals(Tabs.SelectedItem, _searchTab)) RefreshDiscoverChrome();
                if (ReferenceEquals(Tabs.SelectedItem, _alertsTab)) RefreshAlerts();
            };
            Unloaded += (_, _) =>
            {
                _store.EventAdded -= OnEventAdded;
                _rules.AlertRaised -= OnAlertRaised;
                _rules.AlertsChanged -= OnAlertsChanged;
                _rules.RulesChanged -= OnRulesChanged;
                SiemAgentRegistry.Instance.Changed -= OnAgentsChanged;
                _timer.Stop();
            };
        }

        /// <summary>When viewing a remote collector, hide the controls that toggle the local OS sources.</summary>
        public void ConfigureForRemote()
        {
            if (_localSourcesCard != null) _localSourcesCard.Visibility = Visibility.Collapsed;
        }

        private Brush Br(string key) => (Brush)FindResource(key);
        private Brush Hex(string c) => (Brush)_hex.Convert(c, typeof(Brush), null!, null!);

        // ════════════════════════════════════════════════════════════════════
        //  KPI strip
        // ════════════════════════════════════════════════════════════════════
        private void BuildKpis()
        {
            KpiHost.Items.Clear(); _kpi.Clear();
            void Kpi(string key, string label, string icon, string brush)
            {
                var card = new Border
                {
                    Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(10), Margin = new Thickness(0, 0, 10, 0), Padding = new Thickness(14, 10, 14, 10),
                };
                var g = new Grid();
                g.RowDefinitions.Add(new RowDefinition());
                g.RowDefinitions.Add(new RowDefinition());
                var top = new DockPanel();
                top.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.ChartBar, FontSize = 12, Foreground = Br(brush), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
                top.Children.Add(new TextBlock { Text = label, FontSize = 10, Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Center, FontWeight = FontWeights.SemiBold });
                Grid.SetRow(top, 0); g.Children.Add(top);
                var val = new TextBlock { Text = "0", FontSize = 24, FontWeight = FontWeights.Bold, Foreground = Br(brush), Margin = new Thickness(0, 2, 0, 0) };
                Grid.SetRow(val, 1); g.Children.Add(val);
                card.Child = g; KpiHost.Items.Add(card); _kpi[key] = val;
            }
            Kpi("total", "TOTAL EVENTS", "Database", "TextBrush");
            Kpi("window", "IN WINDOW", "Clock", "AccentBrush");
            Kpi("rate", "EVENTS / SEC", "Bolt", "SuccessBrush");
            Kpi("crit", "CRITICAL", "TriangleExclamation", "CriticalBrush");
            Kpi("high", "HIGH", "CircleExclamation", "WarningBrush");
            Kpi("machines", "MACHINES", "Server", "TextBrush");
            Kpi("dropped", "DROPPED (PIPELINE)", "Filter", "SubtleTextBrush");
            Kpi("queue", "INGEST QUEUE", "Inbox", "AccentBrush");
        }

        private void RefreshKpis()
        {
            var sev = _store.CountBySeverity(_query, _window);
            int machines = _store.SourceStats(_window).Count;
            void Set(string k, string v) { if (_kpi.TryGetValue(k, out var t)) t.Text = v; }
            Set("total", _store.TotalIngested.ToString("N0"));
            Set("window", sev.Values.Sum().ToString("N0"));
            Set("rate", _rate.ToString("0.0"));
            Set("crit", sev[SiemSeverity.Critical].ToString("N0"));
            Set("high", sev[SiemSeverity.High].ToString("N0"));
            Set("machines", machines.ToString("N0"));
            Set("dropped", _store.TotalDropped.ToString("N0"));
            var iq = SiemIngestQueue.Instance;
            Set("queue", iq.Depth.ToString("N0"));
            if (_kpi.TryGetValue("queue", out var qt))
                qt.ToolTip = $"Depth {iq.Depth:N0} · peak {iq.PeakDepth:N0} · processed {iq.TotalProcessed:N0} · dropped (back-pressure) {iq.TotalDropped:N0} · capacity {iq.Capacity:N0}";
        }

        // ════════════════════════════════════════════════════════════════════
        //  Overview tiles
        // ════════════════════════════════════════════════════════════════════
        private void BuildTile(SiemWidget w)
        {
            var card = new Border
            {
                Width = TileW, Height = TileH, Margin = new Thickness(0, 0, 14, 14),
                Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"),
                BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10),
                Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = Colors.Black, BlurRadius = 16, ShadowDepth = 2, Opacity = 0.18 },
            };
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var header = new Border { Padding = new Thickness(14, 11, 8, 9), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(0, 0, 0, 1) };
            var hd = new DockPanel();
            var rm = new Button { Content = "✕", Width = 22, Height = 22, Foreground = Br("SubtleTextBrush"), Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, ToolTip = "Remove panel" };
            rm.Click += (_, _) => RemoveTile(w);
            DockPanel.SetDock(rm, Dock.Right); hd.Children.Add(rm);
            if (w.Type == SiemWidgetType.Custom)
            {
                var edit = new Button { Width = 22, Height = 22, Foreground = Br("SubtleTextBrush"), Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, ToolTip = "Edit visualization" };
                edit.Content = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.PenToSquare, FontSize = 11 };
                edit.Click += (_, _) => EditCustomTile(w);
                DockPanel.SetDock(edit, Dock.Right); hd.Children.Add(edit);
            }
            hd.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(w.DisplayIcon(), out var ic) ? ic : FontAwesome.Sharp.IconChar.ChartBar, FontSize = 12, Foreground = Br("AccentBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            hd.Children.Add(new TextBlock { Text = w.DisplayTitle().ToUpperInvariant(), FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
            header.Child = hd; Grid.SetRow(header, 0); grid.Children.Add(header);

            var host = new Border { Padding = new Thickness(14, 10, 14, 12), ClipToBounds = true };
            Grid.SetRow(host, 1); grid.Children.Add(host);

            card.Child = grid;
            TilesHost.Children.Add(card);
            var ctx = new TileCtx { W = w, Card = card, Host = host };
            _tileCtx[w.Id] = ctx;
            RenderTile(ctx);
        }

        private void EditCustomTile(SiemWidget w)
        {
            var fields = _store.FieldNames(_query, _window).Select(f => f.field).ToList();
            if (!SiemVizDialog.Edit(Window.GetWindow(this), w, fields)) return;
            SaveDashboards();
            // rebuild the tile in place (header title/icon + body may have changed)
            if (_tileCtx.TryGetValue(w.Id, out var c))
            {
                int idx = TilesHost.Children.IndexOf(c.Card);
                TilesHost.Children.Remove(c.Card);
                _tileCtx.Remove(w.Id);
                BuildTile(w);
                // move the freshly-built tile back to its original position
                if (idx >= 0 && _tileCtx.TryGetValue(w.Id, out var nc))
                {
                    TilesHost.Children.Remove(nc.Card);
                    TilesHost.Children.Insert(Math.Min(idx, TilesHost.Children.Count), nc.Card);
                }
            }
        }

        private void RemoveTile(SiemWidget w)
        {
            if (_tileCtx.TryGetValue(w.Id, out var c)) TilesHost.Children.Remove(c.Card);
            _tileCtx.Remove(w.Id); _tiles.Remove(w);
            SaveDashboards();
        }

        private void RenderTile(TileCtx c)
        {
            switch (c.W.Type)
            {
                case SiemWidgetType.Histogram: c.Host.Child = BuildHistogram(); break;
                case SiemWidgetType.SeverityDonut: c.Host.Child = BuildSeverity(); break;
                case SiemWidgetType.TopSources: c.Host.Child = BuildTop(e => e.Host, "host", "#58A6FF"); break;
                case SiemWidgetType.TopCategories: c.Host.Child = BuildTop(e => e.Category, "category", "#56D364"); break;
                case SiemWidgetType.TopEventTypes: c.Host.Child = BuildTop(e => e.EventType, "type", "#E3B341"); break;
                case SiemWidgetType.Custom: c.Host.Child = BuildCustomTile(c.W); break;
                case SiemWidgetType.Watchlist:
                    if (c.Grid == null)
                    {
                        c.Rows = new ObservableCollection<SiemEvent>();
                        c.Grid = BuildEventGrid(compact: true);
                        c.Grid.ItemsSource = c.Rows;
                        c.Grid.MouseDoubleClick += (_, _) => { if (c.Grid!.SelectedItem is SiemEvent ev) AddFilter("host", ev.Host); };
                        c.Host.Child = WrapWithEmptyState(c.Grid, c.Rows, "ShieldHalved", "All clear", "No high or critical events in range.");
                        RebuildWatchlist(c);
                    }
                    break;
            }
        }

        private void RefreshTiles()
        {
            foreach (var c in _tileCtx.Values)
                if (c.W.Type != SiemWidgetType.Watchlist) RenderTile(c);
        }

        private void RebuildWatchlist(TileCtx c)
        {
            if (c.Rows == null) return;
            c.Rows.Clear();
            foreach (var e in _store.Query(_query, _window, (int)FeedCap))
                if (e.Severity >= SiemSeverity.High) c.Rows.Add(e);
        }

        // ── chart builders ──
        private UIElement BuildHistogram() => BuildHistogram(TileH - 92, 40, 7);

        private UIElement BuildHistogram(double h, int buckets, double barWidth)
        {
            var hWindow = _window ?? (SiemRange)TimeSpan.FromHours(1);
            var data = _store.Histogram(_query, hWindow, buckets);
            int max = Math.Max(1, data.Max());
            var grad = new LinearGradientBrush { StartPoint = new Point(0, 0), EndPoint = new Point(0, 1) };
            grad.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString("#79C0FF"), 0));
            grad.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString("#1F6FEB"), 1));
            var bars = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Bottom, HorizontalAlignment = HorizontalAlignment.Center };
            foreach (var v in data)
                bars.Children.Add(new Rectangle { Width = barWidth, Height = Math.Max(v > 0 ? 3 : 0, v / (double)max * h), Margin = new Thickness(1.4, 0, 1.4, 0), RadiusX = 2, RadiusY = 2, Fill = grad, VerticalAlignment = VerticalAlignment.Bottom, ToolTip = $"{v} events" });
            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(bars, 0); root.Children.Add(bars);
            var axis = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
            axis.Children.Add(new TextBlock { Text = RangeLabel(), FontSize = 10, Foreground = Br("SubtleTextBrush") });
            var peak = new TextBlock { Text = $"peak {max}", FontSize = 10, Foreground = Br("SubtleTextBrush"), HorizontalAlignment = HorizontalAlignment.Right };
            DockPanel.SetDock(peak, Dock.Right); axis.Children.Add(peak);
            Grid.SetRow(axis, 1); root.Children.Add(axis);
            return root;
        }

        private string RangeLabel() => _window?.Label() ?? "all time";

        /// <summary>The Discover histogram with drag-to-zoom: select a span to set an absolute range.</summary>
        private UIElement BuildBrushHistogram(double h, int buckets)
        {
            var range = _window ?? (SiemRange)TimeSpan.FromHours(1);
            var data = _store.Histogram(_query, range, buckets);
            int max = Math.Max(1, data.Max());
            var grad = new LinearGradientBrush { StartPoint = new Point(0, 0), EndPoint = new Point(0, 1) };
            grad.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString("#79C0FF"), 0));
            grad.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString("#1F6FEB"), 1));

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // bars fill the width evenly so x maps linearly to time
            var bars = new UniformGrid { Rows = 1, Columns = buckets, VerticalAlignment = VerticalAlignment.Bottom };
            foreach (var v in data)
            {
                var cell = new Grid();
                cell.Children.Add(new Rectangle { Height = Math.Max(v > 0 ? 3 : 0, v / (double)max * h), Margin = new Thickness(1.2, 0, 1.2, 0), RadiusX = 2, RadiusY = 2, Fill = grad, VerticalAlignment = VerticalAlignment.Bottom, ToolTip = $"{v} events" });
                bars.Children.Add(cell);
            }
            Grid.SetRow(bars, 0); root.Children.Add(bars);

            // transparent brushing overlay + selection rectangle
            var overlay = new Canvas { Background = Brushes.Transparent, ClipToBounds = true, Cursor = Cursors.IBeam, ToolTip = "Drag to zoom to a time range" };
            var sel = new Rectangle { Fill = Hex("#58A6FF"), Opacity = 0.25, Stroke = Br("AccentBrush"), StrokeThickness = 1, Visibility = Visibility.Collapsed };
            overlay.Children.Add(sel);
            double startX = 0; bool dragging = false;
            overlay.MouseLeftButtonDown += (_, e) =>
            {
                startX = e.GetPosition(overlay).X; dragging = true;
                Canvas.SetLeft(sel, startX); Canvas.SetTop(sel, 0); sel.Width = 0; sel.Height = overlay.ActualHeight; sel.Visibility = Visibility.Visible;
                overlay.CaptureMouse();
            };
            overlay.MouseMove += (_, e) =>
            {
                if (!dragging) return;
                double x = e.GetPosition(overlay).X, l = Math.Min(x, startX), w = Math.Abs(x - startX);
                Canvas.SetLeft(sel, l); sel.Width = w;
            };
            overlay.MouseLeftButtonUp += (_, e) =>
            {
                if (!dragging) return;
                dragging = false; overlay.ReleaseMouseCapture(); sel.Visibility = Visibility.Collapsed;
                double w = overlay.ActualWidth; if (w <= 0) return;
                double endX = e.GetPosition(overlay).X;
                double f1 = Math.Clamp(Math.Min(startX, endX) / w, 0, 1), f2 = Math.Clamp(Math.Max(startX, endX) / w, 0, 1);
                if (f2 - f1 < 0.02) return;   // ignore a click / tiny drag
                var span = range.Span.TotalMilliseconds;
                var from = range.From.AddMilliseconds(span * f1);
                var to = range.From.AddMilliseconds(span * f2);
                ApplyAbsoluteRange(from, to);
            };
            Grid.SetRow(overlay, 0); root.Children.Add(overlay);

            var axis = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
            axis.Children.Add(new TextBlock { Text = RangeLabel() + "  ·  drag to zoom", FontSize = 10, Foreground = Br("SubtleTextBrush") });
            var peak = new TextBlock { Text = $"peak {max}", FontSize = 10, Foreground = Br("SubtleTextBrush"), HorizontalAlignment = HorizontalAlignment.Right };
            DockPanel.SetDock(peak, Dock.Right); axis.Children.Add(peak);
            Grid.SetRow(axis, 1); root.Children.Add(axis);
            return root;
        }

        private UIElement BuildSeverity()
        {
            var counts = _store.CountBySeverity(_query, _window);
            int total = counts.Values.Sum();
            var root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            double size = 150;
            var canvas = new Canvas { Width = size, Height = size, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 14, 0) };
            double cx = size / 2, cy = size / 2, R = size / 2 - 4;
            var order = new (SiemSeverity s, string c)[] { (SiemSeverity.Critical, "#F85149"), (SiemSeverity.High, "#FF7B72"), (SiemSeverity.Medium, "#E3B341"), (SiemSeverity.Low, "#58A6FF"), (SiemSeverity.Info, "#8B949E") };
            double a0 = -90;
            if (total == 0)
                canvas.Children.Add(new Ellipse { Width = size, Height = size, Stroke = Br("BorderBrush"), StrokeThickness = 2, Fill = Brushes.Transparent });
            else
                foreach (var (s, col) in order)
                {
                    if (counts[s] == 0) continue;
                    double sweep = 360.0 * counts[s] / total;
                    var slice = PieSlice(cx, cy, R, a0, a0 + sweep, col);
                    slice.ToolTip = $"{s}: {counts[s]}";
                    var sevName = s.ToString();
                    slice.MouseLeftButtonDown += (_, _) => AddFilter("severity", sevName);
                    canvas.Children.Add(slice); a0 += sweep;
                }
            var hole = new Ellipse { Width = R * 1.15, Height = R * 1.15, Fill = Br("SecondaryBackgroundBrush") };
            Canvas.SetLeft(hole, cx - R * 0.575); Canvas.SetTop(hole, cy - R * 0.575);
            canvas.Children.Add(hole);
            var center = new StackPanel { Width = size };
            Canvas.SetLeft(center, 0); Canvas.SetTop(center, cy - 18);
            center.Children.Add(new TextBlock { Text = total.ToString("N0"), FontSize = 22, FontWeight = FontWeights.Bold, Foreground = Br("TextBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            center.Children.Add(new TextBlock { Text = "events", FontSize = 10, Foreground = Br("SubtleTextBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            canvas.Children.Add(center);
            Grid.SetColumn(canvas, 0); root.Children.Add(canvas);

            var legend = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            foreach (var (s, col) in order)
            {
                var row = new DockPanel { Margin = new Thickness(0, 3, 0, 3), Cursor = Cursors.Hand };
                var sevName = s.ToString();
                row.MouseLeftButtonDown += (_, _) => AddFilter("severity", sevName);
                row.Children.Add(new Ellipse { Width = 9, Height = 9, Fill = Hex(col), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
                var cnt = new TextBlock { Text = counts[s].ToString("N0"), Foreground = Br("SubtleTextBrush"), FontSize = 12 };
                DockPanel.SetDock(cnt, Dock.Right); row.Children.Add(cnt);
                row.Children.Add(new TextBlock { Text = s.ToString(), Foreground = Br("TextBrush"), FontSize = 12, VerticalAlignment = VerticalAlignment.Center });
                legend.Children.Add(row);
            }
            Grid.SetColumn(legend, 1); root.Children.Add(legend);
            return root;
        }

        private Path PieSlice(double cx, double cy, double R, double a0, double a1, string color)
        {
            Point P(double deg) { double r = deg * Math.PI / 180; return new Point(cx + R * Math.Cos(r), cy + R * Math.Sin(r)); }
            var fig = new PathFigure { StartPoint = new Point(cx, cy), IsClosed = true };
            fig.Segments.Add(new LineSegment(P(a0), true));
            fig.Segments.Add(new ArcSegment(P(a1), new Size(R, R), 0, (a1 - a0) > 180, SweepDirection.Clockwise, true));
            var geo = new PathGeometry(); geo.Figures.Add(fig);
            return new Path { Data = geo, Fill = Hex(color), Cursor = Cursors.Hand };
        }

        private UIElement BuildTop(Func<SiemEvent, string> sel, string field, string color)
            => BuildBars(_store.TopBy(sel, _query, _window, 8), field, color);

        private UIElement BuildBars(List<(string key, int count)> top, string field, string color)
        {
            int max = Math.Max(1, top.Count == 0 ? 1 : top.Max(t => t.count));
            var sp = new StackPanel();
            if (top.Count == 0)
                sp.Children.Add(new TextBlock { Text = "No data in range", Foreground = Br("SubtleTextBrush"), FontSize = 12, Margin = new Thickness(0, 8, 0, 0) });
            foreach (var (key, count) in top)
            {
                var g = new Grid { Margin = new Thickness(0, 3, 0, 3), Cursor = Cursors.Hand };
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                var label = string.IsNullOrEmpty(key) ? "(none)" : key;
                g.MouseLeftButtonDown += (_, _) => AddFilter(field, label);
                var lab = new TextBlock { Text = label, Foreground = Br("TextBrush"), FontSize = 12, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(lab, 0); g.Children.Add(lab);
                var track = new Border { Height = 14, Background = Br("BackgroundBrush"), CornerRadius = new CornerRadius(3), VerticalAlignment = VerticalAlignment.Center };
                var fill = new Rectangle { Height = 14, RadiusX = 3, RadiusY = 3, HorizontalAlignment = HorizontalAlignment.Left, Fill = Hex(color), Width = count / (double)max * 120.0 };
                track.Child = fill; Grid.SetColumn(track, 1); g.Children.Add(track);
                var cnt = new TextBlock { Text = count.ToString("N0"), Foreground = Br("SubtleTextBrush"), FontSize = 12, Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(cnt, 2); g.Children.Add(cnt);
                sp.Children.Add(g);
            }
            return new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = sp };
        }

        // ── config-driven (Lens-style) custom visualization ──
        private static readonly string[] _vizPalette = { "#58A6FF", "#56D364", "#E3B341", "#FF7B72", "#BC8CFF", "#F778BA", "#79C0FF", "#7EE787" };

        private UIElement BuildCustomTile(SiemWidget w)
        {
            bool needsField = w.Chart switch
            {
                SiemChart.Line => false,
                SiemChart.Metric or SiemChart.Gauge => w.Agg != SiemAgg.Count,
                _ => true,
            };
            if (needsField && string.IsNullOrWhiteSpace(w.Field))
                return EmptyTileText("Pick a field for this visualization.");

            switch (w.Chart)
            {
                case SiemChart.Gauge:
                    return BuildGauge(w);
                case SiemChart.Heatmap:
                    return BuildHeatmap(w);
                case SiemChart.Treemap:
                    return BuildTreemap(_store.TopByField(w.Field, _query, _window, Math.Max(2, w.TopN)), w.Field);
                case SiemChart.Metric:
                {
                    double val = _store.Metric(w.Agg, w.Field, _query, _window);
                    var sp = new StackPanel { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
                    sp.Children.Add(new TextBlock { Text = w.Agg == SiemAgg.Average ? val.ToString("N1") : val.ToString("N0"), FontSize = 46, FontWeight = FontWeights.Bold, Foreground = Br("AccentBrush"), HorizontalAlignment = HorizontalAlignment.Center });
                    sp.Children.Add(new TextBlock { Text = w.DisplayTitle(), FontSize = 11, Foreground = Br("SubtleTextBrush"), HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center, TextWrapping = TextWrapping.Wrap });
                    return sp;
                }
                case SiemChart.Line:
                    return BuildHistogram(TileH - 92, 40, 7);
                case SiemChart.Donut:
                    return BuildDataDonut(_store.TopByField(w.Field, _query, _window, Math.Max(2, w.TopN)), w.Field);
                case SiemChart.Table:
                    return BuildDataTable(_store.TopByField(w.Field, _query, _window, Math.Max(2, w.TopN)), w.Field);
                default:
                    return BuildBars(_store.TopByField(w.Field, _query, _window, Math.Max(2, w.TopN)), w.Field, "#58A6FF");
            }
        }

        private UIElement BuildDataDonut(List<(string key, int count)> data, string field)
        {
            int total = data.Sum(d => d.count);
            var root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            double size = 150;
            var canvas = new Canvas { Width = size, Height = size, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 14, 0) };
            double cx = size / 2, cy = size / 2, R = size / 2 - 4, a0 = -90;
            if (total == 0)
                canvas.Children.Add(new Ellipse { Width = size, Height = size, Stroke = Br("BorderBrush"), StrokeThickness = 2, Fill = Brushes.Transparent });
            else
                for (int i = 0; i < data.Count; i++)
                {
                    double sweep = 360.0 * data[i].count / total;
                    var col = _vizPalette[i % _vizPalette.Length];
                    var slice = PieSlice(cx, cy, R, a0, a0 + sweep, col);
                    var label = string.IsNullOrEmpty(data[i].key) ? "(none)" : data[i].key;
                    slice.ToolTip = $"{label}: {data[i].count}";
                    slice.MouseLeftButtonDown += (_, _) => AddFilter(field, label);
                    canvas.Children.Add(slice); a0 += sweep;
                }
            var hole = new Ellipse { Width = R * 1.15, Height = R * 1.15, Fill = Br("SecondaryBackgroundBrush") };
            Canvas.SetLeft(hole, cx - R * 0.575); Canvas.SetTop(hole, cy - R * 0.575);
            canvas.Children.Add(hole);
            var center = new StackPanel { Width = size };
            Canvas.SetLeft(center, 0); Canvas.SetTop(center, cy - 18);
            center.Children.Add(new TextBlock { Text = total.ToString("N0"), FontSize = 22, FontWeight = FontWeights.Bold, Foreground = Br("TextBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            center.Children.Add(new TextBlock { Text = "total", FontSize = 10, Foreground = Br("SubtleTextBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            canvas.Children.Add(center);
            Grid.SetColumn(canvas, 0); root.Children.Add(canvas);

            var legend = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            for (int i = 0; i < data.Count; i++)
            {
                var label = string.IsNullOrEmpty(data[i].key) ? "(none)" : data[i].key;
                var row = new DockPanel { Margin = new Thickness(0, 3, 0, 3), Cursor = Cursors.Hand };
                row.MouseLeftButtonDown += (_, _) => AddFilter(field, label);
                row.Children.Add(new Ellipse { Width = 9, Height = 9, Fill = Hex(_vizPalette[i % _vizPalette.Length]), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
                var cnt = new TextBlock { Text = data[i].count.ToString("N0"), Foreground = Br("SubtleTextBrush"), FontSize = 12 };
                DockPanel.SetDock(cnt, Dock.Right); row.Children.Add(cnt);
                row.Children.Add(new TextBlock { Text = label, Foreground = Br("TextBrush"), FontSize = 12, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
                legend.Children.Add(row);
            }
            if (data.Count == 0) legend.Children.Add(new TextBlock { Text = "No data in range", Foreground = Br("SubtleTextBrush"), FontSize = 12 });
            Grid.SetColumn(legend, 1); root.Children.Add(new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = legend });
            Grid.SetColumn(root.Children[^1], 1);
            return root;
        }

        private UIElement BuildDataTable(List<(string key, int count)> data, string field)
        {
            var sp = new StackPanel();
            if (data.Count == 0)
                sp.Children.Add(new TextBlock { Text = "No data in range", Foreground = Br("SubtleTextBrush"), FontSize = 12, Margin = new Thickness(0, 8, 0, 0) });
            foreach (var (key, count) in data)
            {
                var label = string.IsNullOrEmpty(key) ? "(none)" : key;
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 0), Cursor = Cursors.Hand, Height = 26 };
                row.MouseLeftButtonDown += (_, _) => AddFilter(field, label);
                var cnt = new TextBlock { Text = count.ToString("N0"), Foreground = Br("AccentBrush"), FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
                DockPanel.SetDock(cnt, Dock.Right); row.Children.Add(cnt);
                row.Children.Add(new TextBlock { Text = label, Foreground = Br("TextBrush"), FontSize = 12, FontFamily = new FontFamily("Consolas"), VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
                var wrap = new Border { BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = row };
                sp.Children.Add(wrap);
            }
            return new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = sp };
        }

        private UIElement EmptyTileText(string msg) => new TextBlock
        {
            Text = msg, Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center,
        };

        /// <summary>A speedometer-style gauge of a single metric against an auto-scaled "nice" maximum.</summary>
        private UIElement BuildGauge(SiemWidget w)
        {
            double val = _store.Metric(w.Agg, w.Field, _query, _window);
            double max = NiceMax(val);
            double frac = max > 0 ? Math.Clamp(val / max, 0, 1) : 0;
            const double size = 150;
            double cx = size, cy = size * 0.92, R = size * 0.78;
            var canvas = new Canvas { Width = size * 2, Height = size };
            canvas.Children.Add(GaugeArc(cx, cy, R, 180, 360, Br("BorderBrush"), 14));
            if (frac > 0) canvas.Children.Add(GaugeArc(cx, cy, R, 180, 180 + 180 * frac, Br("AccentBrush"), 14));
            var center = new StackPanel { Width = R * 2 };
            Canvas.SetLeft(center, cx - R); Canvas.SetTop(center, cy - 46);
            center.Children.Add(new TextBlock { Text = w.Agg == SiemAgg.Average ? val.ToString("N1") : val.ToString("N0"), FontSize = 34, FontWeight = FontWeights.Bold, Foreground = Br("AccentBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            center.Children.Add(new TextBlock { Text = $"of {max:N0}", FontSize = 11, Foreground = Br("SubtleTextBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            canvas.Children.Add(center);
            return new Viewbox { Child = canvas, Stretch = Stretch.Uniform, MaxHeight = TileH - 36, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        }

        private System.Windows.Shapes.Path GaugeArc(double cx, double cy, double R, double a0, double a1, Brush stroke, double thick)
        {
            Point Polar(double deg) { double r = deg * Math.PI / 180; return new Point(cx + R * Math.Cos(r), cy + R * Math.Sin(r)); }
            var fig = new PathFigure { StartPoint = Polar(a0), IsClosed = false };
            fig.Segments.Add(new ArcSegment(Polar(a1), new Size(R, R), 0, (a1 - a0) > 180, SweepDirection.Clockwise, true));
            var g = new PathGeometry(); g.Figures.Add(fig);
            return new System.Windows.Shapes.Path { Data = g, Stroke = stroke, StrokeThickness = thick, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
        }

        /// <summary>Round a value up to the next 1/2/2.5/5/10 × 10^k for a tidy gauge scale.</summary>
        private static double NiceMax(double v)
        {
            if (v <= 0) return 1;
            double mag = Math.Pow(10, Math.Floor(Math.Log10(v)));
            foreach (var m in new[] { 1.0, 2, 2.5, 5, 10 }) if (mag * m >= v) return mag * m;
            return mag * 10;
        }

        /// <summary>A squarified treemap of a field's top values, sized by count. Laid out on resize.</summary>
        private UIElement BuildTreemap(List<(string key, int count)> data, string field)
        {
            if (data.Count == 0) return EmptyTileText("No data in range");
            var canvas = new Canvas { ClipToBounds = true };
            void Relayout()
            {
                canvas.Children.Clear();
                double W = canvas.ActualWidth, H = canvas.ActualHeight;
                if (W <= 1 || H <= 1) return;
                var values = data.Select(d => (double)d.count).ToList();
                foreach (var t in SiemTreemap.Layout(values, W, H))
                {
                    var (key, count) = data[t.Index];
                    var label = string.IsNullOrEmpty(key) ? "(none)" : key;
                    var cell = new Border
                    {
                        Width = Math.Max(0, t.W - 2), Height = Math.Max(0, t.H - 2),
                        Background = Hex(_vizPalette[t.Index % _vizPalette.Length]), CornerRadius = new CornerRadius(3),
                        Cursor = Cursors.Hand, ToolTip = $"{label}: {count:N0}",
                        Child = new TextBlock { Text = $"{label}\n{count:N0}", Foreground = Brushes.White, FontSize = 11, Margin = new Thickness(5, 3, 3, 3), TextTrimming = TextTrimming.CharacterEllipsis },
                    };
                    cell.MouseLeftButtonDown += (_, _) => AddFilter(field, label);
                    Canvas.SetLeft(cell, t.X); Canvas.SetTop(cell, t.Y);
                    canvas.Children.Add(cell);
                }
            }
            canvas.SizeChanged += (_, _) => Relayout();
            return canvas;
        }

        /// <summary>A field-over-time heat map: top values (rows) × time buckets (cols), intensity = count.</summary>
        private UIElement BuildHeatmap(SiemWidget w)
        {
            const int buckets = 12;
            var (rows, matrix) = _store.HeatmapByField(w.Field, _query, _window, buckets, Math.Max(2, w.TopN));
            if (rows.Count == 0) return EmptyTileText("No data in range");
            int max = 1; foreach (var r in matrix) foreach (var c in r) if (c > max) max = c;
            var accent = ((SolidColorBrush)Br("AccentBrush")).Color;
            var outer = new StackPanel();
            for (int i = 0; i < rows.Count; i++)
            {
                var rowPanel = new DockPanel { Height = 24, Margin = new Thickness(0, 0, 0, 2) };
                var label = string.IsNullOrEmpty(rows[i]) ? "(none)" : rows[i];
                var lbl = new TextBlock { Text = label, Width = 130, Foreground = Br("TextBrush"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
                DockPanel.SetDock(lbl, Dock.Left); rowPanel.Children.Add(lbl);
                var ug = new System.Windows.Controls.Primitives.UniformGrid { Rows = 1, Columns = buckets };
                for (int b = 0; b < buckets; b++)
                {
                    int cnt = matrix[i][b];
                    double a = (double)cnt / max;
                    var cell = new Border
                    {
                        Background = cnt > 0 ? new SolidColorBrush(Color.FromArgb((byte)(40 + a * 215), accent.R, accent.G, accent.B)) : Br("SecondaryBackgroundBrush"),
                        Margin = new Thickness(1), CornerRadius = new CornerRadius(2),
                        ToolTip = $"{label} · bucket {b + 1}: {cnt:N0}",
                    };
                    ug.Children.Add(cell);
                }
                rowPanel.Children.Add(ug);
                outer.Children.Add(rowPanel);
            }
            return new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = outer };
        }

        // ════════════════════════════════════════════════════════════════════
        //  Search tab — a Kibana-style Discover (fields sidebar, columns, expand)
        // ════════════════════════════════════════════════════════════════════
        private void BuildSearchTab()
        {
            SearchHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            SearchHost.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // toolbar: hit count + saved searches + reset columns
            var bar = new DockPanel { Margin = new Thickness(16, 12, 16, 8) };

            var rightTools = new StackPanel { Orientation = Orientation.Horizontal };
            DockPanel.SetDock(rightTools, Dock.Right);

            var openBtn = ToolbarButton("FolderOpen", "Open", "Open a saved search");
            openBtn.Click += (_, _) => OpenSavedMenu(openBtn);
            var saveBtn = ToolbarButton("FloppyDisk", "Save search", "Save the current query, columns and time range");
            saveBtn.Click += (_, _) => SaveCurrentSearch();
            var exportBtn = ToolbarButton("FileCsv", "Export CSV", "Export the matching events to a CSV file");
            exportBtn.Click += (_, _) => ExportCsv();
            var resetCols = new Button { Content = "Reset columns", Style = (Style)FindResource("GhostButtonStyle"), Height = 28, FontSize = 11, Margin = new Thickness(6, 0, 0, 0) };
            resetCols.Click += (_, _) => { _columns.Clear(); RebuildColumns(); RefreshFields(); };
            rightTools.Children.Add(openBtn);
            rightTools.Children.Add(saveBtn);
            rightTools.Children.Add(exportBtn);
            rightTools.Children.Add(resetCols);
            bar.Children.Add(rightTools);

            var leftInfo = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            _searchCount = new TextBlock { Foreground = Br("TextBrush"), FontSize = 13, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
            leftInfo.Children.Add(_searchCount);
            _savedSearchLabel = new Border
            {
                Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("AccentBrush"), BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(12, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center, Visibility = Visibility.Collapsed,
            };
            _savedSearchText = new TextBlock { Foreground = Br("AccentBrush"), FontSize = 11, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
            _savedSearchLabel.Child = _savedSearchText;
            leftInfo.Children.Add(_savedSearchLabel);
            bar.Children.Add(leftInfo);

            Grid.SetRow(bar, 0); SearchHost.Children.Add(bar);

            // body: fields sidebar | results
            var body = new Grid { Margin = new Thickness(16, 0, 16, 16) };
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(248) });
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var sidebar = BuildFieldsSidebar();
            Grid.SetColumn(sidebar, 0); body.Children.Add(sidebar);

            var results = new Grid { Margin = new Thickness(12, 0, 0, 0) };
            results.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // filter pills
            results.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // histogram
            results.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            _filterBar = new WrapPanel { Orientation = Orientation.Horizontal };
            Grid.SetRow(_filterBar, 0); results.Children.Add(_filterBar);
            _histoHost = new Border { Height = 78, Margin = new Thickness(0, 0, 0, 10), Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(10, 6, 10, 4) };
            Grid.SetRow(_histoHost, 1); results.Children.Add(_histoHost);

            _searchRows = new ObservableCollection<SiemEvent>();
            _searchGrid = BuildDiscoverGrid();
            _searchGrid.ItemsSource = _searchRows;
            var gridWrap = new Border
            {
                CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1),
                Child = WrapWithEmptyState(_searchGrid, _searchRows, "MagnifyingGlass", "No matching events", "Adjust the search or time range — or wait for new events to stream in."),
            };
            Grid.SetRow(gridWrap, 2); results.Children.Add(gridWrap);
            Grid.SetColumn(results, 1); body.Children.Add(results);
            Grid.SetRow(body, 1); SearchHost.Children.Add(body);

            RebuildColumns();
            RefreshFields();
        }

        /// <summary>A compact themed toolbar button with a centered icon + label (consistent look).</summary>
        private Button ToolbarButton(string icon, string label, string tip)
        {
            var content = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            content.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 7, 0) });
            content.Children.Add(new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center });
            return new Button { Content = content, Style = (Style)FindResource("GhostButtonStyle"), Height = 28, FontSize = 11, Margin = new Thickness(0, 0, 6, 0), ToolTip = tip, Padding = new Thickness(12, 0, 12, 0) };
        }

        // ── saved searches ──
        private void SaveCurrentSearch()
        {
            var name = TextPromptDialog.Ask(Window.GetWindow(this), "Save search", "NAME THIS SAVED SEARCH", _currentSearchName ?? "", "Save");
            if (string.IsNullOrWhiteSpace(name)) return;
            var s = new SiemSavedSearch
            {
                Name = name,
                Query = SearchBox.Text ?? "",
                Columns = new List<string>(_columns),
                RangeMinutes = _rangeMin,
            };
            SiemSavedSearchStore.Upsert(s);
            _currentSearchName = name;
            UpdateSavedSearchLabel();
        }

        private void ApplySavedSearch(SiemSavedSearch s)
        {
            _columns.Clear();
            _columns.AddRange(s.Columns);
            RebuildColumns();
            _rangeMin = s.RangeMinutes;
            _window = s.RangeMinutes == 0 ? null : SiemRange.Rolling(TimeSpan.FromMinutes(s.RangeMinutes));
            HighlightRange(_rangeMin);
            SearchBox.Text = s.Query;   // may trigger TextChanged → ApplyQuery
            ApplyQuery();               // ensure applied even when the text is unchanged
            RecordSearchHistory(s.Query);
            _currentSearchName = s.Name;
            UpdateSavedSearchLabel();
            Tabs.SelectedItem = _searchTab;
        }

        private void UpdateSavedSearchLabel()
        {
            if (_savedSearchLabel == null || _savedSearchText == null) return;
            if (string.IsNullOrEmpty(_currentSearchName)) { _savedSearchLabel.Visibility = Visibility.Collapsed; return; }
            _savedSearchText.Text = "★ " + _currentSearchName;
            _savedSearchLabel.Visibility = Visibility.Visible;
        }

        private void OpenSavedMenu(Button anchor)
        {
            var menu = new ContextMenu();
            var all = SiemSavedSearchStore.Load();
            if (all.Count == 0)
            {
                menu.Items.Add(new MenuItem { Header = "No saved searches yet", IsEnabled = false });
            }
            else
            {
                foreach (var s in all)
                {
                    var captured = s;
                    var mi = new MenuItem { Header = $"{s.Name}     ({s.RangeText})" };
                    mi.Click += (_, _) => ApplySavedSearch(captured);
                    menu.Items.Add(mi);
                }
                menu.Items.Add(new Separator());
                var delMenu = new MenuItem { Header = "Delete a saved search" };
                foreach (var s in all)
                {
                    var captured = s;
                    var di = new MenuItem { Header = s.Name };
                    di.Click += (_, _) =>
                    {
                        SiemSavedSearchStore.Delete(captured.Id);
                        if (string.Equals(_currentSearchName, captured.Name, StringComparison.OrdinalIgnoreCase))
                        { _currentSearchName = null; UpdateSavedSearchLabel(); }
                    };
                    delMenu.Items.Add(di);
                }
                menu.Items.Add(delMenu);
            }
            menu.PlacementTarget = anchor; menu.IsOpen = true;
        }

        // ── CSV export of the result set ──
        private void ExportCsv()
        {
            var cols = _columns.Count > 0
                ? new List<string>(_columns)
                : new List<string> { "@timestamp", "log.level", "event.category", "event.action", "host.name", "observer.name", "message" };

            var rows = _store.Query(_query, _window, 100_000);
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "CSV file (*.csv)|*.csv|All files (*.*)|*.*",
                FileName = $"siem-export-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
                Title = "Export matching events to CSV",
            };
            if (dlg.ShowDialog() != true) return;

            var sb = new System.Text.StringBuilder();
            sb.AppendLine(string.Join(",", cols.Select(CsvCell)));
            foreach (var e in rows)
                sb.AppendLine(string.Join(",", cols.Select(c => CsvCell(e.Get(c) ?? ""))));

            try
            {
                System.IO.File.WriteAllText(dlg.FileName, sb.ToString(), new System.Text.UTF8Encoding(true));
                if (_searchCount != null) _searchCount.Text = $"Exported {rows.Count:N0} event(s) to {System.IO.Path.GetFileName(dlg.FileName)}";
            }
            catch (Exception ex)
            {
                MessageBox.Show(Window.GetWindow(this), $"Could not write the file:\n{ex.Message}", "Export failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private static string CsvCell(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            if (s.Contains(',') || s.Contains('"') || s.Contains('\n') || s.Contains('\r'))
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        // ── fields sidebar ──
        private UIElement BuildFieldsSidebar()
        {
            var card = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8) };
            var g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            var head = new StackPanel { Margin = new Thickness(12, 12, 12, 6) };
            head.Children.Add(new TextBlock { Text = "FIELDS", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush") });
            var searchWrap = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 8, 0, 0) };
            _fieldSearch = new TextBox { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Foreground = Br("TextBrush"), FontSize = 12, VerticalContentAlignment = VerticalAlignment.Center };
            _fieldSearch.TextChanged += (_, _) => RefreshFields();
            searchWrap.Child = _fieldSearch;
            head.Children.Add(searchWrap);
            Grid.SetRow(head, 0); g.Children.Add(head);
            _fieldsPanel = new StackPanel { Margin = new Thickness(6, 4, 6, 8) };
            var sv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _fieldsPanel };
            Grid.SetRow(sv, 1); g.Children.Add(sv);
            card.Child = g;
            return card;
        }

        private void RefreshFields()
        {
            if (_fieldsPanel == null) return;
            _fieldsPanel.Children.Clear();
            string filter = _fieldSearch?.Text?.Trim() ?? "";
            var names = _store.FieldNames(_query, _window);
            var docCounts = names.ToDictionary(n => n.field, n => n.docs, StringComparer.OrdinalIgnoreCase);

            if (_columns.Count > 0)
            {
                _fieldsPanel.Children.Add(FieldSection($"SELECTED FIELDS"));
                foreach (var f in _columns) _fieldsPanel.Children.Add(FieldRow(f, true, docCounts.GetValueOrDefault(f)));
                _fieldsPanel.Children.Add(FieldSection("AVAILABLE FIELDS"));
            }
            foreach (var (f, docs) in names)
            {
                if (_columns.Contains(f)) continue;
                if (filter.Length > 0 && !f.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
                _fieldsPanel.Children.Add(FieldRow(f, false, docs));
            }
            if (names.Count == 0)
                _fieldsPanel.Children.Add(new TextBlock { Text = "No fields yet — waiting for events.", Foreground = Br("SubtleTextBrush"), FontSize = 11, Margin = new Thickness(6, 8, 6, 0), TextWrapping = TextWrapping.Wrap });
        }

        private TextBlock FieldSection(string text) => new()
        { Text = text, FontSize = 9.5, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(6, 10, 0, 4) };

        private UIElement FieldRow(string field, bool isSelected, int docs)
        {
            var container = new StackPanel();
            var row = new Grid { Cursor = Cursors.Hand, Background = Brushes.Transparent, Margin = new Thickness(0, 1, 0, 1) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var icon = new FontAwesome.Sharp.IconBlock { Icon = FieldIcon(field), FontSize = 10, Foreground = Br("AccentBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 7, 0), Width = 12 };
            Grid.SetColumn(icon, 0); row.Children.Add(icon);
            var name = new TextBlock { Text = field, Foreground = Br("TextBrush"), FontSize = 12, FontFamily = new FontFamily("Consolas"), TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, ToolTip = field };
            Grid.SetColumn(name, 1); row.Children.Add(name);
            var addBtn = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Width = 22, Height = 20, Foreground = Br("SubtleTextBrush"), ToolTip = isSelected ? "Remove column" : "Add as column" };
            addBtn.Content = new FontAwesome.Sharp.IconBlock { Icon = isSelected ? FontAwesome.Sharp.IconChar.Xmark : FontAwesome.Sharp.IconChar.Plus, FontSize = 11 };
            addBtn.Click += (_, _) => ToggleColumn(field);
            Grid.SetColumn(addBtn, 2); row.Children.Add(addBtn);
            row.MouseLeftButtonUp += (_, _) =>
            {
                if (_openFieldPopovers.Contains(field)) _openFieldPopovers.Remove(field); else _openFieldPopovers.Add(field);
                RefreshFields();
            };
            row.MouseEnter += (_, _) => row.Background = Br("HoverBrush");
            row.MouseLeave += (_, _) => row.Background = Brushes.Transparent;
            container.Children.Add(row);
            if (_openFieldPopovers.Contains(field)) container.Children.Add(BuildFieldPopover(field));
            return container;
        }

        private FontAwesome.Sharp.IconChar FieldIcon(string field)
        {
            // ES-style type icon (keyword/text/number/ip/date/boolean/geo) inferred from name + samples
            var t = SiemFieldTypes.Infer(field, _store.TopValues(field, _query, _window, 8).top.Select(v => v.value));
            return Enum.TryParse<FontAwesome.Sharp.IconChar>(SiemFieldTypes.IconName(t), out var ic) ? ic : FontAwesome.Sharp.IconChar.Font;
        }

        private UIElement BuildFieldPopover(string field)
        {
            var (total, top) = _store.TopValues(field, _query, _window, 5);
            var ftype = SiemFieldTypes.Infer(field, top.Select(v => v.value));
            var b = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(9, 7, 9, 8), Margin = new Thickness(4, 1, 4, 6) };
            var sp = new StackPanel();
            // header: type label (left) + Visualize shortcut (right)
            var hdr = new DockPanel { Margin = new Thickness(0, 0, 0, 5) };
            var vizBtn = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Foreground = Br("AccentBrush"), ToolTip = "Visualize this field on the Overview dashboard", Padding = new Thickness(0) };
            var vizSp = new StackPanel { Orientation = Orientation.Horizontal };
            vizSp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.ChartColumn, FontSize = 10, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) });
            vizSp.Children.Add(new TextBlock { Text = "Visualize", FontSize = 10, VerticalAlignment = VerticalAlignment.Center });
            vizBtn.Content = vizSp;
            vizBtn.Click += (_, _) => VisualizeField(field, ftype);
            DockPanel.SetDock(vizBtn, Dock.Right); hdr.Children.Add(vizBtn);
            hdr.Children.Add(new TextBlock { Text = $"{SiemFieldTypes.Label(ftype)}  ·  top {top.Count} value(s)", FontSize = 10, Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Center });
            sp.Children.Add(hdr);
            if (top.Count == 0) sp.Children.Add(new TextBlock { Text = "No values in range", FontSize = 11, Foreground = Br("SubtleTextBrush") });
            foreach (var (val, count) in top)
            {
                double pct = total > 0 ? count * 100.0 / total : 0;
                var line = new Grid { Margin = new Thickness(0, 2, 0, 3) };
                line.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                line.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                var top1 = new DockPanel();
                var actions = new StackPanel { Orientation = Orientation.Horizontal };
                actions.Children.Add(MiniBtn(FontAwesome.Sharp.IconChar.MagnifyingGlassPlus, "Filter for", () => { AddFilter(field, val); }));
                actions.Children.Add(MiniBtn(FontAwesome.Sharp.IconChar.MagnifyingGlassMinus, "Filter out", () => { AddFilter(field, "-" + val); }));
                DockPanel.SetDock(actions, Dock.Right); top1.Children.Add(actions);
                top1.Children.Add(new TextBlock { Text = string.IsNullOrEmpty(val) ? "(empty)" : val, Foreground = Br("TextBrush"), FontSize = 11.5, FontFamily = new FontFamily("Consolas"), TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, ToolTip = val });
                Grid.SetColumnSpan(top1, 2); line.Children.Add(top1);
                sp.Children.Add(line);
                var track = new Border { Height = 4, Background = Br("SecondaryBackgroundBrush"), CornerRadius = new CornerRadius(2), Margin = new Thickness(0, 0, 0, 1) };
                var fill = new Border { Height = 4, Width = Math.Max(2, pct / 100.0 * 196), HorizontalAlignment = HorizontalAlignment.Left, Background = Br("AccentBrush"), CornerRadius = new CornerRadius(2) };
                track.Child = fill;
                var pctRow = new DockPanel();
                var pctTxt = new TextBlock { Text = $"{pct:0.0}%", FontSize = 9.5, Foreground = Br("SubtleTextBrush") };
                DockPanel.SetDock(pctTxt, Dock.Right); pctRow.Children.Add(pctTxt);
                pctRow.Children.Add(track);
                sp.Children.Add(pctRow);
            }
            b.Child = sp;
            return b;
        }

        private Button MiniBtn(FontAwesome.Sharp.IconChar icon, string tip, Action act)
        {
            var b = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Width = 22, Height = 18, Foreground = Br("SubtleTextBrush"), ToolTip = tip, Margin = new Thickness(1, 0, 0, 0) };
            b.Content = new FontAwesome.Sharp.IconBlock { Icon = icon, FontSize = 10 };
            b.Click += (_, _) => act();
            return b;
        }

        private void ToggleColumn(string field)
        {
            if (_columns.Contains(field)) _columns.Remove(field); else _columns.Add(field);
            RebuildColumns(); RefreshFields();
        }

        // ── the documents grid ──
        private DataGrid BuildDiscoverGrid()
        {
            var grid = ThemedGrid(32);
            grid.RowDetailsVisibilityMode = DataGridRowDetailsVisibilityMode.VisibleWhenSelected;   // click a row to expand its document
            grid.HeadersVisibility = DataGridHeadersVisibility.Column;
            grid.Columns.Add(ExpanderColumn());
            grid.Columns.Add(DotColumn("SeverityColor"));
            grid.Columns.Add(MakeTextColumn("Time", "TimeText", new DataGridLength(165), mono: true));
            grid.RowDetailsTemplate = DocDetailTemplate();
            grid.LoadingRowDetails += (_, e) =>
            {
                if (e.DetailsElement is ContentControl cc && e.Row.Item is SiemEvent ev) cc.Content = BuildDocDetail(ev);
            };
            return grid;
        }

        private void RebuildColumns()
        {
            if (_searchGrid == null) return;
            while (_searchGrid.Columns.Count > 3) _searchGrid.Columns.RemoveAt(3);   // keep expander, dot, time
            if (_columns.Count == 0)
                _searchGrid.Columns.Add(FieldColumn("__doc", "Document"));
            else
                foreach (var f in _columns) _searchGrid.Columns.Add(FieldColumn(f, f));
        }

        private DataGridTemplateColumn FieldColumn(string field, string header)
        {
            var col = new DataGridTemplateColumn { Header = header, Width = new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 90 };
            var tmpl = new DataTemplate();
            var tb = new FrameworkElementFactory(typeof(TextBlock));
            tb.SetBinding(TextBlock.TextProperty, new Binding(".") { Converter = _fieldConv, ConverterParameter = field });
            tb.SetValue(TextBlock.FontFamilyProperty, new FontFamily("Consolas"));
            tb.SetValue(TextBlock.FontSizeProperty, 11.5);
            tb.SetValue(TextBlock.ForegroundProperty, field == "__doc" ? Br("SubtleTextBrush") : Br("TextBrush"));
            tb.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
            tb.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            tmpl.VisualTree = tb; col.CellTemplate = tmpl;
            return col;
        }

        private DataGridTemplateColumn ExpanderColumn()
        {
            var col = new DataGridTemplateColumn { Header = "", Width = new DataGridLength(30), CanUserResize = false };
            var tmpl = new DataTemplate();
            var btn = new FrameworkElementFactory(typeof(Button));
            btn.SetValue(BackgroundProperty, Brushes.Transparent);
            btn.SetValue(Control.BorderThicknessProperty, new Thickness(0));
            btn.SetValue(CursorProperty, Cursors.Hand);
            btn.SetValue(Control.ForegroundProperty, Br("SubtleTextBrush"));
            btn.SetValue(Control.PaddingProperty, new Thickness(0));
            var ico = new FrameworkElementFactory(typeof(FontAwesome.Sharp.IconBlock));
            ico.SetValue(FontAwesome.Sharp.IconBlock.IconProperty, FontAwesome.Sharp.IconChar.AngleRight);
            ico.SetValue(TextBlock.FontSizeProperty, 12.0);
            btn.AppendChild(ico);
            btn.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler(Expander_Click));
            tmpl.VisualTree = btn; col.CellTemplate = tmpl;
            return col;
        }

        private void Expander_Click(object sender, RoutedEventArgs e)
        {
            // With VisibleWhenSelected, selecting the row expands its document; clicking the
            // chevron of the already-selected row collapses it again.
            if (sender is FrameworkElement fe && fe.DataContext is SiemEvent ev && _searchGrid != null)
            {
                if (_searchGrid.SelectedItem == ev) _searchGrid.SelectedItem = null;
                else _searchGrid.SelectedItem = ev;
            }
        }

        private DataTemplate DocDetailTemplate()
        {
            var dt = new DataTemplate();
            var f = new FrameworkElementFactory(typeof(ContentControl));
            dt.VisualTree = f;
            return dt;
        }

        // ── expanded document (Table | JSON) ──
        private UIElement BuildDocDetail(SiemEvent ev)
        {
            var card = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("AccentBrush"), BorderThickness = new Thickness(0, 0, 0, 0), Padding = new Thickness(18, 12, 18, 14) };
            var root = new StackPanel();

            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            var badge = new Border { Background = Hex(ev.SeverityColor), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 2, 8, 2), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
            badge.Child = new TextBlock { Text = ev.SeverityText.ToUpperInvariant(), Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 10 };
            head.Children.Add(badge);
            head.Children.Add(new TextBlock { Text = $"{ev.EventType}", Foreground = Br("TextBrush"), FontWeight = FontWeights.SemiBold, FontSize = 13, VerticalAlignment = VerticalAlignment.Center });

            var toggleTable = new ToggleButton { Content = "Table", IsChecked = true };
            var toggleJson = new ToggleButton { Content = "JSON" };
            var toggleCtx = new ToggleButton { Content = "Context" };
            StyleSegToggle(toggleTable); StyleSegToggle(toggleJson); StyleSegToggle(toggleCtx);
            toggleCtx.ToolTip = "Surrounding events from the same host in time";
            var seg = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var pin = ToolbarButton("Thumbtack", "Pin", "Pin this event to the investigation timeline");
            pin.Margin = new Thickness(0, 0, 8, 0);
            pin.Click += (_, _) => PinToTimeline(ev);
            seg.Children.Add(pin);
            seg.Children.Add(toggleTable); seg.Children.Add(toggleJson); seg.Children.Add(toggleCtx);
            DockPanel.SetDock(seg, Dock.Right); head.Children.Add(seg);
            root.Children.Add(head);

            var contentHost = new Border();
            var tableView = BuildFieldTable(ev);
            var jsonView = new TextBox
            {
                Text = ev.ToJson(), IsReadOnly = true, FontFamily = new FontFamily("Consolas"), FontSize = 12,
                Background = Br("SecondaryBackgroundBrush"), Foreground = Br("TextBrush"), BorderThickness = new Thickness(1), BorderBrush = Br("BorderBrush"),
                Padding = new Thickness(12), MaxHeight = 360, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, TextWrapping = TextWrapping.NoWrap,
            };
            UIElement? ctxView = null;
            contentHost.Child = tableView;
            toggleTable.Checked += (_, _) => { toggleJson.IsChecked = false; toggleCtx.IsChecked = false; contentHost.Child = tableView; };
            toggleJson.Checked += (_, _) => { toggleTable.IsChecked = false; toggleCtx.IsChecked = false; contentHost.Child = jsonView; };
            toggleCtx.Checked += (_, _) => { toggleTable.IsChecked = false; toggleJson.IsChecked = false; contentHost.Child = ctxView ??= BuildSurrounding(ev); };
            toggleTable.Unchecked += (_, _) => { if (toggleJson.IsChecked != true && toggleCtx.IsChecked != true) toggleTable.IsChecked = true; };
            toggleJson.Unchecked += (_, _) => { if (toggleTable.IsChecked != true && toggleCtx.IsChecked != true) toggleJson.IsChecked = true; };
            toggleCtx.Unchecked += (_, _) => { if (toggleTable.IsChecked != true && toggleJson.IsChecked != true) toggleTable.IsChecked = true; };
            root.Children.Add(contentHost);

            card.Child = root;
            return card;
        }

        private void StyleSegToggle(ToggleButton t)
        {
            t.Height = 26; t.MinWidth = 56; t.Cursor = Cursors.Hand; t.FontSize = 11; t.Foreground = Br("SubtleTextBrush");
            var tmpl = new ControlTemplate(typeof(ToggleButton));
            var b = new FrameworkElementFactory(typeof(Border));
            b.Name = "b";
            b.SetValue(Border.BackgroundProperty, Br("SecondaryBackgroundBrush"));
            b.SetValue(Border.BorderBrushProperty, Br("BorderBrush"));
            b.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            b.SetValue(Border.PaddingProperty, new Thickness(12, 0, 12, 0));
            var cp = new FrameworkElementFactory(typeof(ContentPresenter));
            cp.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(VerticalAlignmentProperty, VerticalAlignment.Center);
            b.AppendChild(cp);
            tmpl.VisualTree = b;
            var trig = new Trigger { Property = ToggleButton.IsCheckedProperty, Value = true };
            trig.Setters.Add(new Setter(Border.BackgroundProperty, Br("AccentBrush"), "b"));
            trig.Setters.Add(new Setter(Control.ForegroundProperty, Br("OnAccentBrush")));
            tmpl.Triggers.Add(trig);
            t.Template = tmpl;
        }

        /// <summary>D20: "view in context" — the events just before/after this one on the same host, in time order.</summary>
        private UIElement BuildSurrounding(SiemEvent ev)
        {
            var host = string.IsNullOrEmpty(ev.Host) ? null : ev.Host;
            var rows = _store.Surrounding(ev, 6, 6, host);
            var sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = host == null ? "Surrounding events (all hosts)" : $"Surrounding events on {host}",
                Foreground = Br("SubtleTextBrush"), FontSize = 11, Margin = new Thickness(0, 0, 0, 8),
            });
            if (rows.Count <= 1)
                sp.Children.Add(new TextBlock { Text = "No nearby events in the index.", Foreground = Br("SubtleTextBrush"), FontSize = 12 });
            foreach (var e in rows)
            {
                bool anchor = e.Id == ev.Id;
                var row = new Border
                {
                    Background = anchor ? Br("SecondaryBackgroundBrush") : Brushes.Transparent,
                    BorderBrush = anchor ? Br("AccentBrush") : Br("BorderBrush"),
                    BorderThickness = anchor ? new Thickness(1) : new Thickness(0, 0, 0, 1),
                    CornerRadius = anchor ? new CornerRadius(5) : new CornerRadius(0),
                    Padding = new Thickness(8, 5, 8, 5), Margin = new Thickness(0, 0, 0, anchor ? 2 : 0), Cursor = Cursors.Hand,
                };
                var dp = new DockPanel();
                var dot = new Border { Width = 6, Height = 6, CornerRadius = new CornerRadius(3), Background = Hex(e.SeverityColor), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 9, 0) };
                DockPanel.SetDock(dot, Dock.Left); dp.Children.Add(dot);
                var ts = new TextBlock { Text = e.Timestamp.ToString("HH:mm:ss.fff"), Foreground = Br("SubtleTextBrush"), FontFamily = new FontFamily("Consolas"), FontSize = 11, Width = 96, VerticalAlignment = VerticalAlignment.Center };
                DockPanel.SetDock(ts, Dock.Left); dp.Children.Add(ts);
                if (anchor)
                {
                    var here = new Border { Background = Br("AccentBrush"), CornerRadius = new CornerRadius(3), Padding = new Thickness(5, 0, 5, 0), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
                    here.Child = new TextBlock { Text = "THIS", Foreground = Br("OnAccentBrush"), FontSize = 8.5, FontWeight = FontWeights.Bold };
                    DockPanel.SetDock(here, Dock.Left); dp.Children.Add(here);
                }
                dp.Children.Add(new TextBlock { Text = $"{e.EventType}  ·  {e.Summary()}", Foreground = anchor ? Br("TextBrush") : Br("SubtleTextBrush"), FontSize = 11.5, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center });
                row.Child = dp;
                if (!anchor) row.MouseLeftButtonUp += (_, _) => { if (_searchGrid != null) { _searchGrid.SelectedItem = e; _searchGrid.ScrollIntoView(e); } };
                sp.Children.Add(row);
            }
            return new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = 360, Content = sp };
        }

        private UIElement BuildFieldTable(SiemEvent ev)
        {
            var sp = new StackPanel();
            foreach (var kv in ev.AllFields())
                sp.Children.Add(FieldDetailRow(kv.Key, kv.Value));
            return new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = 360, Content = sp };
        }

        private UIElement FieldDetailRow(string field, string value)
        {
            var g = new Grid { Margin = new Thickness(0, 0, 0, 0), MinHeight = 26 };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });   // actions
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(230) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            actions.Children.Add(MiniBtn(FontAwesome.Sharp.IconChar.MagnifyingGlassPlus, "Filter for value", () => AddFilter(field, value)));
            actions.Children.Add(MiniBtn(FontAwesome.Sharp.IconChar.MagnifyingGlassMinus, "Filter out value", () => AddFilter(field, "-" + value)));
            actions.Children.Add(MiniBtn(FontAwesome.Sharp.IconChar.TableColumns, "Toggle column", () => ToggleColumn(field)));
            Grid.SetColumn(actions, 0); g.Children.Add(actions);
            var name = new TextBlock { Text = field, Foreground = Br("AccentBrush"), FontFamily = new FontFamily("Consolas"), FontSize = 12, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = field };
            Grid.SetColumn(name, 1); g.Children.Add(name);
            var val = new TextBox { Text = value, IsReadOnly = true, Background = Brushes.Transparent, BorderThickness = new Thickness(0), Foreground = Br("TextBrush"), FontFamily = new FontFamily("Consolas"), FontSize = 12, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 0, 0) };
            Grid.SetColumn(val, 2); g.Children.Add(val);
            var wrap = new Border { Padding = new Thickness(0, 3, 0, 3), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(0, 0, 0, 1) };
            wrap.Child = g;
            return wrap;
        }

        private void RebuildSearch()
        {
            if (_searchRows == null) return;
            _searchRows.Clear();
            foreach (var e in _store.Query(_query, _window, (int)FeedCap)) _searchRows.Add(e);
            UpdateSearchCount();
        }

        private void UpdateSearchCount()
        {
            if (_searchCount == null) return;
            int total = _store.CountMatching(_query, _window);
            _searchCount.Text = _query.IsEmpty && _window == null
                ? $"{total:N0} events"
                : $"{total:N0} matching events  ·  showing newest {Math.Min(total, (int)FeedCap):N0}";
        }

        // ════════════════════════════════════════════════════════════════════
        //  Sources & Agents tab
        // ════════════════════════════════════════════════════════════════════
        private void BuildSourcesTab()
        {
            SourcesHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            SourcesHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            SourcesHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Local collection card
            _localSourcesCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 16) };
            var lsp = new StackPanel();
            lsp.Children.Add(new TextBlock { Text = "Local collection", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 4) });
            lsp.Children.Add(new TextBlock { Text = "Sources collected on this machine. Remote machines ship logs via the PrivaCore agent — see the table below.", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 12), TextWrapping = TextWrapping.Wrap });
            var chips = new WrapPanel { Orientation = Orientation.Horizontal };
            _winChip = new ToggleButton { Style = (Style)FindResource("Chip"), Content = "Win Event Log", IsChecked = _ing.WinEventLogOn };
            _sysChip = new ToggleButton { Style = (Style)FindResource("Chip"), Content = $"Syslog UDP :{_ing.SyslogPort}", IsChecked = _ing.SyslogOn };
            _genChip = new ToggleButton { Style = (Style)FindResource("Chip"), Content = "Demo Generator", IsChecked = _ing.GeneratorOn };
            _sysTcpChip = new ToggleButton { Style = (Style)FindResource("Chip"), Content = $"Syslog TCP :{_ing.SyslogTcpPort}", IsChecked = _ing.SyslogTcpOn };
            _httpChip = new ToggleButton { Style = (Style)FindResource("Chip"), Content = $"HTTP ingest :{_ing.HttpPort}", IsChecked = _ing.HttpOn, ToolTip = $"POST JSON events to http://<this-host>:{_ing.HttpPort}/ to ingest · GET /api/search?q=… to query (same token)" };
            _winChip.Click += LocalSource_Click; _sysChip.Click += LocalSource_Click; _sysTcpChip.Click += LocalSource_Click; _genChip.Click += LocalSource_Click; _httpChip.Click += LocalSource_Click;
            chips.Children.Add(_winChip); chips.Children.Add(_sysChip); chips.Children.Add(_sysTcpChip); chips.Children.Add(_httpChip); chips.Children.Add(_genChip);
            lsp.Children.Add(chips);

            // HTTP ingest auth token (opt-in shared secret — blank = unauthenticated, trusted-network)
            var tokRow = new DockPanel { Margin = new Thickness(0, 12, 0, 0) };
            tokRow.Children.Add(new TextBlock { Text = "HTTP ingest token", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0), Width = 120 });
            var tokApply = new Button { Content = "Apply", Style = (Style)FindResource("GhostButtonStyle"), Height = 30, Padding = new Thickness(12, 0, 12, 0), Margin = new Thickness(8, 0, 0, 0) };
            DockPanel.SetDock(tokApply, Dock.Right); tokRow.Children.Add(tokApply);
            var tokBox = new TextBox { Style = (Style)FindResource("InputBoxStyle"), Text = _indexSettings.HttpIngestToken, VerticalAlignment = VerticalAlignment.Center };
            tokApply.Click += (_, _) =>
            {
                _indexSettings.HttpIngestToken = tokBox.Text.Trim();
                _indexSettings.Save();
                _ing.HttpToken = _indexSettings.HttpIngestToken;
                SiemAudit.Instance.Log("Config", "Set HTTP ingest token", string.IsNullOrEmpty(_ing.HttpToken) ? "cleared (unauthenticated)" : "enabled");
                ShowToastText("HTTP ingest", string.IsNullOrEmpty(_ing.HttpToken) ? "Token cleared — endpoint is unauthenticated (trusted-network only)." : "Token set — POSTs must send X-Ingest-Token.");
            };
            tokRow.Children.Add(tokBox);
            lsp.Children.Add(tokRow);
            lsp.Children.Add(new TextBlock { Text = "Blank = unauthenticated (trusted-network only). Set a secret and senders must include  X-Ingest-Token: <secret>  (or  Authorization: Bearer <secret>).", FontSize = 10, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) });
            lsp.Children.Add(new TextBlock { Text = $"Query API:  GET http://<this-host>:{_ing.HttpPort}/api/search?q=<KQL>&size=<n>&minutes=<m>  → JSON hits (ECS _source). Honours the same token.", FontSize = 10, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) });

            // collector-side file tailing (Filebeat-style)
            var tailHead = new DockPanel { Margin = new Thickness(0, 16, 0, 0) };
            tailHead.Children.Add(new TextBlock { Text = "Tail local log files", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Center });
            var addTail = new Button { Content = "＋ Tail file…", Style = (Style)FindResource("GhostButtonStyle"), Height = 28, Padding = new Thickness(12, 0, 12, 0) };
            DockPanel.SetDock(addTail, Dock.Right);
            addTail.Click += (_, _) =>
            {
                var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose a log file to tail", Filter = "Log files (*.log;*.txt)|*.log;*.txt|All files (*.*)|*.*" };
                if (dlg.ShowDialog() == true) { _ing.AddTailedFile(dlg.FileName); SiemAudit.Instance.Log("Config", "Tail file", dlg.FileName); RefreshTailedFiles(); }
            };
            tailHead.Children.Add(addTail);
            lsp.Children.Add(tailHead);
            _tailHost = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            lsp.Children.Add(_tailHost);
            lsp.Children.Add(new TextBlock { Text = "New lines appended to these files are ingested as events (source = file:<name>). Click a file to stop tailing.", FontSize = 10, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) });
            RefreshTailedFiles();

            // email alert notifications (SMTP) — pairs with a rule's "Email to"
            var em = SiemEmailSettings.Load();
            lsp.Children.Add(new TextBlock { Text = "Email alerts (SMTP)", FontSize = 12.5, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 18, 0, 4) });
            lsp.Children.Add(new TextBlock { Text = "Configure an SMTP server, then set “Email to” on a detection rule to receive its alerts by email.", FontSize = 10, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });
            TextBox EmTb(string val) { var b = new TextBox { Style = (Style)FindResource("InputBoxStyle"), Text = val, VerticalAlignment = VerticalAlignment.Center }; b.SetValue(System.Windows.Controls.Primitives.TextBoxBase.AcceptsReturnProperty, false); return b; }
            FrameworkElement EmRow(string label, FrameworkElement ctrl)
            {
                var dp = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
                var l = new TextBlock { Text = label, Width = 130, FontSize = 11, Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Center };
                DockPanel.SetDock(l, Dock.Left); dp.Children.Add(l); dp.Children.Add(ctrl); return dp;
            }
            var emHost = EmTb(em.Host); var emPort = EmTb(em.Port.ToString()); var emFrom = EmTb(em.From); var emUser = EmTb(em.Username);
            var emPass = new PasswordBox { Style = (Style)FindResource("PasswordBoxStyle"), Password = em.Password, VerticalAlignment = VerticalAlignment.Center };
            var emSsl = new ToggleButton { Style = (Style)FindResource("ToggleSwitchStyle"), IsChecked = em.UseSsl, HorizontalAlignment = HorizontalAlignment.Left };
            var emEnabled = new ToggleButton { Style = (Style)FindResource("ToggleSwitchStyle"), IsChecked = em.Enabled, HorizontalAlignment = HorizontalAlignment.Left };
            lsp.Children.Add(EmRow("SMTP host", emHost));
            lsp.Children.Add(EmRow("Port", emPort));
            lsp.Children.Add(EmRow("From address", emFrom));
            lsp.Children.Add(EmRow("Username", emUser));
            lsp.Children.Add(EmRow("Password", emPass));
            lsp.Children.Add(EmRow("Use SSL/TLS", emSsl));
            lsp.Children.Add(EmRow("Enabled", emEnabled));
            var emApply = new Button { Content = "Save SMTP settings", Style = (Style)FindResource("AccentButtonStyle"), Height = 30, Padding = new Thickness(14, 0, 14, 0), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 0) };
            emApply.Click += (_, _) =>
            {
                em.Host = emHost.Text.Trim(); em.Port = int.TryParse(emPort.Text.Trim(), out var pp) ? pp : 587; em.From = emFrom.Text.Trim();
                em.Username = emUser.Text.Trim(); em.Password = emPass.Password; em.UseSsl = emSsl.IsChecked == true; em.Enabled = emEnabled.IsChecked == true;
                em.Save();
                SiemAudit.Instance.Log("Config", "Set SMTP settings", em.Enabled ? $"enabled host={em.Host}:{em.Port}" : "disabled");
                ShowToastText("Email alerts", em.IsConfigured ? "SMTP saved — set “Email to” on a rule to receive alerts." : "Saved (disabled or incomplete).");
            };
            lsp.Children.Add(emApply);

            _localSourcesCard.Child = lsp;
            Grid.SetRow(_localSourcesCard, 0); SourcesHost.Children.Add(_localSourcesCard);

            // Reporting machines card
            var machCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 16) };
            var mgrid = new Grid();
            mgrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mgrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            head.Children.Add(new TextBlock { Text = "Reporting machines & agents", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), VerticalAlignment = VerticalAlignment.Center });
            _droppedLabel = new TextBlock { Foreground = Br("SubtleTextBrush"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Right };
            DockPanel.SetDock(_droppedLabel, Dock.Right); head.Children.Add(_droppedLabel);
            Grid.SetRow(head, 0); mgrid.Children.Add(head);

            _machineRows = new ObservableCollection<SiemSourceStat>();
            _machineGrid = ThemedGrid(40);
            _machineGrid.MaxHeight = 520;
            _machineGrid.Columns.Add(DotColumn("LiveColor", 9));
            _machineGrid.Columns.Add(MakeTextColumn("Machine / Host", "Host", new DataGridLength(1.4, DataGridLengthUnitType.Star), bold: true));
            _machineGrid.Columns.Add(MakeTextColumn("Status", "StatusText", new DataGridLength(72)));
            _machineGrid.Columns.Add(MakeTextColumn("Last source", "Source", new DataGridLength(1.2, DataGridLengthUnitType.Star), mono: true));
            _machineGrid.Columns.Add(MakeTextColumn("Events", "EventsText", new DataGridLength(84)));
            var highCol = MakeTextColumn("High", "HighText", new DataGridLength(72));
            ColorCol(highCol, "#FF7B72"); _machineGrid.Columns.Add(highCol);
            var critCol = MakeTextColumn("Critical", "CriticalText", new DataGridLength(84));
            ColorCol(critCol, "#F85149"); _machineGrid.Columns.Add(critCol);
            _machineGrid.Columns.Add(MakeTextColumn("Last seen", "LastSeenText", new DataGridLength(120), subtle: true));
            _machineGrid.ItemsSource = _machineRows;
            _machineGrid.MouseDoubleClick += (_, _) => { if (_machineGrid!.SelectedItem is SiemSourceStat st) { AddFilter("host", st.Host); Tabs.SelectedItem = _searchTab; } };
            var machWrap = new Border
            {
                CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), MinHeight = 150,
                Child = WrapWithEmptyState(_machineGrid, _machineRows, "Server", "No machines reporting yet", "Deploy the PrivaCore agent on a machine and point it at this collector — it will appear here within seconds."),
            };
            Grid.SetRow(machWrap, 1); mgrid.Children.Add(machWrap);
            machCard.Child = mgrid;
            Grid.SetRow(machCard, 1); SourcesHost.Children.Add(machCard);

            // ── Managed agents (Fleet) ──
            var fleetCard = new Border { Style = (Style)FindResource("CardStyle") };
            var fg = new Grid();
            fg.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            fg.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            var fhead = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
            var ftitle = new StackPanel();
            ftitle.Children.Add(new TextBlock { Text = "Managed agents (Fleet)", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            ftitle.Children.Add(new TextBlock { Text = "Enrolled agents check in here. Select one and push a policy to reconfigure it live.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap });
            fhead.Children.Add(ftitle);
            var pushBtn = ToolbarButton("PaperPlane", "Push policy", "Push a configuration to the selected agent");
            pushBtn.VerticalAlignment = VerticalAlignment.Top;
            pushBtn.Click += (_, _) => PushSelectedAgentPolicy();
            DockPanel.SetDock(pushBtn, Dock.Right); fhead.Children.Add(pushBtn);
            Grid.SetRow(fhead, 0); fg.Children.Add(fhead);

            _agentRows = new ObservableCollection<AgentInfo>();
            _agentGrid = ThemedGrid(38);
            _agentGrid.MaxHeight = 420;
            _agentGrid.Columns.Add(DotColumn("StatusColor", 9));
            _agentGrid.Columns.Add(MakeTextColumn("Agent", "Name", new DataGridLength(1.1, DataGridLengthUnitType.Star), bold: true));
            _agentGrid.Columns.Add(MakeTextColumn("Status", "StatusText", new DataGridLength(80)));
            _agentGrid.Columns.Add(MakeTextColumn("OS", "OsShort", new DataGridLength(1.4, DataGridLengthUnitType.Star), subtle: true));
            _agentGrid.Columns.Add(MakeTextColumn("Version", "Version", new DataGridLength(80), mono: true));
            _agentGrid.Columns.Add(MakeTextColumn("Events", "EventsText", new DataGridLength(90)));
            _agentGrid.Columns.Add(MakeTextColumn("Last check-in", "LastSeenText", new DataGridLength(120), subtle: true));
            _agentGrid.ItemsSource = _agentRows;
            _agentGrid.MouseDoubleClick += (_, _) => PushSelectedAgentPolicy();
            var fwrap = new Border
            {
                CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), MinHeight = 120,
                Child = WrapWithEmptyState(_agentGrid, _agentRows, "Robot", "No agents enrolled", "Run the PrivaCore agent against this collector — it enrolls automatically and appears here."),
            };
            Grid.SetRow(fwrap, 1); fg.Children.Add(fwrap);
            fleetCard.Child = fg;
            Grid.SetRow(fleetCard, 2); SourcesHost.Children.Add(fleetCard);

            RefreshAgents();
        }

        private void RefreshAgents()
        {
            if (_agentRows == null) return;
            var sel = _agentGrid?.SelectedItem as AgentInfo;
            var agents = SiemAgentRegistry.Instance.All();
            _agentRows.Clear();
            foreach (var a in agents) _agentRows.Add(a);
            if (sel != null && _agentGrid != null) _agentGrid.SelectedItem = _agentRows.FirstOrDefault(a => a.ConnId == sel.ConnId);
        }

        private void PushSelectedAgentPolicy()
        {
            if (_agentGrid?.SelectedItem is not AgentInfo agent) { ShowToastText("Select an agent", "Pick an agent in the Fleet table first."); return; }
            var policy = SiemAgentPolicyDialog.Edit(Window.GetWindow(this), agent.Name, agent.Policy);
            if (policy == null) return;
            bool ok = SiemAgentRegistry.Instance.PushPolicy(agent, policy);
            ShowToastText(ok ? "Policy pushed" : "Agent offline",
                ok ? $"New policy sent to “{agent.Name}”." : $"“{agent.Name}” is offline — policy saved, will apply when it reconnects.");
            RefreshAgents();
        }

        private void RefreshMachines()
        {
            if (_machineRows == null) return;
            var stats = _store.SourceStats(_window);
            _machineRows.Clear();
            foreach (var s in stats) _machineRows.Add(s);
            if (_droppedLabel != null)
                _droppedLabel.Text = $"{stats.Count} machine(s)  ·  {_store.TotalDropped:N0} dropped by pipeline";
        }

        private void LocalSource_Click(object sender, RoutedEventArgs e)
        {
            if (sender == _winChip) { if (_winChip!.IsChecked == true) _ing.StartWinEventLog(); else _ing.StopWinEventLog(); _winChip.IsChecked = _ing.WinEventLogOn; }
            else if (sender == _sysChip) { if (_sysChip!.IsChecked == true) _ing.StartSyslog(_ing.SyslogPort); else _ing.StopSyslog(); _sysChip.IsChecked = _ing.SyslogOn; }
            else if (sender == _genChip) { if (_genChip!.IsChecked == true) _ing.StartGenerator(); else _ing.StopGenerator(); _genChip.IsChecked = _ing.GeneratorOn; }
            else if (sender == _sysTcpChip) { if (_sysTcpChip!.IsChecked == true) _ing.StartSyslogTcp(_ing.SyslogTcpPort); else _ing.StopSyslogTcp(); _sysTcpChip.IsChecked = _ing.SyslogTcpOn; }
            else if (sender == _httpChip) { if (_httpChip!.IsChecked == true) _ing.StartHttp(_ing.HttpPort); else _ing.StopHttp(); _httpChip.IsChecked = _ing.HttpOn; }
        }

        private void RefreshTailedFiles()
        {
            if (_tailHost == null) return;
            _tailHost.Children.Clear();
            var files = _ing.TailedFiles();
            foreach (var path in files)
            {
                var p = path;
                var chip = new Button
                {
                    Style = (Style)FindResource("GhostButtonStyle"), Height = 26, Margin = new Thickness(0, 0, 6, 6),
                    Padding = new Thickness(10, 0, 10, 0), Content = "📄 " + System.IO.Path.GetFileName(p) + "  ✕",
                    ToolTip = p + "   (click to stop tailing)",
                };
                chip.Click += (_, _) => { _ing.RemoveTailedFile(p); SiemAudit.Instance.Log("Config", "Stop tailing file", p); RefreshTailedFiles(); };
                _tailHost.Children.Add(chip);
            }
            if (files.Count == 0)
                _tailHost.Children.Add(new TextBlock { Text = "No files tailed.", FontSize = 11, Foreground = Br("SubtleTextBrush") });
        }

        // ════════════════════════════════════════════════════════════════════
        //  Pipeline tab — composable processing stages
        // ════════════════════════════════════════════════════════════════════
        private void BuildPipelineTab()
        {
            PipelineHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            PipelineHost.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 14) };
            var titleSp = new StackPanel();
            titleSp.Children.Add(new TextBlock { Text = "Processing pipeline", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            titleSp.Children.Add(new TextBlock { Text = "Sources flow into the store through these stages (top → bottom). Drop noise, re-tag, or override severity — Logstash-style.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, MaxWidth = 640, HorizontalAlignment = HorizontalAlignment.Left });
            head.Children.Add(titleSp);
            var headBtns = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top };
            DockPanel.SetDock(headBtns, Dock.Right);
            // named-pipeline selector (C11) + new/delete
            _pipelineSelector = new ComboBox { Style = (Style)FindResource("ComboBoxStyle"), Width = 150, Height = 32, Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center, ToolTip = "Which pipeline to edit. 'main' runs on ingestion; others are reached via a Route-to stage." };
            _pipelineSelector.SelectionChanged += (_, _) =>
            {
                if (_pipelineSelector.SelectedItem is string name && _pipelineSet.ByName(name) is { } pl && !ReferenceEquals(pl, _pipeline))
                { _pipeline = pl; RenderPipeline(); }
            };
            var newPlBtn = new Button { Content = "＋ Pipeline", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(10, 0, 10, 0), ToolTip = "Create a new named pipeline" };
            newPlBtn.Click += (_, _) => NewPipeline();
            var delPlBtn = new Button { Content = "Delete", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(10, 0, 10, 0), ToolTip = "Delete the selected pipeline (not 'main')" };
            delPlBtn.Click += (_, _) => DeletePipeline();
            var testBtn = new Button { Content = "Test pipeline", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(12, 0, 12, 0), ToolTip = "Run the newest event through the pipeline (dry-run)" };
            testBtn.Click += (_, _) => RunPipelineTest();
            var intBtn = new Button { Content = "＋ Add integration", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(12, 0, 12, 0), ToolTip = "Add prebuilt parser stages for a known log source" };
            intBtn.Click += AddIntegration_Click;
            var addBtn = new Button { Content = "＋ Add stage", Style = (Style)FindResource("AccentButtonStyle"), Height = 32 };
            addBtn.Click += AddStage_Click;
            headBtns.Children.Add(_pipelineSelector); headBtns.Children.Add(newPlBtn); headBtns.Children.Add(delPlBtn); headBtns.Children.Add(testBtn); headBtns.Children.Add(intBtn); headBtns.Children.Add(addBtn);
            RebuildPipelineSelector();
            head.Children.Add(headBtns);
            Grid.SetRow(head, 0); PipelineHost.Children.Add(head);

            var body = new Grid();
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(240) });

            _pipelineList = new ItemsControl();
            var sv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 16, 0), Content = _pipelineList };
            Grid.SetColumn(sv, 0); body.Children.Add(sv);

            // flow diagram side panel
            var flowCard = new Border { Style = (Style)FindResource("CardStyle"), VerticalAlignment = VerticalAlignment.Top };
            var flow = new StackPanel();
            flow.Children.Add(new TextBlock { Text = "DATA FLOW", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 10) });
            void FlowNode(string icon, string label, string sub)
            {
                var b = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 9, 12, 9), Margin = new Thickness(0, 0, 0, 4) };
                var dp = new DockPanel();
                dp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 15, Foreground = Br("AccentBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) });
                var t = new StackPanel();
                t.Children.Add(new TextBlock { Text = label, Foreground = Br("TextBrush"), FontSize = 13, FontWeight = FontWeights.SemiBold });
                t.Children.Add(new TextBlock { Text = sub, Foreground = Br("SubtleTextBrush"), FontSize = 10 });
                dp.Children.Add(t); b.Child = dp; flow.Children.Add(b);
            }
            void Arrow() => flow.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.ArrowDown, FontSize = 12, Foreground = Br("SubtleTextBrush"), HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 1, 0, 1) });
            FlowNode("Server", "Sources", "agents · syslog · OS logs"); Arrow();
            FlowNode("Filter", "Pipeline", "drop · enrich · re-tag"); Arrow();
            FlowNode("Database", "Store & Index", "search · dashboards");
            _pipelineSummary = new TextBlock { Foreground = Br("SubtleTextBrush"), FontSize = 11, Margin = new Thickness(0, 12, 0, 0), TextWrapping = TextWrapping.Wrap };
            flow.Children.Add(_pipelineSummary);
            _pipelineTestResult = new TextBlock { Foreground = Br("TextBrush"), FontSize = 11, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 10, 0, 0), TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
            flow.Children.Add(_pipelineTestResult);
            flowCard.Child = flow;
            Grid.SetColumn(flowCard, 1); body.Children.Add(flowCard);

            Grid.SetRow(body, 1); PipelineHost.Children.Add(body);
            RenderPipeline();
        }

        private void RenderPipeline()
        {
            if (_pipelineList == null) return;
            _pipelineList.Items.Clear();
            if (_pipeline.Processors.Count == 0)
            {
                var empty = new Border { Style = (Style)FindResource("CardStyle"), Padding = new Thickness(24) };
                empty.Child = new TextBlock { Text = "No stages yet. Every event flows straight into the store.\nClick “Add stage” to drop noisy events, override severity, or tag/enrich by host.", Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center };
                _pipelineList.Items.Add(empty);
            }
            for (int i = 0; i < _pipeline.Processors.Count; i++)
                _pipelineList.Items.Add(BuildStageCard(_pipeline.Processors[i], i));
            if (_pipelineSummary != null)
            {
                int on = _pipeline.Processors.Count(p => p.Enabled);
                _pipelineSummary.Text = _pipeline.Processors.Count == 0
                    ? "Pipeline is pass-through."
                    : $"{on} active stage(s) of {_pipeline.Processors.Count}.  {_store.TotalDropped:N0} events dropped so far.";
            }
        }

        private Border BuildStageCard(SiemProcessor p, int index)
        {
            var card = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(14, 10, 12, 10), Margin = new Thickness(0, 0, 0, 8) };
            var dp = new DockPanel();

            var num = new Border { Width = 26, Height = 26, CornerRadius = new CornerRadius(13), Background = Br("BackgroundBrush"), Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center };
            num.Child = new TextBlock { Text = (index + 1).ToString(), Foreground = Br("AccentBrush"), FontWeight = FontWeights.Bold, FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(num, Dock.Left); dp.Children.Add(num);

            // controls on the right
            var ctrls = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var en = new ToggleButton { Style = (Style)FindResource("ToggleSwitchStyle"), IsChecked = p.Enabled, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0), ToolTip = "Enable / disable" };
            en.Click += (_, _) => { p.Enabled = en.IsChecked == true; CommitPipeline(); };
            ctrls.Children.Add(en);
            Button IconBtn(string icon, string tip, Action act)
            {
                var b = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Width = 28, Height = 28, ToolTip = tip, Foreground = Br("SubtleTextBrush") };
                b.Content = new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 12 };
                b.Click += (_, _) => act();
                return b;
            }
            ctrls.Children.Add(IconBtn("ArrowUp", "Move up", () => MoveStage(index, -1)));
            ctrls.Children.Add(IconBtn("ArrowDown", "Move down", () => MoveStage(index, +1)));
            ctrls.Children.Add(IconBtn("PenToSquare", "Edit", () => EditStage(p)));
            ctrls.Children.Add(IconBtn("TrashCan", "Remove", () => { _pipeline.Processors.Remove(p); CommitPipeline(); }));
            DockPanel.SetDock(ctrls, Dock.Right); dp.Children.Add(ctrls);

            var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Opacity = p.Enabled ? 1.0 : 0.5 };
            info.Children.Add(new TextBlock { Text = p.Summary(), Foreground = Br("TextBrush"), FontSize = 13, FontWeight = FontWeights.SemiBold });
            info.Children.Add(new TextBlock { Text = p.Type.ToString(), Foreground = Br("SubtleTextBrush"), FontSize = 10 });
            dp.Children.Add(info);

            card.Child = dp;
            return card;
        }

        private void MoveStage(int index, int dir)
        {
            int j = index + dir;
            if (j < 0 || j >= _pipeline.Processors.Count) return;
            (_pipeline.Processors[index], _pipeline.Processors[j]) = (_pipeline.Processors[j], _pipeline.Processors[index]);
            CommitPipeline();
        }

        private void AddStage_Click(object sender, RoutedEventArgs e)
        {
            var p = new SiemProcessor { Type = SiemProcessorType.Drop, MatchField = SiemMatchField.Category, MatchValue = "" };
            if (PipelineStageDialog.Edit(Window.GetWindow(this)!, p)) { _pipeline.Processors.Add(p); CommitPipeline(); }
        }

        // ── named pipelines (C11) ──
        private void RebuildPipelineSelector()
        {
            if (_pipelineSelector == null) return;
            _pipelineSelector.SelectionChanged -= PipelineSelector_Noop;   // no-op guard; selection handled inline
            _pipelineSelector.Items.Clear();
            foreach (var name in _pipelineSet.Names()) _pipelineSelector.Items.Add(name);
            _pipelineSelector.SelectedItem = _pipeline.Name;
        }
        private void PipelineSelector_Noop(object? s, SelectionChangedEventArgs e) { }

        private void NewPipeline()
        {
            var name = TextPromptDialog.Ask(Window.GetWindow(this), "New pipeline", "PIPELINE NAME", "", "Create");
            if (string.IsNullOrWhiteSpace(name)) return;
            name = name.Trim();
            if (_pipelineSet.ByName(name) != null) { ShowToastText("Name in use", $"A pipeline named “{name}” already exists."); return; }
            var pl = new SiemPipeline { Name = name };
            _pipelineSet.Pipelines.Add(pl);
            _pipeline = pl;
            SiemPipelineSetStore.Save(_pipelineSet);
            SiemAudit.Instance.Log("Config", "Created pipeline", name);
            RebuildPipelineSelector(); RenderPipeline();
        }

        private void DeletePipeline()
        {
            if (string.Equals(_pipeline.Name, "main", StringComparison.OrdinalIgnoreCase))
            { ShowToastText("Can't delete main", "The 'main' pipeline runs on ingestion and can't be removed."); return; }
            var removed = _pipeline.Name;
            _pipelineSet.Pipelines.Remove(_pipeline);
            _pipeline = _pipelineSet.Main();
            SiemPipelineSetStore.Save(_pipelineSet);
            _store.Pipeline = _pipelineSet.Main();
            SiemAudit.Instance.Log("Config", "Deleted pipeline", removed);
            RebuildPipelineSelector(); RenderPipeline();
        }

        /// <summary>Append a prebuilt integration's parser stages (the ELK "Integrations" catalog).</summary>
        private void AddIntegration_Click(object sender, RoutedEventArgs e)
        {
            var menu = new ContextMenu();
            foreach (var integ in SiemIntegrations.All)
            {
                var captured = integ;
                var header = new StackPanel { Orientation = Orientation.Horizontal };
                header.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(integ.Icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.PuzzlePiece, FontSize = 13, Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center });
                header.Children.Add(new TextBlock { Text = integ.Name, VerticalAlignment = VerticalAlignment.Center });
                var mi = new MenuItem { Header = header, ToolTip = captured.Description };
                mi.Click += (_, _) =>
                {
                    var stages = captured.Build();
                    _pipeline.Processors.AddRange(stages);
                    CommitPipeline();
                    SiemAudit.Instance.Log("Config", "Added integration", $"{captured.Name} ({stages.Count} stages)");
                    ShowToastText("Integration added", $"“{captured.Name}” added {stages.Count} pipeline stage(s).");
                };
                menu.Items.Add(mi);
            }
            menu.PlacementTarget = sender as UIElement; menu.IsOpen = true;
        }

        private void EditStage(SiemProcessor p) { if (PipelineStageDialog.Edit(Window.GetWindow(this)!, p)) CommitPipeline(); }

        private void CommitPipeline()
        {
            SiemPipelineSetStore.Save(_pipelineSet);
            _store.Pipeline = _pipelineSet.Main();   // ingestion always runs "main"
            RenderPipeline();
        }

        /// <summary>Dry-run the pipeline against the newest event (on a copy) and show the before/after.</summary>
        private void RunPipelineTest()
        {
            if (_pipelineTestResult == null) return;
            var sample = _store.Snapshot().FirstOrDefault();
            if (sample == null) { _pipelineTestResult.Text = "No events to test — turn on a source first."; _pipelineTestResult.Visibility = Visibility.Visible; return; }

            var before = $"IN:  [{sample.Severity}] {sample.Category}/{sample.EventType}";
            var result = _pipeline.Process(sample.Clone());   // copy → original untouched
            string after;
            if (result == null) after = "OUT: ✕ DROPPED by pipeline";
            else
            {
                var changes = new List<string>();
                if (result.Severity != sample.Severity) changes.Add($"severity {sample.Severity}→{result.Severity}");
                if (result.Category != sample.Category) changes.Add($"category→{result.Category}");
                if (result.Source != sample.Source) changes.Add($"source→{result.Source}");
                int added = result.Fields.Count - sample.Fields.Count;
                if (added != 0) changes.Add($"{(added > 0 ? "+" : "")}{added} field(s)");
                after = "OUT: ✓ kept" + (changes.Count > 0 ? "  ·  " + string.Join(", ", changes) : "  ·  unchanged");
            }
            _pipelineTestResult.Text = before + "\n" + after;
            _pipelineTestResult.Visibility = Visibility.Visible;
        }

        // ════════════════════════════════════════════════════════════════════
        //  Setup Guide tab — animated onboarding
        // ════════════════════════════════════════════════════════════════════
        private void BuildGuideTab()
        {
            var root = new StackPanel { MaxWidth = 1080, HorizontalAlignment = HorizontalAlignment.Left };

            root.Children.Add(new TextBlock { Text = "How the SIEM works", FontSize = 22, FontWeight = FontWeights.Bold, Foreground = Br("TextBrush") });
            root.Children.Add(new TextBlock { Text = "PrivaCore SIEM is a central collector. Lightweight agents on your machines ship logs to it; events flow through your pipeline, get indexed, and light up the dashboards in real time.", FontSize = 13, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 22) });

            // ── animated data-flow strip ──
            var flowCard = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(20, 24, 20, 24), Margin = new Thickness(0, 0, 0, 24) };
            var flow = new Grid();
            for (int i = 0; i < 7; i++) flow.ColumnDefinitions.Add(new ColumnDefinition { Width = (i % 2 == 0) ? new GridLength(1, GridUnitType.Star) : GridLength.Auto });
            void Node(int col, string icon, string title, string sub, string brush)
            {
                var sp = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                var disc = new Border { Width = 64, Height = 64, CornerRadius = new CornerRadius(32), Background = Br("BackgroundBrush"), BorderBrush = Br(brush), BorderThickness = new Thickness(2), HorizontalAlignment = HorizontalAlignment.Center };
                disc.Child = new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 26, Foreground = Br(brush), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                sp.Children.Add(disc);
                sp.Children.Add(new TextBlock { Text = title, Foreground = Br("TextBrush"), FontWeight = FontWeights.SemiBold, FontSize = 13, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 8, 0, 0) });
                sp.Children.Add(new TextBlock { Text = sub, Foreground = Br("SubtleTextBrush"), FontSize = 10, HorizontalAlignment = HorizontalAlignment.Center });
                Grid.SetColumn(sp, col); flow.Children.Add(sp);
            }
            void Chevrons(int col)
            {
                var sp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(6, 0, 6, 22) };
                for (int k = 0; k < 3; k++)
                {
                    var ch = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.ChevronRight, FontSize = 16, Foreground = Br("AccentBrush"), Opacity = 0.18, Margin = new Thickness(1, 0, 1, 0) };
                    _guideChevrons.Add(ch); sp.Children.Add(ch);
                }
                Grid.SetColumn(sp, col); flow.Children.Add(sp);
            }
            Node(0, "Server", "Your machines", "agents tail logs", "TextBrush");
            Chevrons(1);
            Node(2, "ChartBar", "SIEM collector", "central · port 9720", "AccentBrush");
            Chevrons(3);
            Node(4, "Filter", "Pipeline", "drop · enrich · tag", "SuccessBrush");
            Chevrons(5);
            Node(6, "GaugeHigh", "Dashboards", "search · alerts", "WarningBrush");
            flowCard.Child = flow;
            root.Children.Add(flowCard);

            // ── numbered steps ──
            var steps = new UniformGrid { Columns = 2 };
            FrameworkElement Step(int n, string icon, string title, string body, string? action = null, Action? onClick = null)
            {
                var card = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(18), Margin = new Thickness(0, 0, 16, 16) };
                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                var badge = new Border { Width = 36, Height = 36, CornerRadius = new CornerRadius(18), Background = Br("AccentBrush"), Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Top };
                badge.Child = new TextBlock { Text = n.ToString(), Foreground = Br("OnAccentBrush"), FontWeight = FontWeights.Bold, FontSize = 16, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(badge, 0); g.Children.Add(badge);
                var sp = new StackPanel();
                var t = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
                t.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 14, Foreground = Br("AccentBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
                t.Children.Add(new TextBlock { Text = title, Foreground = Br("TextBrush"), FontWeight = FontWeights.SemiBold, FontSize = 14, VerticalAlignment = VerticalAlignment.Center });
                sp.Children.Add(t);
                sp.Children.Add(new TextBlock { Text = body, Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap });
                if (action != null)
                {
                    var b = new Button { Content = action, Style = (Style)FindResource("GhostButtonStyle"), Height = 30, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 12, 0, 0) };
                    if (onClick != null) b.Click += (_, _) => onClick();
                    sp.Children.Add(b);
                }
                Grid.SetColumn(sp, 1); g.Children.Add(sp);
                card.Child = g;
                _guideCards.Add(card);
                return card;
            }
            steps.Children.Add(Step(1, "ChartBar", "Run the collector", "Start the PrivaCore SIEM module on a central machine. It listens on port 9720 and shows its reachable IPs in the title strip. Open the firewall (Modules/SIEM/Allow-Firewall.cmd) so other machines can reach it."));
            steps.Children.Add(Step(2, "Server", "Deploy an agent", "Copy privacore-agent to each machine you want to monitor (Windows, Linux, macOS). Point it at the collector IP + port with the operator credentials and pairing code, and list the logs to ship.", "View Sources & Agents", () => Tabs.SelectedItem = _sourcesTab));
            steps.Children.Add(Step(3, "Bolt", "Watch data arrive", "Events stream in live. The Overview tiles, Search, and the per-machine roll-up update in real time. No agents handy? Turn on demo data to see it instantly.", "Start demo data", StartDemo));
            steps.Children.Add(Step(4, "Filter", "Shape the pipeline", "Compose your own data flow: drop noisy events, override severity, re-tag or rename sources — top-to-bottom, Logstash-style. Changes apply to everything ingested next.", "Open Pipeline", () => Tabs.SelectedItem = _pipelineTab));
            root.Children.Add(steps);

            var cmd = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 10, 14, 10), Margin = new Thickness(0, 4, 16, 0) };
            cmd.Child = new TextBlock { FontFamily = new FontFamily("Consolas"), FontSize = 12.5, Foreground = Br("TextBrush"), TextWrapping = TextWrapping.Wrap, Text = "privacore-agent --host <collector-ip> --port 9720 --user admin --pass <password> --pairing <code> --name WEB01 --tail /var/log/auth.log,/var/log/syslog" };
            root.Children.Add(cmd);

            // ── full user manual (expandable, in-depth per area) ──
            root.Children.Add(new TextBlock { Text = "User manual", FontSize = 18, FontWeight = FontWeights.Bold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 30, 0, 4) });
            root.Children.Add(new TextBlock { Text = "Click any section to expand it. This documents every part of the SIEM and exactly how to use it.", FontSize = 12, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 14) });
            var manual = new StackPanel { Margin = new Thickness(0, 0, 16, 0) };
            var sections = GuideSections();
            for (int i = 0; i < sections.Length; i++)
                manual.Children.Add(BuildManualSection(sections[i], expanded: i == 0));
            root.Children.Add(manual);

            // ── query cheatsheet ──
            root.Children.Add(new TextBlock { Text = "Search cheat-sheet", FontSize = 18, FontWeight = FontWeights.Bold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 14, 0, 4) });
            var cheats = new[]
            {
                ("host:DC01", "events from a host"),
                ("severity:>=high", "severity at or above High"),
                ("(host:DC01 OR host:WEB02) AND severity:>=high", "boolean + grouping"),
                ("user.name:adm*", "wildcard match"),
                ("network.bytes>=1000", "numeric range on any field"),
                ("NOT category:noise", "exclude a category"),
                ("\"failed logon\"", "free-text phrase"),
            };
            var cheatSp = new StackPanel { Margin = new Thickness(0, 0, 16, 0) };
            foreach (var (q, what) in cheats)
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 5) };
                var whatTb = new TextBlock { Text = what, Foreground = Br("SubtleTextBrush"), FontSize = 11.5, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };
                DockPanel.SetDock(whatTb, Dock.Right); row.Children.Add(whatTb);
                var code = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(5), Padding = new Thickness(8, 3, 8, 3), HorizontalAlignment = HorizontalAlignment.Left };
                code.Child = new TextBlock { Text = q, FontFamily = new FontFamily("Consolas"), FontSize = 12, Foreground = Br("AccentBrush") };
                row.Children.Add(code);
                cheatSp.Children.Add(row);
            }
            root.Children.Add(cheatSp);

            var reopen = new Button { Content = "Show the welcome tour again", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 22, 0, 0), Padding = new Thickness(14, 0, 14, 0) };
            reopen.Click += (_, _) => ShowWelcome();
            root.Children.Add(reopen);

            GuideHost.Children.Add(root);
        }

        // ── in-depth user manual ──────────────────────────────────────────────
        // Block kinds: 'h' heading · 'p' paragraph · 'b' bullet · 'c' code/example · 't' tip
        private sealed record ManualSection(string Icon, string Title, (char kind, string text)[] Blocks);

        private static ManualSection[] GuideSections() => new ManualSection[]
        {
            new("Rocket", "1 · Getting started & deploying agents", new (char,string)[]
            {
                ('p', "PrivaCore SIEM is a central collector. It runs on one machine, listens on a TCP port (9720 by default), and receives security events from many sources: this machine's own logs, syslog from network gear, anything POSTing JSON, and the cross-platform PrivaCore agent installed on your servers/workstations."),
                ('h', "Start the collector"),
                ('b', "Run it — launch the SIEM module on a central, always-on machine. The title strip shows its reachable LAN IPs and \"Listening on port 9720\"."),
                ('b', "Open the firewall — run as Administrator, or run Modules/SIEM/Allow-Firewall.cmd, so other machines can reach the port. If you see \"firewall not opened\" in the strip, remote agents will be blocked until you do this."),
                ('b', "Set credentials — the operator username/password and a pairing code protect the collector. Change them any time with the Reconfigure button (top-right)."),
                ('h', "Deploy an agent on a machine to monitor"),
                ('p', "Copy privacore-agent to the target (Windows, Linux or macOS) and point it at the collector. First run with no config starts an interactive setup, or pass everything on the command line:"),
                ('c', "privacore-agent --host <collector-ip> --port 9720 --user admin --pass <password> --pairing <code> --name WEB01 --tail /var/log/auth.log,/var/log/syslog --gen"),
                ('b', "--host / --port — where the collector is."),
                ('b', "--user / --pass / --pairing — must match the collector's operator credentials + pairing code."),
                ('b', "--name — how this machine appears in the SIEM."),
                ('b', "--tail — comma-separated log files to ship (only new lines are sent)."),
                ('b', "--gen — also emit demo events (handy for a quick test)."),
                ('t', "No machines to hand right now? Open Sources & Agents and toggle Demo Generator, or click \"Start demo data\" in the steps above — events stream in immediately so you can explore every tab."),
            }),

            new("Clock", "2 · Time range & global search (top bar)", new (char,string)[]
            {
                ('p', "The header controls at the top apply everywhere — Overview tiles, Search, Entities, Network and the KPI strip all honour them."),
                ('h', "Time range"),
                ('b', "Quick ranges — 5m / 15m / 1h / 24h / All. The highlighted one is active."),
                ('b', "More ranges (⋯) — extra presets (30m, 6h, 12h, 3d, 7d, 30d), a Custom-minutes prompt, and an Absolute range (pick a fixed From / To)."),
                ('b', "Rolling vs absolute — quick/custom ranges roll forward live (\"last 15m\"); absolute ranges pin two exact timestamps and stop moving."),
                ('h', "Global search box"),
                ('p', "Type a query here to filter the whole workspace. It uses the same language as Discover (see the Search section). Clear it with the ✕ to go back to everything in the window."),
            }),

            new("GaugeHigh", "3 · Overview & dashboards", new (char,string)[]
            {
                ('p', "The landing page: a KPI strip plus a grid of tiles you fully control. You can keep several named dashboards."),
                ('h', "KPI strip"),
                ('p', "Total events ingested, events in the current window, events/sec, Critical & High counts, reporting machines, how many events your pipeline has dropped, and the ingest-queue depth (a bounded back-pressure buffer that absorbs bursts; hover it for peak/processed/dropped)."),
                ('h', "Tiles"),
                ('b', "＋ Visualize — build your own tile: choose a chart (Metric / Bar / Donut / Table / Line), an aggregation (count, unique-count, sum, avg, min, max, top-N), and a field. Example: a Metric of unique-count over source.ip, or a Bar of top host.name."),
                ('b', "＋ Add panel — drop in a ready-made tile (histogram, severity donut, top sources/categories/event-types, watchlist)."),
                ('b', "Edit / remove — custom tiles have a pencil (reconfigure) and ✕ (remove) in their header."),
                ('b', "Click to drill in — clicking a bar/slice/row adds that value as a filter and takes you to Search."),
                ('h', "Multiple dashboards"),
                ('b', "Switcher (▦ name ▾) — switch between dashboards, or New / Rename / Delete. Each dashboard keeps its own set of tiles, saved automatically."),
                ('b', "Reset — restores the default tile set for the current dashboard."),
            }),

            new("MagnifyingGlass", "4 · Search (Discover) — finding events", new (char,string)[]
            {
                ('p', "Discover is where you investigate raw events. Results stream live and respect the time range + global search."),
                ('b', "Auto-refresh — the ⟳ control in the top bar sets how often the dashboard re-queries (Off / 1s / 5s / 10s / 30s / 1m / 5m). Set it to Off to freeze the view while you investigate."),
                ('h', "The query language (KQL-style)"),
                ('b', "field:value — substring match, e.g. host:DC01 (case-insensitive)."),
                ('b', "Ranges — severity:>=high, network.bytes>=1000, http.response.status_code:>=500. Works on any numeric field and on severity."),
                ('b', "Wildcards — user.name:adm*  or  host:DC0?  ( * = any run, ? = one char )."),
                ('b', "Booleans & grouping — (host:DC01 OR host:WEB02) AND severity:>=high. Adjacent terms are AND-ed by default."),
                ('b', "Negation — NOT category:noise, or -host:DC01, or !user.name:svc."),
                ('b', "Phrases — wrap multi-word values in quotes: message:\"failed logon\"."),
                ('c', "(event.action:logon AND event.outcome:failure) AND source.ip:10.* NOT user.name:svc_backup"),
                ('h', "Fields sidebar (left)"),
                ('b', "Every field present in the results, with how many documents have it. Type to filter the list."),
                ('b', "Click a field — see its top values with % bars; use the magnifier+/- to filter FOR or OUT that value."),
                ('b', "＋ / ✕ — add the field as a column (or remove it). \"Reset columns\" goes back to the Document summary."),
                ('h', "Results & documents"),
                ('b', "Click a row — expands the full document. Toggle Table / JSON; each field has filter-for, filter-out and toggle-column actions; Pin adds the event to the Timeline."),
                ('b', "Filter pills — every active clause shows as a chip; click to flip include/exclude, ✕ to remove, \"Clear all\" to reset."),
                ('b', "Histogram — events over time; drag across it to zoom into that exact span (sets an absolute range)."),
                ('h', "Toolbar"),
                ('b', "Save search — names the current query + columns + time range; reopen later from Open. Delete from the Open menu."),
                ('b', "Export CSV — writes the matching events (your selected columns) to a file."),
                ('t', "Columns can be reordered and resized by dragging their headers."),
            }),

            new("Server", "5 · Sources & ingestion", new (char,string)[]
            {
                ('p', "The Sources & Agents tab controls what this collector ingests locally, and shows who's reporting in."),
                ('h', "Local sources (toggle chips)"),
                ('b', "Win Event Log — Security / System / Application channels (the Security log needs Administrator)."),
                ('b', "Syslog UDP :5514 — listens for RFC3164 and RFC5424 syslog over UDP."),
                ('b', "Syslog TCP :5514 — same, over a newline-delimited TCP stream."),
                ('b', "HTTP ingest :9721 — accepts JSON. POST a single object or an array; known keys map to columns, everything else becomes a field."),
                ('c', "curl -X POST http://<collector>:9721/ -H \"Content-Type: application/json\" -d '{\"message\":\"hi\",\"severity\":\"high\",\"host\":\"DC01\",\"user.name\":\"admin\"}'"),
                ('b', "Query API — GET /api/search on the same HTTP port returns matching events as JSON (ECS _source); honours the ingest token. Lets SOAR/scripts pull data out."),
                ('c', "curl \"http://<collector>:9721/api/search?q=severity:>=high&size=50&minutes=60\" -H \"X-Ingest-Token: <secret>\""),
                ('b', "Demo Generator — synthetic events for testing/demos."),
                ('h', "Reporting machines & agents"),
                ('p', "A live roll-up of every host sending events — last source, event/high/critical counts, last-seen, and LIVE/IDLE. Double-click a row to investigate that host in Discover."),
            }),

            new("Robot", "6 · Fleet — managed agents", new (char,string)[]
            {
                ('p', "Agents that connect don't just send data — they enrol into a Fleet inventory you can manage centrally, in the \"Managed agents (Fleet)\" card."),
                ('b', "Inventory — each agent's name, ONLINE/OFFLINE status, OS, version, events shipped, and last check-in (every ~20s). Status flips to OFFLINE automatically when an agent disconnects."),
                ('b', "Push policy — select an agent and click Push policy to reconfigure it remotely and live (no restart on the agent):"),
                ('b', "  · Heartbeat + interval — whether/how often it emits a heartbeat."),
                ('b', "  · Demo generator — turn synthetic events on/off."),
                ('b', "  · Tail files — the exact set of log files it ships."),
                ('t', "If an agent is offline when you push, the policy is stored and applied the next time it reconnects."),
            }),

            new("DiagramProject", "7 · Pipeline — shaping events", new (char,string)[]
            {
                ('p', "Every event entering the store passes through your pipeline, top to bottom (Logstash-style). Use it to cut noise, normalise, enrich and re-tag. Add a stage with ＋ Add stage; drag the ▲/▼ to reorder; toggle a stage on/off; edit or delete it."),
                ('p', "Each stage has a WHERE clause (a field + substring, or \"every event\") and an action:"),
                ('b', "Drop — discard matching events (noise reduction)."),
                ('b', "KeepOnly — discard everything that does NOT match."),
                ('b', "SetSeverity / SetCategory / RenameSource — overwrite those values."),
                ('b', "AddTag — add a field, written as key=value."),
                ('b', "ExtractRegex — run a .NET regex with NAMED groups over a field; each group becomes a field. Example pattern below pulls user + ip out of a message:"),
                ('c', "user (?<user>\\w+) from (?<ip>[\\d.]+)"),
                ('b', "RenameField / RemoveField / Lowercase — edit the open field bag."),
                ('b', "ParseTimestamp — set the event time from a field (optionally with a .NET date format)."),
                ('b', "Dedupe — drop repeats of a fingerprint field within N seconds."),
                ('b', "IndicatorMatch (threat intel) — if a field (default the common IOC fields) matches your known-bad list, tag threat.matched=true and escalate severity to High."),
                ('b', "GeoEnrich — real GeoIP lookup on an IP field; adds {prefix}.geo.country_name / country_iso_code and ASN/ISP."),
                ('b', "Test pipeline — runs the newest event through a copy of the pipeline and shows the before/after (dropped vs kept + what changed)."),
                ('t', "Combine stages: an IndicatorMatch tagging threat.matched=true plus a Threshold rule on threat.matched:true gives you indicator-match alerting."),
            }),

            new("Bell", "8 · Detection rules & Alerts", new (char,string)[]
            {
                ('p', "The Alerts tab has three inner views: Active alerts (what fired), Rules (your detections), and ATT&CK coverage."),
                ('h', "Building a rule (Rules → ＋ New rule)"),
                ('b', "Query — the events to watch, in the Discover language."),
                ('b', "Condition — Threshold (total matches ≥ N in the window), GroupThreshold (≥ N from one Group-by value, e.g. per source.ip), NewTerms (a Group-by value never seen before in history), Sequence (≥ N of the query, THEN a second query, from the same group, in order), Anomaly (rate spikes σ above a rolling baseline), or IndicatorMatch (events whose observables hit a managed threat-intel indicator)."),
                ('b', "Threshold + Window — how many, over how many minutes."),
                ('b', "Group by — the field to correlate on (source.ip, user.name, …)."),
                ('b', "Exception — events matching this query are ignored (allow-list known-good, e.g. user.name:svc_backup)."),
                ('b', "Severity + MITRE — the alert's severity and ATT&CK technique/tactic tags."),
                ('b', "Webhook URL — optional; the alert is POSTed there (Slack/Teams/generic JSON) when it fires."),
                ('b', "Add from library — drop in ready-made detections (brute force, malware, log cleared, new service, sequence, …); tweak as needed."),
                ('h', "How alerts behave"),
                ('p', "The engine evaluates enabled rules every ~15s. A trip raises an alert (with a toast), drops an alert event into the store, and is suppressed by a per-rule/group cooldown so it won't re-fire every tick."),
                ('h', "Triage (Active alerts)"),
                ('b', "Select an alert, then Acknowledge or Close; Clear closed removes resolved ones."),
                ('b', "Add to case — bundle the alert into a case for investigation."),
                ('h', "ATT&CK coverage"),
                ('p', "A matrix of MITRE tactics; covered tactics are highlighted with their technique chips, and chips outline/badge by live alert count so you can see your detection gaps."),
            }),

            new("Briefcase", "9 · Cases & 10 · Timeline (investigation)", new (char,string)[]
            {
                ('h', "Cases"),
                ('b', "＋ New case — title, description, severity, status."),
                ('b', "Attach evidence — from Alerts, select one and use Add to case (new or existing)."),
                ('b', "Collaborate — add comments; move the case Open → In progress → Closed with the status pills."),
                ('h', "Timeline"),
                ('b', "Pin — expand a document in Discover and click Pin to add it to the Timeline."),
                ('b', "Annotate — entries are shown oldest→newest on a rail; add a note to each."),
                ('b', "Clear timeline — empties the board when you're done."),
            }),

            new("UsersViewfinder", "11 · Entities & Network", new (char,string)[]
            {
                ('h', "Entities"),
                ('p', "Host and User sub-tabs rank entities by a severity-weighted risk score (0–100): Critical events add the most, then High, Medium, Low. Use it to spot the riskiest machines/accounts at a glance. Double-click an entity to investigate its events in Discover."),
                ('h', "Network"),
                ('p', "A network-centric breakdown of the current window: top source IPs, destination IPs, destination ports, protocols (donut), top talkers and top countries, plus unique-IP counts and total bytes transferred. Click any value to pivot into Discover."),
            }),

            new("Database", "12 · Index, retention & saved objects", new (char,string)[]
            {
                ('p', "The Index tab is storage management for the in-memory event index."),
                ('b', "Stats — document count vs capacity, approximate size, ingested vs dropped, time span, and per-source document counts."),
                ('b', "Retention — Max events (ring-buffer capacity), Max age (purge events older than N minutes; 0 = keep), and Persist to disk (snapshot the index so it survives a restart). Click Apply retention."),
                ('b', "Danger zone — Delete matching current search (delete-by-query) and Clear entire index."),
                ('h', "Saved objects (backup / share)"),
                ('b', "Export config — writes your rules, saved searches, dashboards, pipeline and settings to one JSON file."),
                ('b', "Import config — loads such a file (replaces the current configuration). Great for moving a setup between collectors."),
            }),

            new("CircleQuestion", "13 · Tips & troubleshooting", new (char,string)[]
            {
                ('b', "No events at all? — On Sources & Agents turn on Demo Generator (or Win Event Log). Check the time range isn't a tiny window in the past."),
                ('b', "An agent won't connect? — Verify host/port, that the collector's firewall is open (run as Admin / Allow-Firewall.cmd), and that the agent's user/pass/pairing exactly match the collector."),
                ('b', "A rule never fires? — Test its Query in Discover first to confirm it matches; check the Threshold/Window and that it's enabled; remember the cooldown suppresses repeats within the window."),
                ('b', "Too much noise? — Add a Drop or Dedupe stage in the Pipeline, or an Exception on the rule."),
                ('b', "Geo/threat fields missing? — Add a GeoEnrich / IndicatorMatch stage; GeoIP fills in once an IP has been looked up (it warms its cache in the background)."),
                ('t', "You can reopen this whole tour any time from the button at the bottom of this guide, or from the welcome screen on startup."),
            }),
        };

        private Border BuildManualSection(ManualSection s, bool expanded)
        {
            var card = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Margin = new Thickness(0, 0, 0, 8) };
            var outer = new StackPanel();

            // clickable header
            var header = new Border { Background = Brushes.Transparent, Padding = new Thickness(14, 12, 12, 12), Cursor = Cursors.Hand };
            var hd = new DockPanel();
            var chevron = new FontAwesome.Sharp.IconBlock { Icon = expanded ? FontAwesome.Sharp.IconChar.AngleDown : FontAwesome.Sharp.IconChar.AngleRight, FontSize = 14, Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(chevron, Dock.Right); hd.Children.Add(chevron);
            hd.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(s.Icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 15, Foreground = Br("AccentBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) });
            hd.Children.Add(new TextBlock { Text = s.Title, Foreground = Br("TextBrush"), FontWeight = FontWeights.SemiBold, FontSize = 14, VerticalAlignment = VerticalAlignment.Center });
            header.Child = hd;
            outer.Children.Add(header);

            // content
            var content = new StackPanel { Margin = new Thickness(16, 0, 16, 14), Visibility = expanded ? Visibility.Visible : Visibility.Collapsed };
            foreach (var (kind, text) in s.Blocks) content.Children.Add(ManualBlock(kind, text));
            outer.Children.Add(content);

            header.MouseLeftButtonUp += (_, _) =>
            {
                bool show = content.Visibility != Visibility.Visible;
                content.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
                chevron.Icon = show ? FontAwesome.Sharp.IconChar.AngleDown : FontAwesome.Sharp.IconChar.AngleRight;
                if (show)
                {
                    content.Opacity = 0; var tt = new TranslateTransform(0, -6); content.RenderTransform = tt;
                    content.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(220))));
                    tt.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(-6, 0, new Duration(TimeSpan.FromMilliseconds(220))) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
                }
            };

            card.Child = outer;
            return card;
        }

        private UIElement ManualBlock(char kind, string text) => kind switch
        {
            'h' => new TextBlock { Text = text, Foreground = Br("TextBrush"), FontWeight = FontWeights.SemiBold, FontSize = 12.5, Margin = new Thickness(0, 12, 0, 5) },
            'c' => new Border
            {
                Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(5),
                Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 3, 0, 6), HorizontalAlignment = HorizontalAlignment.Left,
                Child = new TextBlock { Text = text, FontFamily = new FontFamily("Consolas"), FontSize = 12, Foreground = Br("AccentBrush"), TextWrapping = TextWrapping.Wrap },
            },
            't' => BuildTipRow(text),
            'b' => BuildBulletRow(text),
            _ => new TextBlock { Text = text, Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 5), LineHeight = 18 },
        };

        private UIElement BuildBulletRow(string text)
        {
            var g = new Grid { Margin = new Thickness(2, 0, 0, 5) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var dot = new TextBlock { Text = "•", Foreground = Br("AccentBrush"), FontSize = 12, Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Top };
            Grid.SetColumn(dot, 0); g.Children.Add(dot);
            // bold the part before " — " (the label) if present
            var tb = new TextBlock { Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, LineHeight = 18 };
            int dash = text.IndexOf(" — ", StringComparison.Ordinal);
            if (dash > 0)
            {
                tb.Inlines.Add(new System.Windows.Documents.Run(text[..dash]) { Foreground = Br("TextBrush"), FontWeight = FontWeights.SemiBold });
                tb.Inlines.Add(new System.Windows.Documents.Run(text[dash..]));
            }
            else tb.Text = text;
            Grid.SetColumn(tb, 1); g.Children.Add(tb);
            return g;
        }

        private UIElement BuildTipRow(string text)
        {
            var b = new Border { Background = Br("BackgroundBrush"), CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 3, 0, 6) };
            var dp = new DockPanel();
            dp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.Lightbulb, FontSize = 12, Foreground = Br("WarningBrush"), VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 1, 8, 0) });
            dp.Children.Add(new TextBlock { Text = text, Foreground = Br("SubtleTextBrush"), FontSize = 11.5, TextWrapping = TextWrapping.Wrap, LineHeight = 17 });
            b.Child = dp;
            return b;
        }

        private void StartDemo()
        {
            _ing.StartGenerator();
            if (_genChip != null) _genChip.IsChecked = _ing.GeneratorOn;
        }

        private void AnimateGuide()
        {
            // staggered fade + rise for the step cards
            for (int i = 0; i < _guideCards.Count; i++)
            {
                var el = _guideCards[i];
                var tt = new TranslateTransform(0, 18);
                el.RenderTransform = tt; el.Opacity = 0;
                var begin = TimeSpan.FromMilliseconds(120 * i);
                el.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(420))) { BeginTime = begin, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
                tt.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(18, 0, new Duration(TimeSpan.FromMilliseconds(420))) { BeginTime = begin, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
            }
            // continuously "flow" the chevrons left→right
            for (int i = 0; i < _guideChevrons.Count; i++)
            {
                var ch = _guideChevrons[i];
                var anim = new DoubleAnimation(0.18, 1.0, new Duration(TimeSpan.FromMilliseconds(520)))
                {
                    AutoReverse = true,
                    RepeatBehavior = RepeatBehavior.Forever,
                    BeginTime = TimeSpan.FromMilliseconds(140 * i),
                };
                ch.BeginAnimation(OpacityProperty, anim);
            }
        }

        // ════════════════════════════════════════════════════════════════════
        //  Welcome / how-to overlay (shown on startup; "don't show again")
        // ════════════════════════════════════════════════════════════════════
        private Border? _welcomeOverlay;

        private void ShowWelcome()
        {
            if (Content is not Grid root || _welcomeOverlay != null) return;

            // dimmed backdrop covering the whole page
            var overlay = new Border { Background = new SolidColorBrush(Color.FromArgb(190, 0, 0, 0)) };
            Grid.SetRowSpan(overlay, Math.Max(1, root.RowDefinitions.Count));
            Panel.SetZIndex(overlay, 1000);

            // centered card
            var card = new Border
            {
                Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("AccentBrush"), BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14), Padding = new Thickness(0), MaxWidth = 760, MaxHeight = 760,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(24),
                Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = Colors.Black, BlurRadius = 40, ShadowDepth = 6, Opacity = 0.5 },
            };
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // header
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // scroll body
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // footer

            // header with animated flow strip
            var header = new Border { Padding = new Thickness(26, 22, 26, 16) };
            var hsp = new StackPanel();
            hsp.Children.Add(new TextBlock { Text = "Welcome to PrivaCore SIEM", FontSize = 22, FontWeight = FontWeights.Bold, Foreground = Br("TextBrush") });
            hsp.Children.Add(new TextBlock { Text = "A central collector for security events: agents ship logs in, your pipeline shapes them, and the workspace lets you search, visualize, detect and investigate.", FontSize = 12.5, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 14) });
            var chevrons = new System.Collections.Generic.List<FontAwesome.Sharp.IconBlock>();
            hsp.Children.Add(BuildFlowStrip(chevrons));
            header.Child = hsp;
            Grid.SetRow(header, 0); grid.Children.Add(header);

            // body: the parts list (staggered)
            var body = new StackPanel { Margin = new Thickness(26, 4, 26, 8) };
            body.Children.Add(new TextBlock { Text = "COMPLETE WALKTHROUGH  ·  click any section to expand", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 8) });
            var rows = new System.Collections.Generic.List<FrameworkElement>();
            var secs = GuideSections();
            for (int i = 0; i < secs.Length; i++)
            {
                var sectionCard = BuildManualSection(secs[i], expanded: i == 0);   // same full manual as the Setup Guide
                body.Children.Add(sectionCard);
                rows.Add(sectionCard);
            }
            var bodySv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = body };
            Grid.SetRow(bodySv, 1); grid.Children.Add(bodySv);

            // footer: don't-show + actions
            var footer = new Border { Background = Br("BackgroundBrush"), CornerRadius = new CornerRadius(0, 0, 14, 14), Padding = new Thickness(26, 14, 26, 16), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(0, 1, 0, 0) };
            var fdp = new DockPanel();
            var dontShow = new CheckBox { Content = "Don't show this again", Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Center, FontSize = 12 };
            try { dontShow.Style = (Style)FindResource("CheckBoxStyle"); } catch { }
            fdp.Children.Add(dontShow);
            var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            DockPanel.SetDock(actions, Dock.Right);
            var guideBtn = new Button { Content = "Open Setup Guide", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(14, 0, 14, 0) };
            var startBtn = new Button { Content = "Get started", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 120 };
            void Close() { SiemWelcome.SetDontShow(dontShow.IsChecked == true); HideWelcome(); }
            guideBtn.Click += (_, _) => { SiemWelcome.SetDontShow(dontShow.IsChecked == true); HideWelcome(); SelectGuideTab(); };
            startBtn.Click += (_, _) => Close();
            actions.Children.Add(guideBtn); actions.Children.Add(startBtn);
            fdp.Children.Add(actions);
            footer.Child = fdp;
            Grid.SetRow(footer, 2); grid.Children.Add(footer);

            card.Child = grid;
            overlay.Child = card;
            root.Children.Add(overlay);
            _welcomeOverlay = overlay;

            // ── animate in ──
            overlay.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(200))));
            var ct = new TranslateTransform(0, 30); card.RenderTransform = ct; card.Opacity = 0;
            card.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(380))) { BeginTime = TimeSpan.FromMilliseconds(80) });
            ct.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(30, 0, new Duration(TimeSpan.FromMilliseconds(420))) { BeginTime = TimeSpan.FromMilliseconds(80), EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
            for (int i = 0; i < rows.Count; i++)
            {
                var el = rows[i]; var tt = new TranslateTransform(0, 14); el.RenderTransform = tt; el.Opacity = 0;
                var begin = TimeSpan.FromMilliseconds(220 + 55 * i);
                el.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(360))) { BeginTime = begin, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
                tt.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(14, 0, new Duration(TimeSpan.FromMilliseconds(360))) { BeginTime = begin, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
            }
            for (int i = 0; i < chevrons.Count; i++)
                chevrons[i].BeginAnimation(OpacityProperty, new DoubleAnimation(0.18, 1.0, new Duration(TimeSpan.FromMilliseconds(520))) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever, BeginTime = TimeSpan.FromMilliseconds(140 * i) });
        }

        private void HideWelcome()
        {
            if (_welcomeOverlay == null || Content is not Grid root) return;
            var ov = _welcomeOverlay; _welcomeOverlay = null;
            var fade = new DoubleAnimation(1, 0, new Duration(TimeSpan.FromMilliseconds(220)));
            fade.Completed += (_, _) => root.Children.Remove(ov);
            ov.BeginAnimation(OpacityProperty, fade);
        }

        private void SelectGuideTab()
        {
            // Setup Guide is the last tab
            if (Tabs.Items.Count > 0) Tabs.SelectedIndex = Tabs.Items.Count - 1;
        }

        /// <summary>An animated agents → collector → pipeline → dashboards strip (chevrons collected for looping).</summary>
        private UIElement BuildFlowStrip(System.Collections.Generic.List<FontAwesome.Sharp.IconBlock> chevrons)
        {
            var card = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(14, 14, 14, 14) };
            var flow = new Grid();
            for (int i = 0; i < 7; i++) flow.ColumnDefinitions.Add(new ColumnDefinition { Width = (i % 2 == 0) ? new GridLength(1, GridUnitType.Star) : GridLength.Auto });
            void Node(int col, string icon, string title, string brush)
            {
                var sp = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                var disc = new Border { Width = 44, Height = 44, CornerRadius = new CornerRadius(22), Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br(brush), BorderThickness = new Thickness(2), HorizontalAlignment = HorizontalAlignment.Center };
                disc.Child = new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 18, Foreground = Br(brush), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                sp.Children.Add(disc);
                sp.Children.Add(new TextBlock { Text = title, Foreground = Br("TextBrush"), FontSize = 10.5, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 6, 0, 0) });
                Grid.SetColumn(sp, col); flow.Children.Add(sp);
            }
            void Chevrons(int col)
            {
                var sp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 4, 16) };
                for (int k = 0; k < 3; k++)
                {
                    var ch = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.ChevronRight, FontSize = 13, Foreground = Br("AccentBrush"), Opacity = 0.18, Margin = new Thickness(1, 0, 1, 0) };
                    chevrons.Add(ch); sp.Children.Add(ch);
                }
                Grid.SetColumn(sp, col); flow.Children.Add(sp);
            }
            Node(0, "Server", "Agents", "TextBrush"); Chevrons(1);
            Node(2, "ChartBar", "Collector", "AccentBrush"); Chevrons(3);
            Node(4, "Filter", "Pipeline", "SuccessBrush"); Chevrons(5);
            Node(6, "GaugeHigh", "Workspace", "WarningBrush");
            card.Child = flow;
            return card;
        }

        // ════════════════════════════════════════════════════════════════════
        //  Entities tab — host / user analytics + risk (investigation)
        // ════════════════════════════════════════════════════════════════════
        private void BuildEntitiesTab()
        {
            _entitiesTab = EntitiesHost.Parent as TabItem;
            var inner = new TabControl { Style = (Style)FindResource("TabControlStyle"), Background = Br("BackgroundBrush"), Padding = new Thickness(0) };

            (_hostGrid, _hostRows) = BuildEntityGrid("host");
            var hostItem = new TabItem { Style = (Style)FindResource("TabItemStyle"), Header = TabHeader("Server", "Hosts") };
            hostItem.Content = WrapEntityGrid(_hostGrid, _hostRows, "Server", "No hosts in range", "Host risk is computed from the severity of each host's events.");
            inner.Items.Add(hostItem);

            (_userGrid, _userRows) = BuildEntityGrid("user.name");
            var userItem = new TabItem { Style = (Style)FindResource("TabItemStyle"), Header = TabHeader("User", "Users") };
            userItem.Content = WrapEntityGrid(_userGrid, _userRows, "User", "No users in range", "User risk is computed from events carrying a user.name field.");
            inner.Items.Add(userItem);

            // Process-tree (session view) — host → parent process → child processes
            var procItem = new TabItem { Style = (Style)FindResource("TabItemStyle"), Header = TabHeader("Sitemap", "Processes") };
            var procGrid = new Grid { Margin = new Thickness(18) };
            procGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            procGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            procGrid.Children.Add(new TextBlock { Text = "Process activity grouped by host → parent → child (from process events in range). Click a process to investigate it in Discover.", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 12) });
            _processHost = new Border();
            var psv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _processHost };
            Grid.SetRow(psv, 1); procGrid.Children.Add(psv);
            procItem.Content = procGrid;
            inner.Items.Add(procItem);

            _entitiesInner = inner;
            _entityDetailHost = new Border { Visibility = Visibility.Collapsed };
            EntitiesHost.Children.Add(inner);
            EntitiesHost.Children.Add(_entityDetailHost);
            RefreshEntities();
        }

        private TabControl? _entitiesInner;
        private Border? _entityDetailHost;
        private Border? _processHost;

        /// <summary>G8: build a host → parent-process → child-process tree from process-category events.</summary>
        private void RefreshProcessTree()
        {
            if (_processHost == null) return;
            var procs = _store.Query(SiemQuery.Parse("event.category:process"), _window, 20_000)
                .Where(e => !string.IsNullOrEmpty(e.Get("process.name"))).ToList();

            if (procs.Count == 0)
            {
                _processHost.Child = new TextBlock { Text = "No process events in range. Turn on the demo generator or a Windows 4688 source.", Foreground = Br("SubtleTextBrush"), FontSize = 12 };
                return;
            }

            var tree = new TreeView { Background = Brushes.Transparent, BorderThickness = new Thickness(0) };
            foreach (var hostGroup in procs.GroupBy(e => string.IsNullOrEmpty(e.Host) ? "(unknown)" : e.Host).OrderByDescending(g => g.Count()))
            {
                var hostNode = new TreeViewItem { Header = ProcNodeHeader("Server", hostGroup.Key, $"{hostGroup.Count()} process event(s)", Br("AccentBrush")), IsExpanded = false, Foreground = Br("TextBrush") };
                foreach (var parentGroup in hostGroup.GroupBy(e => { var p = e.Get("process.parent.name"); return string.IsNullOrEmpty(p) ? "(no parent)" : p; }).OrderByDescending(g => g.Count()))
                {
                    var parentNode = new TreeViewItem { Header = ProcNodeHeader("DiagramProject", parentGroup.Key, $"{parentGroup.Select(e => e.Get("process.name")).Distinct().Count()} child process(es)", Br("SubtleTextBrush")), Foreground = Br("TextBrush") };
                    foreach (var childGroup in parentGroup.GroupBy(e => e.Get("process.name") ?? "").OrderByDescending(g => g.Count()))
                    {
                        var sample = childGroup.First();
                        var pid = sample.Get("process.pid");
                        var childNode = new TreeViewItem
                        {
                            Header = ProcNodeHeader("Gears", childGroup.Key + (string.IsNullOrEmpty(pid) ? "" : $"  (pid {pid})"), $"{childGroup.Count()}×  ·  {sample.Get("user.name") ?? "—"}", Br("TextBrush")),
                            Foreground = Br("TextBrush"), Cursor = Cursors.Hand,
                        };
                        var capturedName = childGroup.Key;
                        childNode.Selected += (_, ev) => { ev.Handled = true; AddFilter("process.name", capturedName); Tabs.SelectedItem = _searchTab; };
                        parentNode.Items.Add(childNode);
                    }
                    hostNode.Items.Add(parentNode);
                }
                tree.Items.Add(hostNode);
            }
            _processHost.Child = tree;
        }

        private UIElement ProcNodeHeader(string icon, string title, string sub, Brush titleColor)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            sp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 12, Foreground = titleColor, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            sp.Children.Add(new TextBlock { Text = title, Foreground = titleColor, FontWeight = FontWeights.SemiBold, FontSize = 12.5, VerticalAlignment = VerticalAlignment.Center, FontFamily = new FontFamily("Consolas") });
            sp.Children.Add(new TextBlock { Text = "   " + sub, Foreground = Br("SubtleTextBrush"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center });
            return sp;
        }

        private (DataGrid grid, ObservableCollection<SiemEntityStat> rows) BuildEntityGrid(string filterField)
        {
            var rows = new ObservableCollection<SiemEntityStat>();
            var grid = ThemedGrid(40);
            grid.MaxHeight = double.PositiveInfinity;
            grid.Columns.Add(DotColumn("RiskColor", 10));
            grid.Columns.Add(MakeTextColumn(filterField == "user.name" ? "User" : "Host", "Name", new DataGridLength(1.4, DataGridLengthUnitType.Star), bold: true));
            grid.Columns.Add(RiskColumn());
            grid.Columns.Add(MakeTextColumn("Events", "EventsText", new DataGridLength(90)));
            var hc = MakeTextColumn("High", "HighText", new DataGridLength(80)); ColorCol(hc, "#FF7B72"); grid.Columns.Add(hc);
            var cc = MakeTextColumn("Critical", "CriticalText", new DataGridLength(90)); ColorCol(cc, "#F85149"); grid.Columns.Add(cc);
            grid.Columns.Add(MakeTextColumn("Last seen", "LastSeenText", new DataGridLength(130), subtle: true));
            grid.ItemsSource = rows;
            grid.MouseDoubleClick += (_, _) => { if (grid.SelectedItem is SiemEntityStat st) ShowEntityDetail(st.Kind, st.Name); };
            return (grid, rows);
        }

        private UIElement WrapEntityGrid(DataGrid grid, ObservableCollection<SiemEntityStat> rows, string icon, string title, string sub)
        {
            var g = new Grid { Margin = new Thickness(18) };
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.Children.Add(new TextBlock { Text = "Double-click an entity to open its profile (risk, activity, related entities, alerts). Risk = severity-weighted, 0–100.", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 12) });
            var wrap = new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1),
                Child = WrapWithEmptyState(grid, rows, icon, title, sub) };
            Grid.SetRow(wrap, 1); g.Children.Add(wrap);
            return new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Disabled, Content = g };
        }

        private DataGridTemplateColumn RiskColumn()
        {
            var col = new DataGridTemplateColumn { Header = "Risk", Width = new DataGridLength(160) };
            var tmpl = new DataTemplate();
            var dp = new FrameworkElementFactory(typeof(DockPanel));
            // score text
            var score = new FrameworkElementFactory(typeof(TextBlock));
            score.SetBinding(TextBlock.TextProperty, new Binding("RiskText"));
            score.SetBinding(TextBlock.ForegroundProperty, new Binding("RiskColor") { Converter = _hex });
            score.SetValue(TextBlock.FontWeightProperty, FontWeights.Bold);
            score.SetValue(TextBlock.FontSizeProperty, 12.0);
            score.SetValue(TextBlock.WidthProperty, 26.0);
            score.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            score.SetValue(DockPanel.DockProperty, Dock.Left);
            dp.AppendChild(score);
            // bar track
            var track = new FrameworkElementFactory(typeof(Border));
            track.SetValue(Border.HeightProperty, 8.0);
            track.SetValue(Border.BackgroundProperty, Br("BackgroundBrush"));
            track.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            track.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            var fill = new FrameworkElementFactory(typeof(Border));
            fill.SetValue(Border.HeightProperty, 8.0);
            fill.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            fill.SetValue(Border.HorizontalAlignmentProperty, HorizontalAlignment.Left);
            fill.SetBinding(Border.BackgroundProperty, new Binding("RiskColor") { Converter = _hex });
            fill.SetBinding(FrameworkElement.WidthProperty, new Binding("RiskScore") { Converter = new RiskWidthConverter() });
            track.AppendChild(fill);
            dp.AppendChild(track);
            tmpl.VisualTree = dp; col.CellTemplate = tmpl;
            return col;
        }

        /// <summary>Maps a 0–100 risk score to a bar width (px) for the Risk column.</summary>
        private sealed class RiskWidthConverter : System.Windows.Data.IValueConverter
        {
            public object Convert(object value, Type t, object p, System.Globalization.CultureInfo c)
                => value is int s ? Math.Max(2.0, s / 100.0 * 110.0) : 2.0;
            public object ConvertBack(object value, Type t, object p, System.Globalization.CultureInfo c) => throw new NotSupportedException();
        }

        private void RefreshEntities()
        {
            if (_hostRows != null)
            {
                var hosts = SiemEntityRisk.Hosts(_window);
                _hostRows.Clear();
                foreach (var h in hosts) _hostRows.Add(h);
            }
            if (_userRows != null)
            {
                var users = SiemEntityRisk.Users(_window);
                _userRows.Clear();
                foreach (var u in users) _userRows.Add(u);
            }
            RefreshProcessTree();
        }

        // ── Entity profile page (G2 host / G4 user — composed from existing aggregations) ──
        private void CloseEntityDetail()
        {
            if (_entityDetailHost == null || _entitiesInner == null) return;
            _entityDetailHost.Visibility = Visibility.Collapsed;
            _entityDetailHost.Child = null;
            _entitiesInner.Visibility = Visibility.Visible;
        }

        private void ShowEntityDetail(SiemEntityKind kind, string name)
        {
            if (_entityDetailHost == null || _entitiesInner == null || string.IsNullOrWhiteSpace(name)) return;

            bool isHost = kind == SiemEntityKind.Host;
            string field = isHost ? "host" : "user.name";
            string clause = name.Contains(' ') ? $"{field}:\"{name}\"" : $"{field}:{name}";
            var q = SiemQuery.Parse(clause);

            var events = _store.Query(q, _window, 1000);
            var sev = _store.CountBySeverity(q, _window);
            int total = sev.Values.Sum();
            var risk = SiemEntityRisk.Entities(kind, _window).FirstOrDefault(s => string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase));
            var first = events.Count > 0 ? events.Min(e => e.Timestamp) : (DateTime?)null;
            var last = events.Count > 0 ? events.Max(e => e.Timestamp) : (DateTime?)null;

            var root = new StackPanel { Margin = new Thickness(18) };

            // header: back + identity + risk badge
            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 14) };
            var back = new Button { Content = "←  Back", Style = (Style)FindResource("GhostButtonStyle"), Height = 30, Padding = new Thickness(12, 0, 12, 0) };
            back.Click += (_, _) => CloseEntityDetail();
            DockPanel.SetDock(back, Dock.Left); head.Children.Add(back);
            var disc = new Button { Content = "Investigate in Discover", Style = (Style)FindResource("AccentButtonStyle"), Height = 30, Padding = new Thickness(12, 0, 12, 0) };
            disc.Click += (_, _) => { AddFilter(field, name); Tabs.SelectedItem = _searchTab; };
            DockPanel.SetDock(disc, Dock.Right); head.Children.Add(disc);
            var idsp = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };
            idsp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = isHost ? FontAwesome.Sharp.IconChar.Server : FontAwesome.Sharp.IconChar.User, FontSize = 18, Foreground = Br("AccentBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) });
            idsp.Children.Add(new TextBlock { Text = name, FontSize = 19, FontWeight = FontWeights.Bold, Foreground = Br("TextBrush"), VerticalAlignment = VerticalAlignment.Center, FontFamily = new FontFamily("Consolas") });
            idsp.Children.Add(new TextBlock { Text = isHost ? "  host" : "  user", FontSize = 12, Foreground = Br("SubtleTextBrush"), VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(2, 0, 0, 3) });
            head.Children.Add(idsp);
            root.Children.Add(head);

            // KPI strip
            var kpis = new WrapPanel { Margin = new Thickness(0, 0, 0, 4) };
            kpis.Children.Add(DetailKpi("RISK", (risk?.RiskScore ?? 0).ToString(), risk?.RiskColor ?? "#8B949E"));
            kpis.Children.Add(DetailKpi("EVENTS", total.ToString("N0"), "TextBrush"));
            kpis.Children.Add(DetailKpi("CRITICAL", sev[SiemSeverity.Critical].ToString("N0"), "CriticalBrush"));
            kpis.Children.Add(DetailKpi("HIGH", sev[SiemSeverity.High].ToString("N0"), "WarningBrush"));
            kpis.Children.Add(DetailKpi("MEDIUM", sev[SiemSeverity.Medium].ToString("N0"), "AccentBrush"));
            root.Children.Add(kpis);
            root.Children.Add(new TextBlock { Text = first != null ? $"First seen {first:MMM dd, HH:mm}   ·   Last seen {last:MMM dd, HH:mm}" : "No events in the selected range.", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(2, 6, 0, 14) });

            // composition cards
            var cards = new WrapPanel();
            var sevData = new List<(string, int)>
            {
                ("Critical", sev[SiemSeverity.Critical]), ("High", sev[SiemSeverity.High]),
                ("Medium", sev[SiemSeverity.Medium]), ("Low", sev[SiemSeverity.Low]), ("Info", sev[SiemSeverity.Info]),
            };
            cards.Children.Add(DetailCard("Activity by severity", MiniList(sevData.Where(d => d.Item2 > 0).ToList(), null), 230));
            cards.Children.Add(DetailCard("Top categories", MiniList(_store.TopByField("event.category", q, _window, 6), v => { AddFilter("event.category", v); Tabs.SelectedItem = _searchTab; }), 230));
            cards.Children.Add(DetailCard("Top event types", MiniList(_store.TopByField("event.action", q, _window, 6), v => { AddFilter("event.action", v); Tabs.SelectedItem = _searchTab; }), 250));
            // related entities — pivot to the other entity's profile
            if (isHost)
                cards.Children.Add(DetailCard("Top users on this host", MiniList(_store.TopByField("user.name", q, _window, 6), v => ShowEntityDetail(SiemEntityKind.User, v)), 230));
            else
                cards.Children.Add(DetailCard("Top hosts for this user", MiniList(_store.TopByField("host.name", q, _window, 6), v => ShowEntityDetail(SiemEntityKind.Host, v)), 230));
            cards.Children.Add(DetailCard("Top source IPs", MiniList(_store.TopByField("source.ip", q, _window, 6), v => { AddFilter("source.ip", v); Tabs.SelectedItem = _searchTab; }), 230));
            root.Children.Add(cards);

            // alerts involving this entity
            var alertEvents = _store.Query(SiemQuery.Parse($"{clause} event.kind:alert"), _window, 50);
            if (alertEvents.Count > 0)
                root.Children.Add(DetailCard($"Alerts ({alertEvents.Count})", BuildEntityEventGrid(alertEvents, 200), 0));

            // recent events
            root.Children.Add(DetailCard($"Recent events ({events.Count})", BuildEntityEventGrid(events.Take(200).ToList(), 340), 0));

            _entityDetailHost.Child = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = root };
            _entitiesInner.Visibility = Visibility.Collapsed;
            _entityDetailHost.Visibility = Visibility.Visible;
        }

        private Border DetailCard(string title, UIElement body, double minW)
        {
            var sp = new StackPanel();
            sp.Children.Add(new TextBlock { Text = title, FontSize = 12.5, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 10) });
            sp.Children.Add(body);
            var card = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 12, 12), Child = sp };
            if (minW > 0) card.MinWidth = minW;
            return card;
        }

        private Border DetailKpi(string label, string value, string colorKey)
        {
            var sp = new StackPanel();
            var brush = colorKey.StartsWith("#") ? Hex(colorKey) : Br(colorKey);
            sp.Children.Add(new TextBlock { Text = value, FontSize = 24, FontWeight = FontWeights.Bold, Foreground = brush });
            sp.Children.Add(new TextBlock { Text = label, FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush") });
            return new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 10, 0), MinWidth = 92, Child = sp };
        }

        private UIElement MiniList(List<(string key, int count)> data, Action<string>? onClick)
        {
            var sp = new StackPanel();
            if (data.Count == 0) { sp.Children.Add(new TextBlock { Text = "—", Foreground = Br("SubtleTextBrush"), FontSize = 12 }); return sp; }
            foreach (var (key, count) in data)
            {
                var label = string.IsNullOrEmpty(key) ? "(none)" : key;
                var row = new DockPanel { Height = 26, Cursor = onClick != null ? Cursors.Hand : Cursors.Arrow };
                if (onClick != null) row.MouseLeftButtonDown += (_, _) => onClick(label);
                var cnt = new TextBlock { Text = count.ToString("N0"), Foreground = Br("AccentBrush"), FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
                DockPanel.SetDock(cnt, Dock.Right); row.Children.Add(cnt);
                row.Children.Add(new TextBlock { Text = label, Foreground = Br("TextBrush"), FontSize = 12, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, FontFamily = new FontFamily("Consolas") });
                sp.Children.Add(new Border { BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = row });
            }
            return sp;
        }

        private UIElement BuildEntityEventGrid(List<SiemEvent> events, double maxHeight)
        {
            var grid = ThemedGrid(30);
            grid.MaxHeight = maxHeight;
            grid.ItemsSource = events;
            grid.Columns.Add(DotColumn("SeverityColor"));
            grid.Columns.Add(MakeTextColumn("Time", "TimeText", new DataGridLength(150), mono: true));
            grid.Columns.Add(MakeTextColumn("Category", "Category", new DataGridLength(120)));
            grid.Columns.Add(MakeTextColumn("Event", "EventType", new DataGridLength(160), subtle: true));
            grid.Columns.Add(MakeTextColumn("Message", "Message", new DataGridLength(1, DataGridLengthUnitType.Star), subtle: true));
            return new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), Child = grid };
        }

        // ── Security Overview landing (G1 — SOC posture at a glance) ──
        private void BuildSecurityTab() => RefreshSecurity();

        private void RefreshSecurity()
        {
            if (SecurityHost == null) return;
            SecurityHost.Children.Clear();

            var root = new StackPanel();
            root.Children.Add(new TextBlock { Text = "Security overview", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            root.Children.Add(new TextBlock { Text = "SOC posture at a glance — detections, the riskiest entities, and what's happening right now in the selected time range.", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 2, 0, 14), TextWrapping = TextWrapping.Wrap });

            var sev = _store.CountBySeverity(_query, _window);
            int total = sev.Values.Sum();
            var hosts = SiemEntityRisk.Hosts(_window);
            var users = SiemEntityRisk.Users(_window);
            var alerts = _rules.Alerts();
            int meanHostRisk = hosts.Count > 0 ? (int)Math.Round(hosts.Take(20).Average(h => h.RiskScore)) : 0;

            // KPI row
            var kpis = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            kpis.Children.Add(DetailKpi("EVENTS", total.ToString("N0"), "TextBrush"));
            kpis.Children.Add(DetailKpi("CRITICAL", sev[SiemSeverity.Critical].ToString("N0"), "CriticalBrush"));
            kpis.Children.Add(DetailKpi("HIGH", sev[SiemSeverity.High].ToString("N0"), "WarningBrush"));
            kpis.Children.Add(DetailKpi("OPEN ALERTS", _rules.OpenCount().ToString("N0"), "CriticalBrush"));
            kpis.Children.Add(DetailKpi("MEAN HOST RISK", meanHostRisk.ToString(), meanHostRisk >= 50 ? "#FF7B72" : "AccentBrush"));
            kpis.Children.Add(DetailKpi("EVENTS / SEC", _rate.ToString("0.0"), "SuccessBrush"));
            root.Children.Add(kpis);

            // composition cards
            var cards = new WrapPanel();

            var sevData = new List<(string key, int count)>
            {
                ("Critical", sev[SiemSeverity.Critical]), ("High", sev[SiemSeverity.High]),
                ("Medium", sev[SiemSeverity.Medium]), ("Low", sev[SiemSeverity.Low]), ("Info", sev[SiemSeverity.Info]),
            }.Where(d => d.count > 0).ToList();
            cards.Children.Add(DetailCard("Events by severity", sevData.Count > 0 ? BuildDataDonut(sevData, "severity") : EmptyTileText("No events in range"), 300));

            var byRule = alerts.GroupBy(a => a.RuleName).Select(g => (g.Key ?? "(rule)", g.Count()))
                .OrderByDescending(t => t.Item2).Take(7).ToList();
            cards.Children.Add(DetailCard("Top alerts by rule", MiniList(byRule, _ => { Tabs.SelectedItem = AlertsHost.Parent as TabItem; }), 260));

            var byTactic = alerts.Where(a => !string.IsNullOrEmpty(a.MitreTactic)).GroupBy(a => a.MitreTactic)
                .Select(g => (g.Key, g.Count())).OrderByDescending(t => t.Item2).Take(7).ToList();
            cards.Children.Add(DetailCard("MITRE tactics (alerts)", MiniList(byTactic, _ => { Tabs.SelectedItem = AlertsHost.Parent as TabItem; }), 260));

            cards.Children.Add(DetailCard("Highest-risk hosts", MiniList(hosts.Take(6).Select(h => (h.Name, h.RiskScore)).ToList(),
                v => { Tabs.SelectedItem = _entitiesTab; ShowEntityDetail(SiemEntityKind.Host, v); }), 240));
            cards.Children.Add(DetailCard("Highest-risk users", MiniList(users.Take(6).Select(u => (u.Name, u.RiskScore)).ToList(),
                v => { Tabs.SelectedItem = _entitiesTab; ShowEntityDetail(SiemEntityKind.User, v); }), 240));

            cards.Children.Add(DetailCard("Top source IPs", MiniList(_store.TopByField("source.ip", _query, _window, 6),
                v => { AddFilter("source.ip", v); Tabs.SelectedItem = _searchTab; }), 240));
            root.Children.Add(cards);

            // recent high-severity events
            var hi = _store.Query(SiemQuery.Parse("severity:>=high"), _window, 200);
            root.Children.Add(DetailCard($"Recent high & critical events ({hi.Count})", BuildEntityEventGrid(hi, 320), 0));

            SecurityHost.Children.Add(root);
        }

        // ════════════════════════════════════════════════════════════════════
        //  Threat Intel tab — indicator management (G10)
        // ════════════════════════════════════════════════════════════════════
        private void BuildThreatIntelTab()
        {
            _threatTab = ThreatIntelHost.Parent as TabItem;
            ThreatIntelHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            ThreatIntelHost.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // header + add controls
            var head = new StackPanel { Margin = new Thickness(0, 0, 0, 14) };
            head.Children.Add(new TextBlock { Text = "Threat intelligence", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            head.Children.Add(new TextBlock { Text = "Maintain known-bad indicators (IPs, domains, hashes, users). The pipeline's indicator-match tags and escalates any event whose fields hit this list.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, MaxWidth = 760, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 12) });

            var addRow = new DockPanel();
            _tiValueBox = new TextBox { Style = (Style)FindResource("InputBoxStyle"), VerticalAlignment = VerticalAlignment.Center, MinWidth = 240 };
            _tiValueBox.SetValue(System.Windows.Controls.Primitives.TextBoxBase.AcceptsReturnProperty, false);
            _tiTypeBox = new ComboBox { Style = (Style)FindResource("ComboBoxStyle"), Width = 120, Margin = new Thickness(8, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center };
            foreach (var t in new[] { "ip", "domain", "url", "hash", "user", "other" }) _tiTypeBox.Items.Add(t);
            _tiTypeBox.SelectedIndex = 0;
            var addBtn = new Button { Content = "＋ Add indicator", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, Padding = new Thickness(14, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
            addBtn.Click += (_, _) => AddIndicator();
            _tiValueBox.KeyDown += (_, ev) => { if (ev.Key == Key.Enter) AddIndicator(); };
            var matchToggle = new Button { Content = "Enable matching in pipeline", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Padding = new Thickness(12, 0, 12, 0), Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, ToolTip = "Add an indicator-match stage to the pipeline if none exists" };
            matchToggle.Click += (_, _) => EnsureIndicatorMatchStage();
            DockPanel.SetDock(addBtn, Dock.Right); DockPanel.SetDock(matchToggle, Dock.Right);
            DockPanel.SetDock(_tiTypeBox, Dock.Right);
            addRow.Children.Add(matchToggle); addRow.Children.Add(addBtn); addRow.Children.Add(_tiTypeBox); addRow.Children.Add(_tiValueBox);
            head.Children.Add(addRow);
            _tiSummary = new TextBlock { FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 8, 0, 0) };
            head.Children.Add(_tiSummary);
            Grid.SetRow(head, 0); ThreatIntelHost.Children.Add(head);

            // body: indicators (left) + recent matches (right)
            var body = new Grid();
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.3, GridUnitType.Star) });

            _indicatorRows = new ObservableCollection<SiemIndicator>();
            _indicatorGrid = ThemedGrid(34);
            _indicatorGrid.Columns.Add(DotColumn("TypeColor"));
            _indicatorGrid.Columns.Add(MakeTextColumn("Indicator", "Value", new DataGridLength(1.4, DataGridLengthUnitType.Star), bold: true, mono: true));
            _indicatorGrid.Columns.Add(MakeTextColumn("Type", "Type", new DataGridLength(80)));
            _indicatorGrid.Columns.Add(MakeTextColumn("Source", "Source", new DataGridLength(90), subtle: true));
            _indicatorGrid.Columns.Add(MakeTextColumn("Added", "AddedText", new DataGridLength(120), subtle: true));
            _indicatorGrid.ItemsSource = _indicatorRows;
            var indWrapInner = WrapWithEmptyState(_indicatorGrid, _indicatorRows, "Skull", "No indicators yet", "Add an IOC above, or import via config.");
            var delInd = new Button { Content = "Remove selected", Style = (Style)FindResource("GhostButtonStyle"), Height = 28, Margin = new Thickness(0, 8, 0, 0), Padding = new Thickness(10, 0, 10, 0), HorizontalAlignment = HorizontalAlignment.Left };
            delInd.Click += (_, _) => { if (_indicatorGrid?.SelectedItem is SiemIndicator si) { SiemIndicatorStore.Instance.Remove(si); SiemAudit.Instance.Log("Config", "Removed indicator", si.Value); } };
            var indLeft = new Grid { Margin = new Thickness(0, 0, 12, 0) };
            indLeft.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            indLeft.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var indCard = new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), Child = indWrapInner };
            Grid.SetRow(indCard, 0); indLeft.Children.Add(indCard);
            Grid.SetRow(delInd, 1); indLeft.Children.Add(delInd);
            Grid.SetColumn(indLeft, 0); body.Children.Add(indLeft);

            _tiMatchRows = new ObservableCollection<SiemEvent>();
            _tiMatchGrid = ThemedGrid(34);
            _tiMatchGrid.Columns.Add(DotColumn("SeverityColor"));
            _tiMatchGrid.Columns.Add(MakeTextColumn("Time", "TimeText", new DataGridLength(150), mono: true));
            _tiMatchGrid.Columns.Add(BindColumn("Indicator", "threat.indicator", new DataGridLength(1, DataGridLengthUnitType.Star), mono: true));
            _tiMatchGrid.Columns.Add(BindColumn("Field", "threat.indicator.field", new DataGridLength(120), subtle: true));
            _tiMatchGrid.Columns.Add(MakeTextColumn("Host", "Host", new DataGridLength(110)));
            _tiMatchGrid.Columns.Add(MakeTextColumn("Event", "EventType", new DataGridLength(1, DataGridLengthUnitType.Star), subtle: true));
            _tiMatchGrid.ItemsSource = _tiMatchRows;
            var matchCard = new Grid();
            matchCard.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            matchCard.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            matchCard.Children.Add(new TextBlock { Text = "Recent indicator matches", FontSize = 12.5, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 8) });
            var matchWrap = new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1),
                Child = WrapWithEmptyState(_tiMatchGrid, _tiMatchRows, "ShieldHalved", "No matches yet", "Events that hit an indicator (threat.matched) show here.") };
            Grid.SetRow(matchWrap, 1); matchCard.Children.Add(matchWrap);
            Grid.SetColumn(matchCard, 1); body.Children.Add(matchCard);

            Grid.SetRow(body, 1); ThreatIntelHost.Children.Add(body);

            SiemIndicatorStore.Instance.Changed += () => Dispatcher.BeginInvoke(RefreshThreatIntel);
            RefreshThreatIntel();
        }

        private void AddIndicator()
        {
            var v = _tiValueBox?.Text?.Trim() ?? "";
            if (v.Length == 0) return;
            var type = _tiTypeBox?.SelectedItem as string ?? "ip";
            SiemIndicatorStore.Instance.Add(new SiemIndicator { Value = v, Type = type, Source = "manual" });
            SiemAudit.Instance.Log("Config", "Added indicator", $"{v} ({type})");
            if (_tiValueBox != null) _tiValueBox.Text = "";
        }

        /// <summary>Ensure the pipeline has an IndicatorMatch stage so the central list is actually checked.</summary>
        private void EnsureIndicatorMatchStage()
        {
            if (_pipeline.Processors.Any(p => p.Type == SiemProcessorType.IndicatorMatch))
            {
                ShowToastText("Already enabled", "An indicator-match stage is already in the pipeline.");
                return;
            }
            _pipeline.Processors.Add(new SiemProcessor { Type = SiemProcessorType.IndicatorMatch, MatchField = SiemMatchField.Any, MatchValue = "", Field = "", Arg = "" });
            CommitPipeline();
            SiemAudit.Instance.Log("Config", "Enabled indicator matching", "added IndicatorMatch pipeline stage");
            ShowToastText("Matching enabled", "Incoming events are now checked against your indicators.");
        }

        private void RefreshThreatIntel()
        {
            if (_indicatorRows != null)
            {
                _indicatorRows.Clear();
                foreach (var i in SiemIndicatorStore.Instance.All()) _indicatorRows.Add(i);
            }
            if (_tiMatchRows != null)
            {
                _tiMatchRows.Clear();
                foreach (var e in _store.Query(SiemQuery.Parse("threat.matched:true"), _window, 200)) _tiMatchRows.Add(e);
            }
            if (_tiSummary != null)
            {
                bool active = _pipeline.Processors.Any(p => p.Enabled && p.Type == SiemProcessorType.IndicatorMatch);
                _tiSummary.Text = $"{SiemIndicatorStore.Instance.Count:N0} indicator(s).  Pipeline matching: {(active ? "ON" : "OFF — click “Enable matching in pipeline”")}.";
            }
        }

        /// <summary>A grid column bound to an arbitrary SiemEvent field via Get().</summary>
        private DataGridTemplateColumn BindColumn(string header, string field, DataGridLength width, bool mono = false, bool subtle = false)
        {
            var col = new DataGridTemplateColumn { Header = header, Width = width };
            var tmpl = new DataTemplate();
            var tb = new FrameworkElementFactory(typeof(TextBlock));
            tb.SetBinding(TextBlock.TextProperty, new Binding(".") { Converter = _fieldConv, ConverterParameter = field });
            tb.SetValue(TextBlock.ForegroundProperty, subtle ? Br("SubtleTextBrush") : Br("TextBrush"));
            if (mono) tb.SetValue(TextBlock.FontFamilyProperty, new FontFamily("Consolas"));
            tb.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            tb.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
            tmpl.VisualTree = tb; col.CellTemplate = tmpl;
            return col;
        }

        // ════════════════════════════════════════════════════════════════════
        //  Cases tab — SOC case management
        // ════════════════════════════════════════════════════════════════════
        private void BuildCasesTab()
        {
            var grid = new Grid { Margin = new Thickness(18) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };
            var title = new StackPanel();
            title.Children.Add(new TextBlock { Text = "Cases", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            title.Children.Add(new TextBlock { Text = "Track investigations — bundle alerts, add comments, move through Open → In progress → Closed.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, MaxWidth = 680, HorizontalAlignment = HorizontalAlignment.Left });
            head.Children.Add(title);
            var newBtn = new Button { Content = "＋ New case", Style = (Style)FindResource("AccentButtonStyle"), Height = 32, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top };
            newBtn.Click += (_, _) => NewCase();
            DockPanel.SetDock(newBtn, Dock.Right); head.Children.Add(newBtn);
            Grid.SetRow(head, 0); grid.Children.Add(head);

            var body = new Grid();
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(320) });
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            _caseListPanel = new StackPanel();
            var listSv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 14, 0), Content = _caseListPanel };
            Grid.SetColumn(listSv, 0); body.Children.Add(listSv);

            _caseDetailHost = new Border();
            var detailSv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _caseDetailHost };
            Grid.SetColumn(detailSv, 1); body.Children.Add(detailSv);

            Grid.SetRow(body, 1); grid.Children.Add(body);
            CasesHost.Children.Add(grid);

            RenderCases();
        }

        private void RenderCases()
        {
            if (_caseListPanel == null) return;
            _caseListPanel.Children.Clear();
            var cases = SiemCaseStore.All();
            if (cases.Count == 0)
            {
                _caseListPanel.Children.Add(new TextBlock { Text = "No cases yet.\nClick “New case”, or “Add to case” from an alert.", Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4, 8, 4, 0) });
                if (_caseDetailHost != null) _caseDetailHost.Child = CaseEmptyDetail();
                return;
            }
            if (_selectedCase == null || !cases.Contains(_selectedCase)) _selectedCase = cases[0];
            foreach (var c in cases) _caseListPanel.Children.Add(CaseListCard(c));
            RenderCaseDetail();
        }

        private Border CaseListCard(SiemCase c)
        {
            bool sel = ReferenceEquals(c, _selectedCase);
            var card = new Border
            {
                Background = Br("SecondaryBackgroundBrush"), BorderBrush = sel ? Br("AccentBrush") : Br("BorderBrush"),
                BorderThickness = new Thickness(sel ? 2 : 1), CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 10, 12, 10),
                Margin = new Thickness(0, 0, 0, 8), Cursor = Cursors.Hand,
            };
            card.MouseLeftButtonUp += (_, _) => { _selectedCase = c; RenderCases(); };
            var sp = new StackPanel();
            var top = new DockPanel();
            var status = new Border { Background = Hex(c.StatusColor), CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 1, 6, 1), VerticalAlignment = VerticalAlignment.Center };
            status.Child = new TextBlock { Text = c.StatusText.ToUpperInvariant(), Foreground = Brushes.White, FontSize = 9, FontWeight = FontWeights.Bold };
            DockPanel.SetDock(status, Dock.Right); top.Children.Add(status);
            top.Children.Add(new Ellipse { Width = 9, Height = 9, Fill = Hex(c.SeverityColor), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 7, 0) });
            top.Children.Add(new TextBlock { Text = c.Title, Foreground = Br("TextBrush"), FontWeight = FontWeights.SemiBold, FontSize = 13, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center });
            sp.Children.Add(top);
            sp.Children.Add(new TextBlock { Text = c.SummaryLine, Foreground = Br("SubtleTextBrush"), FontSize = 10.5, Margin = new Thickness(0, 5, 0, 0) });
            card.Child = sp;
            return card;
        }

        private UIElement CaseEmptyDetail()
        {
            var sp = new StackPanel { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(20) };
            sp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.Briefcase, FontSize = 34, Foreground = Br("BorderBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            sp.Children.Add(new TextBlock { Text = "Select or create a case", Foreground = Br("SubtleTextBrush"), FontSize = 13, FontWeight = FontWeights.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 10, 0, 0) });
            return sp;
        }

        private void RenderCaseDetail()
        {
            if (_caseDetailHost == null) return;
            var c = _selectedCase;
            if (c == null) { _caseDetailHost.Child = CaseEmptyDetail(); return; }

            var card = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(18) };
            var root = new StackPanel();

            // header: title + actions
            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            DockPanel.SetDock(actions, Dock.Right);
            var editBtn = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Width = 28, Height = 28, Foreground = Br("SubtleTextBrush"), ToolTip = "Edit case" };
            editBtn.Content = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.PenToSquare, FontSize = 13 };
            editBtn.Click += (_, _) => EditCase(c);
            var delBtn = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Width = 28, Height = 28, Foreground = Br("SubtleTextBrush"), ToolTip = "Delete case" };
            delBtn.Content = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.TrashCan, FontSize = 13 };
            delBtn.Click += (_, _) => { SiemCaseStore.Remove(c); _selectedCase = null; RenderCases(); };
            actions.Children.Add(editBtn); actions.Children.Add(delBtn);
            head.Children.Add(actions);
            head.Children.Add(new TextBlock { Text = c.Title, Foreground = Br("TextBrush"), FontWeight = FontWeights.Bold, FontSize = 17, TextWrapping = TextWrapping.Wrap });
            root.Children.Add(head);

            // status pills (clickable) + severity
            var meta = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
            foreach (SiemCaseStatus s in Enum.GetValues(typeof(SiemCaseStatus)))
            {
                var captured = s;
                bool on = c.Status == s;
                var pill = new Button { Style = (Style)FindResource("GhostButtonStyle"), Height = 26, FontSize = 10, Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 0, 10, 0), Content = s == SiemCaseStatus.InProgress ? "In progress" : s.ToString() };
                if (on) { pill.Background = Hex(c.StatusColor); pill.Foreground = Brushes.White; pill.BorderBrush = Hex(c.StatusColor); }
                pill.Click += (_, _) => { c.Status = captured; c.Touch(); SiemCaseStore.Save(); RenderCases(); };
                meta.Children.Add(pill);
            }
            var sevBadge = new Border { Background = Hex(c.SeverityColor), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 3, 8, 3), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            sevBadge.Child = new TextBlock { Text = c.SeverityText.ToUpperInvariant(), Foreground = Brushes.White, FontSize = 9.5, FontWeight = FontWeights.Bold };
            meta.Children.Add(sevBadge);
            root.Children.Add(meta);

            if (!string.IsNullOrWhiteSpace(c.Description))
                root.Children.Add(new TextBlock { Text = c.Description, Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 14) });

            // attached items
            root.Children.Add(SectionLabel($"ATTACHED EVIDENCE ({c.Items.Count})"));
            if (c.Items.Count == 0)
                root.Children.Add(new TextBlock { Text = "Nothing attached yet — use “Add to case” from the Alerts tab.", Foreground = Br("SubtleTextBrush"), FontSize = 11, Margin = new Thickness(0, 0, 0, 12) });
            foreach (var it in c.Items)
            {
                var row = new Border { Background = Br("BackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 0, 0, 6) };
                var dp = new DockPanel();
                var sev = new Border { Background = Hex(SevColorByName(it.Severity)), CornerRadius = new CornerRadius(3), Padding = new Thickness(6, 1, 6, 1), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
                sev.Child = new TextBlock { Text = it.Severity.ToUpperInvariant(), Foreground = Brushes.White, FontSize = 8.5, FontWeight = FontWeights.Bold };
                DockPanel.SetDock(sev, Dock.Left); dp.Children.Add(sev);
                var t = new StackPanel();
                t.Children.Add(new TextBlock { Text = it.RuleName.Length > 0 ? it.RuleName : "Event", Foreground = Br("TextBrush"), FontSize = 12, FontWeight = FontWeights.SemiBold });
                t.Children.Add(new TextBlock { Text = $"{it.TimeText} · {it.Summary}", Foreground = Br("SubtleTextBrush"), FontSize = 10.5, TextTrimming = TextTrimming.CharacterEllipsis });
                dp.Children.Add(t);
                row.Child = dp; root.Children.Add(row);
            }

            // comments
            root.Children.Add(SectionLabel($"COMMENTS ({c.Comments.Count})"));
            foreach (var cm in c.Comments)
            {
                var row = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
                row.Children.Add(new TextBlock { Text = $"{cm.Author} · {cm.TimeText}", Foreground = Br("SubtleTextBrush"), FontSize = 10 });
                row.Children.Add(new TextBlock { Text = cm.Text, Foreground = Br("TextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap });
                root.Children.Add(row);
            }
            var addRow = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
            var commentBox = new TextBox { Style = (Style)FindResource("InputBoxStyle"), VerticalContentAlignment = VerticalAlignment.Center };
            var addCmt = new Button { Content = "Comment", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(8, 0, 0, 0), Padding = new Thickness(12, 0, 12, 0) };
            void DoAdd()
            {
                var txt = commentBox.Text.Trim();
                if (txt.Length == 0) return;
                c.Comments.Add(new SiemCaseComment { Text = txt }); c.Touch(); SiemCaseStore.Save(); RenderCases();
            }
            addCmt.Click += (_, _) => DoAdd();
            commentBox.KeyDown += (_, ev) => { if (ev.Key == Key.Enter) DoAdd(); };
            DockPanel.SetDock(addCmt, Dock.Right); addRow.Children.Add(addCmt); addRow.Children.Add(commentBox);
            root.Children.Add(addRow);

            card.Child = root;
            _caseDetailHost.Child = card;
        }

        private TextBlock SectionLabel(string t) => new()
        { Text = t, FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 6, 0, 8) };

        private static string SevColorByName(string sev) => sev.ToLowerInvariant() switch
        {
            "critical" => "#F85149", "high" => "#FF7B72", "medium" => "#E3B341", "low" => "#58A6FF", _ => "#8B949E",
        };

        private void NewCase()
        {
            var c = new SiemCase { Title = "New case", Severity = SiemSeverity.Medium };
            if (!SiemCaseDialog.Edit(Window.GetWindow(this), c)) return;
            SiemCaseStore.Add(c);
            _selectedCase = c;
            RenderCases();
        }

        private void EditCase(SiemCase c)
        {
            if (!SiemCaseDialog.Edit(Window.GetWindow(this), c)) return;
            c.Touch(); SiemCaseStore.Save(); RenderCases();
        }

        /// <summary>Attach an alert to a case (new or existing) — called from the Alerts tab.</summary>
        private void AddAlertToCase(SiemAlert a)
        {
            var menu = new ContextMenu();
            var cases = SiemCaseStore.All();
            foreach (var c in cases)
            {
                var captured = c;
                var mi = new MenuItem { Header = c.Title };
                mi.Click += (_, _) => { AttachToCase(captured, a); };
                menu.Items.Add(mi);
            }
            if (cases.Count > 0) menu.Items.Add(new Separator());
            var nc = new MenuItem { Header = "New case from this alert…" };
            nc.Click += (_, _) =>
            {
                var c = new SiemCase { Title = a.RuleName, Severity = a.Severity, Description = a.Message };
                if (!SiemCaseDialog.Edit(Window.GetWindow(this), c)) return;
                SiemCaseStore.Add(c); AttachToCase(c, a); _selectedCase = c;
            };
            menu.Items.Add(nc);
            menu.IsOpen = true;
        }

        private void AttachToCase(SiemCase c, SiemAlert a)
        {
            c.Items.Add(new SiemCaseItem { Time = a.Timestamp, Severity = a.SeverityText, RuleName = a.RuleName, Summary = a.Message });
            c.Touch();
            SiemCaseStore.Save();
            RenderCases();
            ShowToastText("Added to case", $"“{a.RuleName}” attached to case “{c.Title}”.");
        }

        // ════════════════════════════════════════════════════════════════════
        //  Timeline tab — investigation workspace (pinned events + notes)
        // ════════════════════════════════════════════════════════════════════
        private void BuildTimelineTab()
        {
            var root = new StackPanel { MaxWidth = 1100, HorizontalAlignment = HorizontalAlignment.Left };
            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            var clear = new Button { Content = "Clear timeline", Style = (Style)FindResource("GhostButtonStyle"), Height = 30, Padding = new Thickness(12, 0, 12, 0), HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top };
            clear.Click += (_, _) => { SiemTimelineStore.Clear(); RenderTimeline(); };
            DockPanel.SetDock(clear, Dock.Right); head.Children.Add(clear);
            var title = new StackPanel();
            title.Children.Add(new TextBlock { Text = "Timeline", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            title.Children.Add(new TextBlock { Text = "Pin events from Discover (expand a document → Pin) or alerts to build a chronological investigation, and annotate each.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, MaxWidth = 760, HorizontalAlignment = HorizontalAlignment.Left });
            head.Children.Add(title);
            root.Children.Add(head);
            _timelineSummary = new TextBlock { Foreground = Br("SubtleTextBrush"), FontSize = 11, Margin = new Thickness(0, 0, 0, 14) };
            root.Children.Add(_timelineSummary);
            _timelinePanel = new StackPanel();
            root.Children.Add(_timelinePanel);
            TimelineHost.Children.Add(root);
            RenderTimeline();
        }

        private void RenderTimeline()
        {
            if (_timelinePanel == null) return;
            _timelinePanel.Children.Clear();
            var entries = SiemTimelineStore.Chronological();
            if (_timelineSummary != null)
                _timelineSummary.Text = entries.Count == 0 ? "Timeline is empty." : $"{entries.Count} pinned event(s), oldest → newest.";
            if (entries.Count == 0)
            {
                _timelinePanel.Children.Add(new TextBlock { Text = "Nothing pinned yet.", Foreground = Br("SubtleTextBrush"), FontSize = 12 });
                return;
            }
            for (int i = 0; i < entries.Count; i++)
                _timelinePanel.Children.Add(TimelineRow(entries[i], i == entries.Count - 1));
        }

        private UIElement TimelineRow(SiemTimelineEntry e, bool last)
        {
            // a left rail (dot + connector line) + a content card
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var rail = new Grid();
            var line = new Rectangle { Width = 2, Fill = Br("BorderBrush"), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Stretch, Margin = new Thickness(0, 6, 0, last ? 0 : -8) };
            if (last) line.Visibility = Visibility.Collapsed;
            rail.Children.Add(line);
            var dot = new Ellipse { Width = 12, Height = 12, Fill = Hex(e.SeverityColor), Stroke = Br("BackgroundBrush"), StrokeThickness = 2, VerticalAlignment = VerticalAlignment.Top, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
            rail.Children.Add(dot);
            Grid.SetColumn(rail, 0); grid.Children.Add(rail);

            var card = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 10, 12, 12), Margin = new Thickness(4, 0, 0, 10) };
            var sp = new StackPanel();
            var top = new DockPanel();
            var rm = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Width = 24, Height = 22, Foreground = Br("SubtleTextBrush"), ToolTip = "Unpin" };
            rm.Content = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.Xmark, FontSize = 11 };
            rm.Click += (_, _) => { SiemTimelineStore.Remove(e); RenderTimeline(); };
            DockPanel.SetDock(rm, Dock.Right); top.Children.Add(rm);
            top.Children.Add(new TextBlock { Text = e.TimeText, Foreground = Br("AccentBrush"), FontSize = 11.5, FontFamily = new FontFamily("Consolas"), FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
            sp.Children.Add(top);
            if (!string.IsNullOrEmpty(e.Label))
                sp.Children.Add(new TextBlock { Text = e.Label, Foreground = Br("TextBrush"), FontSize = 12.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 2, 0, 0), TextWrapping = TextWrapping.Wrap });
            sp.Children.Add(new TextBlock { Text = e.Summary, Foreground = Br("SubtleTextBrush"), FontSize = 11, Margin = new Thickness(0, 2, 0, 8), TextWrapping = TextWrapping.Wrap });
            var note = new TextBox { Style = (Style)FindResource("InputBoxStyle"), Text = e.Note, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 36, VerticalContentAlignment = VerticalAlignment.Top };
            note.LostFocus += (_, _) => { e.Note = note.Text; SiemTimelineStore.Save(); };
            sp.Children.Add(new TextBlock { Text = "NOTE", FontSize = 9, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 3) });
            sp.Children.Add(note);
            card.Child = sp;
            Grid.SetColumn(card, 1); grid.Children.Add(card);
            return grid;
        }

        private void PinToTimeline(SiemEvent ev)
        {
            SiemTimelineStore.Add(new SiemTimelineEntry
            {
                Time = ev.Timestamp,
                Severity = ev.SeverityText,
                Label = string.IsNullOrEmpty(ev.EventType) ? ev.Category : ev.EventType,
                Summary = ev.Summary(),
            });
            RenderTimeline();
            ShowToastText("Pinned to timeline", $"{(string.IsNullOrEmpty(ev.EventType) ? ev.Category : ev.EventType)} added to the investigation timeline.");
        }

        // ════════════════════════════════════════════════════════════════════
        //  Network tab — network-centric analytics (top talkers / IPs / ports)
        // ════════════════════════════════════════════════════════════════════
        private void BuildNetworkTab()
        {
            _networkTab = NetworkHost.Parent is ScrollViewer sv ? sv.Parent as TabItem : null;
            _networkCards.Clear();
            var root = new StackPanel();

            root.Children.Add(new TextBlock { Text = "Network", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            root.Children.Add(new TextBlock { Text = "A source-geography threat map plus top talkers, ports and protocols across events carrying network fields (source.ip, destination.ip, source.geo.*, …).", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 2, 0, 12), TextWrapping = TextWrapping.Wrap });
            _networkKpis = new TextBlock { Foreground = Br("TextBrush"), FontSize = 12.5, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 0, 0, 14) };
            root.Children.Add(_networkKpis);

            // geo threat map (E13) — source countries plotted on an equirectangular projection
            root.Children.Add(new TextBlock { Text = "Source geography", FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 2, 0, 8) });
            root.Children.Add(BuildThreatMap());

            var wrap = new WrapPanel { Orientation = Orientation.Horizontal };
            void Card(string title, string icon, string color, Func<UIElement> build)
            {
                var card = new Border { Width = TileW, Height = TileH, Margin = new Thickness(0, 0, 14, 14), Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10) };
                var grid = new Grid();
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
                var header = new Border { Padding = new Thickness(14, 11, 8, 9), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(0, 0, 0, 1) };
                var hd = new StackPanel { Orientation = Orientation.Horizontal };
                hd.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.ChartBar, FontSize = 12, Foreground = Hex(color), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
                hd.Children.Add(new TextBlock { Text = title.ToUpperInvariant(), FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), VerticalAlignment = VerticalAlignment.Center });
                header.Child = hd; Grid.SetRow(header, 0); grid.Children.Add(header);
                var host = new Border { Padding = new Thickness(14, 10, 14, 12), ClipToBounds = true }; Grid.SetRow(host, 1); grid.Children.Add(host);
                card.Child = grid; wrap.Children.Add(card);
                _networkCards.Add((host, build));
            }

            Card("Top source IPs", "ArrowRightFromBracket", "#58A6FF", () => BuildBars(_store.TopByField("source.ip", _query, _window, 8), "source.ip", "#58A6FF"));
            Card("Top destination IPs", "ArrowRightToBracket", "#56D364", () => BuildBars(_store.TopByField("destination.ip", _query, _window, 8), "destination.ip", "#56D364"));
            Card("Top destination ports", "DoorOpen", "#E3B341", () => BuildDataTable(_store.TopByField("destination.port", _query, _window, 10), "destination.port"));
            Card("Protocols", "ChartPie", "#BC8CFF", () => BuildDataDonut(_store.TopByField("network.protocol", _query, _window, 6), "network.protocol"));
            Card("Top talkers (events)", "Tower-broadcast", "#FF7B72", () => BuildBars(_store.TopByField("source.ip", _query, _window, 8), "source.ip", "#FF7B72"));
            Card("Top countries", "Globe", "#79C0FF", () => BuildBars(_store.TopByField("source.geo.country_iso_code", _query, _window, 8), "source.geo.country_iso_code", "#79C0FF"));

            root.Children.Add(wrap);
            NetworkHost.Children.Add(root);
            RefreshNetwork();
        }

        private Action? _redrawThreatMap;

        /// <summary>E13 geo threat map: top source countries as bubbles (size = count, colour = intensity) on an equirectangular projection.</summary>
        private UIElement BuildThreatMap()
        {
            var canvas = new Canvas { ClipToBounds = true };
            var border = new Border { Height = 340, Background = Hex("#0A0E16"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), ClipToBounds = true, Margin = new Thickness(0, 0, 0, 16), Child = canvas };

            void Draw()
            {
                canvas.Children.Clear();
                double w = canvas.ActualWidth, h = canvas.ActualHeight;
                if (w < 2 || h < 2) return;

                var grat = new SolidColorBrush(Color.FromArgb(34, 88, 166, 255));
                for (int lon = -180; lon <= 180; lon += 30) { var (x, _) = SiemGeoMap.Project(0, lon, w, h); canvas.Children.Add(new System.Windows.Shapes.Line { X1 = x, Y1 = 0, X2 = x, Y2 = h, Stroke = grat, StrokeThickness = 0.5 }); }
                for (int lat = -60; lat <= 60; lat += 30) { var (_, y) = SiemGeoMap.Project(lat, 0, w, h); canvas.Children.Add(new System.Windows.Shapes.Line { X1 = 0, Y1 = y, X2 = w, Y2 = y, Stroke = grat, StrokeThickness = 0.5 }); }

                var data = _store.TopByField("source.geo.country_iso_code", _query, _window, 40).Where(d => !string.IsNullOrEmpty(d.key)).ToList();
                if (data.Count == 0)
                {
                    var t = new TextBlock { Text = "No geo data in range — add a GeoEnrich pipeline stage (or turn on the demo generator).", Foreground = Br("SubtleTextBrush"), FontSize = 12 };
                    Canvas.SetLeft(t, 16); Canvas.SetTop(t, 14); canvas.Children.Add(t);
                    return;
                }
                int max = Math.Max(1, data.Max(d => d.count));
                foreach (var (iso, count) in data)
                {
                    if (!SiemGeoMap.TryGet(iso, out var c)) continue;
                    var (x, y) = SiemGeoMap.Project(c.lat, c.lon, w, h);
                    double r = 5 + 20.0 * Math.Sqrt((double)count / max);
                    var col = (SolidColorBrush)(count >= max * 0.66 ? Hex("#F85149") : count >= max * 0.33 ? Hex("#E3B341") : Hex("#58A6FF"));
                    var dot = new System.Windows.Shapes.Ellipse
                    {
                        Width = r * 2, Height = r * 2, Stroke = col, StrokeThickness = 1.5,
                        Fill = new SolidColorBrush(col.Color) { Opacity = 0.30 }, Cursor = Cursors.Hand,
                        ToolTip = $"{iso}: {count:N0} event(s)",
                    };
                    Canvas.SetLeft(dot, x - r); Canvas.SetTop(dot, y - r);
                    var captured = iso;
                    dot.MouseLeftButtonDown += (_, _) => { AddFilter("source.geo.country_iso_code", captured); Tabs.SelectedItem = _searchTab; };
                    canvas.Children.Add(dot);
                    var lbl = new TextBlock { Text = iso, Foreground = Br("TextBrush"), FontSize = 10, FontWeight = FontWeights.SemiBold, IsHitTestVisible = false };
                    Canvas.SetLeft(lbl, x - 7); Canvas.SetTop(lbl, y - 7); canvas.Children.Add(lbl);
                }
            }
            canvas.SizeChanged += (_, _) => Draw();
            _redrawThreatMap = Draw;
            return border;
        }

        private void RefreshNetwork()
        {
            _redrawThreatMap?.Invoke();
            foreach (var (host, build) in _networkCards) host.Child = build();
            if (_networkKpis != null)
            {
                double bytes = _store.Metric(SiemAgg.Sum, "network.bytes", _query, _window);
                double srcs = _store.Metric(SiemAgg.UniqueCount, "source.ip", _query, _window);
                double dsts = _store.Metric(SiemAgg.UniqueCount, "destination.ip", _query, _window);
                _networkKpis.Text = $"unique source IPs: {srcs:N0}     unique destination IPs: {dsts:N0}     total transferred: {HumanBytes((long)bytes)}";
            }
        }

        // ════════════════════════════════════════════════════════════════════
        //  Index tab — retention / index management (ILM)
        // ════════════════════════════════════════════════════════════════════
        private void BuildIndexTab()
        {
            _indexTab = IndexHost.Parent as TabItem;
            var root = new StackPanel { MaxWidth = 1100, HorizontalAlignment = HorizontalAlignment.Left };

            root.Children.Add(new TextBlock { Text = "Index management", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            root.Children.Add(new TextBlock { Text = "The index is an in-memory ring buffer. Control how much it keeps, age-based retention, and whether it survives a restart.", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 2, 0, 14), TextWrapping = TextWrapping.Wrap });

            // stats card
            var statsCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 14) };
            _indexStats = new TextBlock { Foreground = Br("TextBrush"), FontSize = 12.5, FontFamily = new FontFamily("Consolas"), TextWrapping = TextWrapping.Wrap, LineHeight = 22 };
            statsCard.Child = _indexStats;
            root.Children.Add(statsCard);

            // retention controls
            var retCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 14) };
            var ret = new StackPanel();
            ret.Children.Add(new TextBlock { Text = "Retention", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 10) });
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            StackPanel Field(string label, out TextBox box, string val)
            {
                var sp = new StackPanel { Margin = new Thickness(0, 0, 12, 0) };
                sp.Children.Add(new TextBlock { Text = label, FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 4) });
                box = new TextBox { Style = (Style)FindResource("InputBoxStyle"), Text = val };
                sp.Children.Add(box);
                return sp;
            }
            var capSp = Field("MAX EVENTS (capacity)", out var capBox, _indexSettings.Capacity.ToString()); _capBox = capBox;
            Grid.SetColumn(capSp, 0); grid.Children.Add(capSp);
            var ageSp = Field("MAX AGE (minutes, 0 = forever)", out var ageBox, _indexSettings.MaxAgeMinutes.ToString()); _ageBox = ageBox;
            Grid.SetColumn(ageSp, 1); grid.Children.Add(ageSp);
            var persistSp = new StackPanel();
            persistSp.Children.Add(new TextBlock { Text = "PERSIST TO DISK", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 8) });
            _persistChip = new ToggleButton { Style = (Style)FindResource("ToggleSwitchStyle"), IsChecked = _indexSettings.PersistToDisk, HorizontalAlignment = HorizontalAlignment.Left };
            persistSp.Children.Add(_persistChip);
            Grid.SetColumn(persistSp, 2); grid.Children.Add(persistSp);
            ret.Children.Add(grid);
            var applyBtn = new Button { Content = "Apply retention", Style = (Style)FindResource("AccentButtonStyle"), Height = 32, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 14, 0, 0), Padding = new Thickness(16, 0, 16, 0) };
            applyBtn.Click += (_, _) => ApplyRetention();
            ret.Children.Add(applyBtn);
            retCard.Child = ret;
            root.Children.Add(retCard);

            // per-source breakdown
            var srcCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 14) };
            var srcSp = new Grid();
            srcSp.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            srcSp.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            srcSp.Children.Add(new TextBlock { Text = "Documents per source", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 10) });
            _indexSrcRows = new ObservableCollection<SiemSourceStat>();
            _indexSrcGrid = ThemedGrid(34);
            _indexSrcGrid.MaxHeight = 320;
            _indexSrcGrid.Columns.Add(MakeTextColumn("Source / Host", "Host", new DataGridLength(1.4, DataGridLengthUnitType.Star), bold: true));
            _indexSrcGrid.Columns.Add(MakeTextColumn("Documents", "EventsText", new DataGridLength(120)));
            var hc = MakeTextColumn("High", "HighText", new DataGridLength(90)); ColorCol(hc, "#FF7B72"); _indexSrcGrid.Columns.Add(hc);
            var cc = MakeTextColumn("Critical", "CriticalText", new DataGridLength(100)); ColorCol(cc, "#F85149"); _indexSrcGrid.Columns.Add(cc);
            _indexSrcGrid.Columns.Add(MakeTextColumn("Last seen", "LastSeenText", new DataGridLength(140), subtle: true));
            _indexSrcGrid.ItemsSource = _indexSrcRows;
            var srcWrap = new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), MinHeight = 80,
                Child = WrapWithEmptyState(_indexSrcGrid, _indexSrcRows, "Database", "Index is empty", "Events appear here once sources start reporting.") };
            Grid.SetRow(srcWrap, 1); srcSp.Children.Add(srcWrap);
            srcCard.Child = srcSp;
            root.Children.Add(srcCard);

            // saved objects (config export / import)
            var soCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 14) };
            var so = new StackPanel();
            so.Children.Add(new TextBlock { Text = "Saved objects", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 4) });
            so.Children.Add(new TextBlock { Text = "Back up or share your SIEM configuration — detection rules, saved searches, dashboards, pipeline and retention settings — as one JSON file.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
            var soBtns = new StackPanel { Orientation = Orientation.Horizontal };
            var exp = new Button { Content = "Export config", Style = (Style)FindResource("AccentButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(14, 0, 14, 0) };
            exp.Click += (_, _) => ExportSavedObjects();
            var imp = new Button { Content = "Import config", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(14, 0, 14, 0) };
            imp.Click += (_, _) => ImportSavedObjects();
            var snap = new Button { Content = "Snapshot index", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(14, 0, 14, 0), ToolTip = "Save the current events to a snapshot file" };
            snap.Click += (_, _) => SnapshotIndex();
            var restore = new Button { Content = "Restore", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Padding = new Thickness(14, 0, 14, 0), ToolTip = "Load events from a snapshot file into the index" };
            restore.Click += (_, _) => RestoreIndex();
            soBtns.Children.Add(exp); soBtns.Children.Add(imp); soBtns.Children.Add(snap); soBtns.Children.Add(restore);
            so.Children.Add(soBtns);
            soCard.Child = so;
            root.Children.Add(soCard);

            // runtime fields (B12 — fields computed at read time from a template)
            var rfCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 14) };
            var rf = new StackPanel();
            rf.Children.Add(new TextBlock { Text = "Runtime fields", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 4) });
            rf.Children.Add(new TextBlock { Text = "Computed fields built from a template that interpolates other fields with {field.name}. Evaluated at read time — instantly queryable in Discover and usable as a column.  e.g.  user.session = {user.name}@{host.name}", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
            var rfAdd = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            var rfName = new TextBox { Style = (Style)FindResource("InputBoxStyle"), VerticalAlignment = VerticalAlignment.Center, Width = 200, Margin = new Thickness(0, 0, 8, 0) };
            rfName.SetValue(System.Windows.Controls.Primitives.TextBoxBase.AcceptsReturnProperty, false);
            var rfTpl = new TextBox { Style = (Style)FindResource("InputBoxStyle"), VerticalAlignment = VerticalAlignment.Center };
            rfTpl.SetValue(System.Windows.Controls.Primitives.TextBoxBase.AcceptsReturnProperty, false);
            var rfAddBtn = new Button { Content = "＋ Add field", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, Padding = new Thickness(14, 0, 14, 0), Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(rfAddBtn, Dock.Right); DockPanel.SetDock(rfName, Dock.Left);
            rfAdd.Children.Add(rfAddBtn); rfAdd.Children.Add(rfName); rfAdd.Children.Add(rfTpl);
            rf.Children.Add(rfAdd);
            var rfRows = new ObservableCollection<SiemRuntimeField>();
            var rfGrid = ThemedGrid(32);
            rfGrid.MaxHeight = 240;
            rfGrid.Columns.Add(MakeTextColumn("Field", "Name", new DataGridLength(1, DataGridLengthUnitType.Star), bold: true, mono: true));
            rfGrid.Columns.Add(MakeTextColumn("Template", "Template", new DataGridLength(1.7, DataGridLengthUnitType.Star), mono: true));
            rfGrid.ItemsSource = rfRows;
            var rfWrap = new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), MinHeight = 60,
                Child = WrapWithEmptyState(rfGrid, rfRows, "Code", "No runtime fields", "Add one above to compute a field from others.") };
            rf.Children.Add(rfWrap);
            var rfDel = new Button { Content = "Remove selected", Style = (Style)FindResource("GhostButtonStyle"), Height = 28, Margin = new Thickness(0, 8, 0, 0), Padding = new Thickness(10, 0, 10, 0), HorizontalAlignment = HorizontalAlignment.Left };
            rf.Children.Add(rfDel);
            rfCard.Child = rf;
            root.Children.Add(rfCard);

            void RefreshRf() { rfRows.Clear(); foreach (var f in SiemRuntimeFieldStore.Instance.All()) rfRows.Add(f); }
            void AddRf()
            {
                var n = rfName.Text.Trim(); var t = rfTpl.Text.Trim();
                if (n.Length == 0 || t.Length == 0) return;
                SiemRuntimeFieldStore.Instance.AddOrUpdate(new SiemRuntimeField { Name = n, Template = t });
                SiemAudit.Instance.Log("Config", "Added runtime field", $"{n} = {t}");
                rfName.Text = ""; rfTpl.Text = "";
            }
            rfAddBtn.Click += (_, _) => AddRf();
            rfName.KeyDown += (_, ev) => { if (ev.Key == Key.Enter) AddRf(); };
            rfTpl.KeyDown += (_, ev) => { if (ev.Key == Key.Enter) AddRf(); };
            rfDel.Click += (_, _) => { if (rfGrid.SelectedItem is SiemRuntimeField sf) { SiemRuntimeFieldStore.Instance.Remove(sf); SiemAudit.Instance.Log("Config", "Removed runtime field", sf.Name); } };
            SiemRuntimeFieldStore.Instance.Changed += () => Dispatcher.BeginInvoke((Action)RefreshRf);
            RefreshRf();

            // field mappings (B11 — pin a field's type, overriding inference)
            var fmCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 14) };
            var fm = new StackPanel();
            fm.Children.Add(new TextBlock { Text = "Field mappings", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush"), Margin = new Thickness(0, 0, 0, 4) });
            fm.Children.Add(new TextBlock { Text = "Pin a field to a specific type (keyword / text / number / ip / date / boolean / geo), overriding the automatic inference used for field icons, Visualize and value handling.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
            var fmAdd = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            var fmName = new TextBox { Style = (Style)FindResource("InputBoxStyle"), VerticalAlignment = VerticalAlignment.Center, Width = 240, Margin = new Thickness(0, 0, 8, 0) };
            fmName.SetValue(System.Windows.Controls.Primitives.TextBoxBase.AcceptsReturnProperty, false);
            var fmType = new ComboBox { Style = (Style)FindResource("ComboBoxStyle"), Width = 130, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            foreach (SiemFieldType t in Enum.GetValues(typeof(SiemFieldType))) fmType.Items.Add(t);
            fmType.SelectedIndex = 0;
            var fmAddBtn = new Button { Content = "＋ Set mapping", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, Padding = new Thickness(14, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(fmAddBtn, Dock.Right); DockPanel.SetDock(fmType, Dock.Right);
            fmAdd.Children.Add(fmAddBtn); fmAdd.Children.Add(fmType); fmAdd.Children.Add(fmName);
            fm.Children.Add(fmAdd);
            var fmRows = new ObservableCollection<KeyValuePair<string, SiemFieldType>>();
            var fmGrid = ThemedGrid(32);
            fmGrid.MaxHeight = 220;
            fmGrid.Columns.Add(MakeTextColumn("Field", "Key", new DataGridLength(1.6, DataGridLengthUnitType.Star), bold: true, mono: true));
            fmGrid.Columns.Add(MakeTextColumn("Type", "Value", new DataGridLength(1, DataGridLengthUnitType.Star)));
            fmGrid.ItemsSource = fmRows;
            var fmWrap = new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), MinHeight = 60,
                Child = WrapWithEmptyState(fmGrid, fmRows, "Tags", "No pinned mappings", "Fields use automatic type inference until you pin one here.") };
            fm.Children.Add(fmWrap);
            var fmDel = new Button { Content = "Remove selected", Style = (Style)FindResource("GhostButtonStyle"), Height = 28, Margin = new Thickness(0, 8, 0, 0), Padding = new Thickness(10, 0, 10, 0), HorizontalAlignment = HorizontalAlignment.Left };
            fm.Children.Add(fmDel);
            fmCard.Child = fm;
            root.Children.Add(fmCard);

            void RefreshFm() { fmRows.Clear(); foreach (var kv in SiemFieldMappingStore.Instance.All()) fmRows.Add(kv); }
            void AddFm()
            {
                var n = fmName.Text.Trim();
                if (n.Length == 0) return;
                var t = (SiemFieldType)fmType.SelectedItem;
                SiemFieldMappingStore.Instance.Set(n, t);
                SiemAudit.Instance.Log("Config", "Set field mapping", $"{n} → {t}");
                fmName.Text = "";
            }
            fmAddBtn.Click += (_, _) => AddFm();
            fmName.KeyDown += (_, ev) => { if (ev.Key == Key.Enter) AddFm(); };
            fmDel.Click += (_, _) => { if (fmGrid.SelectedItem is KeyValuePair<string, SiemFieldType> sel) { SiemFieldMappingStore.Instance.Remove(sel.Key); SiemAudit.Instance.Log("Config", "Removed field mapping", sel.Key); } };
            SiemFieldMappingStore.Instance.Changed += () => Dispatcher.BeginInvoke((Action)RefreshFm);
            RefreshFm();

            // audit log
            var auditCard = new Border { Style = (Style)FindResource("CardStyle"), Margin = new Thickness(0, 0, 0, 14) };
            var au = new Grid();
            au.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            au.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var auBar = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            var auTitle = new StackPanel();
            auTitle.Children.Add(new TextBlock { Text = "Audit log", FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            auTitle.Children.Add(new TextBlock { Text = "Who changed what — rule edits, alert triage, retention, deletes, config import/export. Append-only, mirrored to disk.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, MaxWidth = 720, HorizontalAlignment = HorizontalAlignment.Left });
            auBar.Children.Add(auTitle);
            var auBtns = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top };
            DockPanel.SetDock(auBtns, Dock.Right);
            var auExp = new Button { Content = "Export", Style = (Style)FindResource("GhostButtonStyle"), Height = 30, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(12, 0, 12, 0) };
            auExp.Click += (_, _) => ExportAudit();
            var auClr = new Button { Content = "Clear", Style = (Style)FindResource("GhostButtonStyle"), Height = 30, Padding = new Thickness(12, 0, 12, 0) };
            auClr.Click += (_, _) => { SiemAudit.Instance.Clear(); SiemAudit.Instance.Log("Config", "Cleared audit log"); RefreshAudit(); };
            auBtns.Children.Add(auExp); auBtns.Children.Add(auClr);
            auBar.Children.Add(auBtns);
            Grid.SetRow(auBar, 0); au.Children.Add(auBar);
            _auditRows = new ObservableCollection<SiemAuditEntry>();
            _auditGrid = ThemedGrid(32);
            _auditGrid.MaxHeight = 340;
            _auditGrid.Columns.Add(MakeTextColumn("Time", "TimeText", new DataGridLength(150), mono: true));
            _auditGrid.Columns.Add(DotColumn("CategoryColor"));
            _auditGrid.Columns.Add(MakeTextColumn("Area", "Category", new DataGridLength(110)));
            _auditGrid.Columns.Add(MakeTextColumn("User", "User", new DataGridLength(120), subtle: true));
            _auditGrid.Columns.Add(MakeTextColumn("Action", "Action", new DataGridLength(1.1, DataGridLengthUnitType.Star), bold: true));
            _auditGrid.Columns.Add(MakeTextColumn("Detail", "Detail", new DataGridLength(1.6, DataGridLengthUnitType.Star), subtle: true));
            _auditGrid.ItemsSource = _auditRows;
            var auWrap = new Border { CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), MinHeight = 80,
                Child = WrapWithEmptyState(_auditGrid, _auditRows, "ClipboardList", "No audit entries yet", "Configuration and triage actions are recorded here.") };
            Grid.SetRow(auWrap, 1); au.Children.Add(auWrap);
            auditCard.Child = au;
            root.Children.Add(auditCard);

            // danger zone
            var dz = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("CriticalBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(16) };
            var dsp = new StackPanel();
            dsp.Children.Add(new TextBlock { Text = "Danger zone", FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Br("CriticalBrush"), Margin = new Thickness(0, 0, 0, 8) });
            var dbtns = new StackPanel { Orientation = Orientation.Horizontal };
            var delQ = new Button { Content = "Delete matching current search", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(14, 0, 14, 0) };
            delQ.Click += (_, _) => DeleteByQuery();
            var clearAll = new Button { Content = "Clear entire index", Style = (Style)FindResource("DangerButtonStyle"), Height = 32, Padding = new Thickness(14, 0, 14, 0) };
            clearAll.Click += (_, _) => { if (!AllowedTo("DeleteEvents", "clear the index")) return; var n = _store.Count; _store.Clear(); SiemPersistence.SaveNow(); SiemAudit.Instance.Log("Index", "Cleared entire index", $"{n:N0} documents"); RefreshIndex(); RefreshAll(); };
            dbtns.Children.Add(delQ); dbtns.Children.Add(clearAll);
            dsp.Children.Add(dbtns);
            dsp.Children.Add(new TextBlock { Text = "“Delete matching” uses the current search box + time range. These actions cannot be undone.", FontSize = 10, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 8, 0, 0), TextWrapping = TextWrapping.Wrap });
            dz.Child = dsp;
            root.Children.Add(dz);

            IndexHost.Children.Add(root);
            RefreshIndex();
        }

        private void RefreshIndex()
        {
            if (_indexStats != null)
            {
                int count = _store.Count;
                double pct = _store.Capacity > 0 ? count * 100.0 / _store.Capacity : 0;
                string size = HumanBytes(_store.ApproxBytes());
                string oldest = _store.Oldest()?.ToString("MMM dd, HH:mm:ss") ?? "—";
                string newest = _store.Newest()?.ToString("MMM dd, HH:mm:ss") ?? "—";
                string persist = SiemPersistence.Enabled ? $"on  ·  file {HumanBytes(SiemPersistence.FileSize())}" : "off";
                string age = _store.MaxAge > TimeSpan.Zero ? $"{_store.MaxAge.TotalMinutes:0}m" : "forever";
                _indexStats.Text =
                    $"Documents:   {count:N0}  /  {_store.Capacity:N0}  ({pct:0.0}% full)\n" +
                    $"Index size:  ~{size}   (in memory)\n" +
                    $"Ingested:    {_store.TotalIngested:N0} total   ·   Dropped by pipeline: {_store.TotalDropped:N0}\n" +
                    $"Time span:   {oldest}  →  {newest}\n" +
                    $"Retention:   keep {age}   ·   persist to disk: {persist}";
            }
            if (_indexSrcRows != null)
            {
                var stats = _store.SourceStats(null);
                _indexSrcRows.Clear();
                foreach (var s in stats) _indexSrcRows.Add(s);
            }
            RefreshAudit();
        }

        private void RefreshAudit()
        {
            if (_auditRows == null) return;
            _auditRows.Clear();
            foreach (var a in SiemAudit.Instance.Recent(1000)) _auditRows.Add(a);
        }

        private void ExportAudit()
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "CSV (*.csv)|*.csv|All files (*.*)|*.*",
                FileName = $"privacore-siem-audit-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
                Title = "Export audit log",
            };
            if (dlg.ShowDialog() != true) return;
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("time,user,area,action,detail");
            static string Q(string s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
            foreach (var a in SiemAudit.Instance.Recent(100000))
                sb.AppendLine($"{Q(a.Time.ToString("yyyy-MM-dd HH:mm:ss"))},{Q(a.User)},{Q(a.Category)},{Q(a.Action)},{Q(a.Detail)}");
            try { System.IO.File.WriteAllText(dlg.FileName, sb.ToString()); } catch { }
        }

        private void ApplyRetention()
        {
            if (!AllowedTo("ManageRetention", "change retention")) return;
            if (int.TryParse(_capBox?.Text.Trim(), out var cap) && cap > 0) _indexSettings.Capacity = Math.Clamp(cap, 100, 5_000_000);
            if (int.TryParse(_ageBox?.Text.Trim(), out var age) && age >= 0) _indexSettings.MaxAgeMinutes = age;
            _indexSettings.PersistToDisk = _persistChip?.IsChecked == true;
            _indexSettings.Save();

            _store.Capacity = _indexSettings.Capacity;
            _store.MaxAge = _indexSettings.MaxAgeMinutes > 0 ? TimeSpan.FromMinutes(_indexSettings.MaxAgeMinutes) : TimeSpan.Zero;
            SiemPersistence.SetEnabled(_indexSettings.PersistToDisk);
            _store.PurgeExpired();
            SiemAudit.Instance.Log("Index", "Applied retention", $"cap {_indexSettings.Capacity:N0}, max-age {_indexSettings.MaxAgeMinutes}m, persist {(_indexSettings.PersistToDisk ? "on" : "off")}");
            RefreshIndex();
            RefreshAll();
        }

        // ── RBAC gate ─────────────────────────────────────────────────────────
        /// <summary>
        /// Optional permission gate set by the console after sign-in. It maps a permission key to the
        /// signed-in role. Left null in the standalone SIEM module app (which links this page but has
        /// no console session), so the local operator keeps full control there.
        /// </summary>
        public static Func<string, bool>? PermissionGate;

        private bool AllowedTo(string permissionKey, string action)
        {
            if (PermissionGate == null || PermissionGate(permissionKey)) return true;
            ShowToastText("Not permitted", $"Your role can't {action}.");
            return false;
        }

        private void DeleteByQuery()
        {
            if (!AllowedTo("DeleteEvents", "delete events")) return;
            int removed = _store.DeleteMatching(_query, _window);
            SiemAudit.Instance.Log("Index", "Delete-by-query", $"{removed:N0} document(s) matching the current search");
            SiemPersistence.SaveNow();
            RefreshIndex();
            RefreshAll();
            if (_indexStats != null && removed >= 0)
                _indexStats.Text = $"Deleted {removed:N0} document(s) matching the current search.\n" + _indexStats.Text;
        }

        private void SnapshotIndex()
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "SIEM snapshot (*.ndjson.gz)|*.ndjson.gz|All files (*.*)|*.*",
                FileName = $"privacore-siem-snapshot-{DateTime.Now:yyyyMMdd-HHmmss}.ndjson.gz",
                Title = "Snapshot index to file",
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                int n = SiemPersistence.SnapshotTo(dlg.FileName);
                SiemAudit.Instance.Log("Index", "Snapshot index", $"{n:N0} events → {System.IO.Path.GetFileName(dlg.FileName)}");
                ShowToastText("Snapshot saved", $"{n:N0} event(s) written to {System.IO.Path.GetFileName(dlg.FileName)}.");
            }
            catch (Exception ex) { MessageBox.Show(Window.GetWindow(this), ex.Message, "Snapshot failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }

        private void RestoreIndex()
        {
            if (!AllowedTo("ManageRetention", "restore snapshots")) return;
            var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "SIEM snapshot (*.ndjson.gz)|*.ndjson.gz|All files (*.*)|*.*", Title = "Restore index from snapshot" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                int n = SiemPersistence.RestoreFrom(dlg.FileName);
                SiemAudit.Instance.Log("Index", "Restored snapshot", $"{n:N0} events ← {System.IO.Path.GetFileName(dlg.FileName)}");
                RefreshIndex(); RefreshAll();
                ShowToastText("Snapshot restored", $"{n:N0} event(s) loaded into the index.");
            }
            catch (Exception ex) { MessageBox.Show(Window.GetWindow(this), ex.Message, "Restore failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }

        private void ExportSavedObjects()
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "SIEM config (*.json)|*.json|All files (*.*)|*.*",
                FileName = $"privacore-siem-config-{DateTime.Now:yyyyMMdd-HHmmss}.json",
                Title = "Export SIEM configuration",
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                System.IO.File.WriteAllText(dlg.FileName, SiemSavedObjects.ExportJson());
                SiemAudit.Instance.Log("Config", "Exported configuration", System.IO.Path.GetFileName(dlg.FileName));
                ShowToastText("Exported", $"SIEM configuration written to {System.IO.Path.GetFileName(dlg.FileName)}.");
            }
            catch (Exception ex) { MessageBox.Show(Window.GetWindow(this), ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }

        private void ImportSavedObjects()
        {
            if (!AllowedTo("ImportExportConfig", "import configuration")) return;
            var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "SIEM config (*.json)|*.json|All files (*.*)|*.*", Title = "Import SIEM configuration" };
            if (dlg.ShowDialog() != true) return;
            if (MessageBox.Show(Window.GetWindow(this), "This replaces the current rules, saved searches, dashboards, pipeline and settings. Continue?",
                    "Import configuration", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
            try
            {
                var summary = SiemSavedObjects.ImportJson(System.IO.File.ReadAllText(dlg.FileName));
                SiemAudit.Instance.Log("Config", "Imported configuration", System.IO.Path.GetFileName(dlg.FileName));
                // live-reload what we can
                _pipelineSet = SiemPipelineSetStore.Load(); _pipeline = _pipelineSet.Main(); _store.Pipeline = _pipelineSet.Main(); RebuildPipelineSelector(); RenderPipeline();
                RenderRules();
                _indexSettings = SiemIndexSettings.Load();
                RefreshIndex(); RefreshAll();
                ShowToastText("Imported", summary + "  Dashboards & saved searches load on next open.");
            }
            catch (Exception ex) { MessageBox.Show(Window.GetWindow(this), ex.Message, "Import failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }

        private static string HumanBytes(long n)
        {
            string[] u = { "B", "KB", "MB", "GB" };
            double d = n; int i = 0;
            while (d >= 1024 && i < u.Length - 1) { d /= 1024; i++; }
            return $"{d:0.#} {u[i]}";
        }

        // ════════════════════════════════════════════════════════════════════
        //  Alerts tab — detection rules + triggered alerts (correlation layer)
        // ════════════════════════════════════════════════════════════════════
        private void BuildAlertsTab()
        {
            _alertsTab = AlertsHost.Parent as TabItem;

            var inner = new TabControl { Style = (Style)FindResource("TabControlStyle"), Background = Br("BackgroundBrush"), Padding = new Thickness(0) };

            // ── Active alerts ──
            var alertsItem = new TabItem { Style = (Style)FindResource("TabItemStyle") };
            alertsItem.Header = TabHeader("TriangleExclamation", "Active alerts");
            var aGrid = new Grid { Margin = new Thickness(18) };
            aGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            aGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var aBar = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };
            _alertsSummary = new TextBlock { Foreground = Br("TextBrush"), FontSize = 14, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
            aBar.Children.Add(_alertsSummary);
            var aTools = new StackPanel { Orientation = Orientation.Horizontal };
            DockPanel.SetDock(aTools, Dock.Right);
            _alertFilter = new ComboBox { Style = (Style)FindResource("ComboBoxStyle"), Width = 130, Height = 32, Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center, ToolTip = "Filter alerts by triage status" };
            foreach (var f in new[] { "All", "Open", "Acknowledged", "Closed", "Assigned to me" }) _alertFilter.Items.Add(f);
            _alertFilter.SelectedIndex = 0;
            _alertFilter.SelectionChanged += (_, _) => RefreshAlerts();
            var ackBtn = ToolbarButton("Check", "Acknowledge", "Acknowledge the selected alert");
            ackBtn.Click += (_, _) => { if (_alertGrid?.SelectedItem is SiemAlert a) { a.Status = SiemAlertStatus.Acknowledged; SiemAudit.Instance.Log("Alert", "Acknowledged alert", a.RuleName); RefreshAlerts(); } };
            var assignBtn = ToolbarButton("UserCheck", "Assign to me", "Assign the selected alert to you");
            assignBtn.Click += (_, _) => { if (_alertGrid?.SelectedItem is SiemAlert a) { a.Assignee = Environment.UserName; a.Status = a.Status == SiemAlertStatus.Open ? SiemAlertStatus.Acknowledged : a.Status; SiemAudit.Instance.Log("Alert", "Assigned alert to self", a.RuleName); RefreshAlerts(); } };
            var closeBtn = ToolbarButton("Xmark", "Close", "Close the selected alert");
            closeBtn.Click += (_, _) => { if (_alertGrid?.SelectedItem is SiemAlert a) { a.Status = SiemAlertStatus.Closed; SiemAudit.Instance.Log("Alert", "Closed alert", a.RuleName); RefreshAlerts(); } };
            var caseBtn = ToolbarButton("Briefcase", "Add to case", "Attach the selected alert to a case");
            caseBtn.Click += (_, _) => { if (_alertGrid?.SelectedItem is SiemAlert a) AddAlertToCase(a); };
            var clearBtn = ToolbarButton("TrashCan", "Clear closed", "Remove all closed alerts");
            clearBtn.Click += (_, _) => _rules.ClearClosed();
            aTools.Children.Add(_alertFilter); aTools.Children.Add(ackBtn); aTools.Children.Add(assignBtn); aTools.Children.Add(closeBtn); aTools.Children.Add(caseBtn); aTools.Children.Add(clearBtn);
            aBar.Children.Add(aTools);
            Grid.SetRow(aBar, 0); aGrid.Children.Add(aBar);

            _alertRows = new ObservableCollection<SiemAlert>();
            _alertGrid = BuildAlertGrid();
            _alertGrid.ItemsSource = _alertRows;
            var aWrap = new Border
            {
                CornerRadius = new CornerRadius(8), ClipToBounds = true, BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1),
                Child = WrapWithEmptyState(_alertGrid, _alertRows, "ShieldHalved", "No alerts", "When a detection rule trips it appears here. Add rules under the Rules tab."),
            };
            Grid.SetRow(aWrap, 1); aGrid.Children.Add(aWrap);
            alertsItem.Content = aGrid;
            inner.Items.Add(alertsItem);

            // ── Detection rules ──
            var rulesItem = new TabItem { Style = (Style)FindResource("TabItemStyle") };
            rulesItem.Header = TabHeader("ListCheck", "Rules");
            var rGrid = new Grid { Margin = new Thickness(18) };
            rGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var rBar = new DockPanel { Margin = new Thickness(0, 0, 0, 14) };
            var rTitle = new StackPanel();
            rTitle.Children.Add(new TextBlock { Text = "Detection rules", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            rTitle.Children.Add(new TextBlock { Text = "Each rule is a saved query + threshold over a time window. The engine evaluates them continuously and raises alerts.", FontSize = 11, Foreground = Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, MaxWidth = 680, HorizontalAlignment = HorizontalAlignment.Left });
            rBar.Children.Add(rTitle);
            var rRight = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top };
            DockPanel.SetDock(rRight, Dock.Right);
            var libBtn = new Button { Content = "Add from library", Style = (Style)FindResource("GhostButtonStyle"), Height = 32, Margin = new Thickness(0, 0, 8, 0) };
            libBtn.Click += (_, _) => AddFromLibrary();
            var newRuleBtn = new Button { Content = "＋ New rule", Style = (Style)FindResource("AccentButtonStyle"), Height = 32 };
            newRuleBtn.Click += (_, _) => NewRule();
            rRight.Children.Add(libBtn); rRight.Children.Add(newRuleBtn);
            rBar.Children.Add(rRight);
            Grid.SetRow(rBar, 0); rGrid.Children.Add(rBar);

            _rulesList = new ItemsControl();
            var rsv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _rulesList };
            Grid.SetRow(rsv, 1); rGrid.Children.Add(rsv);
            rulesItem.Content = rGrid;
            inner.Items.Add(rulesItem);

            // ── MITRE ATT&CK coverage ──
            var attackItem = new TabItem { Style = (Style)FindResource("TabItemStyle") };
            attackItem.Header = TabHeader("Sitemap", "ATT&CK coverage");
            var cGrid = new Grid { Margin = new Thickness(18) };
            cGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            cGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            var cHead = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
            cHead.Children.Add(new TextBlock { Text = "MITRE ATT&CK coverage", FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Br("TextBrush") });
            _coverageSummary = new TextBlock { Text = "", FontSize = 11, Foreground = Br("SubtleTextBrush"), Margin = new Thickness(0, 2, 0, 0) };
            cHead.Children.Add(_coverageSummary);
            Grid.SetRow(cHead, 0); cGrid.Children.Add(cHead);
            _coverageHost = new Border();
            var csv = new ScrollViewer { HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _coverageHost };
            Grid.SetRow(csv, 1); cGrid.Children.Add(csv);
            attackItem.Content = cGrid;
            inner.Items.Add(attackItem);

            AlertsHost.Children.Add(inner);

            RenderRules();
            RenderCoverage();
            RefreshAlerts();
        }

        // ── MITRE ATT&CK coverage matrix ──
        private void RenderCoverage()
        {
            if (_coverageHost == null) return;

            // technique → alert count (open-or-any) by MITRE id
            var alertsByTech = _rules.Alerts().Where(a => !string.IsNullOrEmpty(a.MitreId))
                .GroupBy(a => a.MitreId).ToDictionary(g => g.Key, g => g.Count());

            var cols = new StackPanel { Orientation = Orientation.Horizontal };
            int coveredTactics = 0, techCount = 0;
            var seenTech = new HashSet<string>();

            foreach (var tactic in SiemMitre.Tactics)
            {
                var rulesForTactic = _rules.Rules.Where(r => string.Equals(r.MitreTactic, tactic, StringComparison.OrdinalIgnoreCase)).ToList();
                bool covered = rulesForTactic.Count > 0;
                if (covered) coveredTactics++;

                var col = new Border
                {
                    Width = 168, Margin = new Thickness(0, 0, 8, 0), CornerRadius = new CornerRadius(8),
                    Background = Br("SecondaryBackgroundBrush"), BorderThickness = new Thickness(1),
                    BorderBrush = covered ? Br("AccentBrush") : Br("BorderBrush"), Padding = new Thickness(0),
                    VerticalAlignment = VerticalAlignment.Top,
                };
                var colSp = new StackPanel();
                var header = new Border { Background = covered ? Br("AccentBrush") : Br("BackgroundBrush"), CornerRadius = new CornerRadius(7, 7, 0, 0), Padding = new Thickness(10, 7, 10, 7) };
                var hsp = new StackPanel();
                hsp.Children.Add(new TextBlock { Text = SiemMitre.Short(tactic), FontSize = 11.5, FontWeight = FontWeights.Bold, Foreground = covered ? Br("OnAccentBrush") : Br("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap });
                hsp.Children.Add(new TextBlock { Text = covered ? $"{rulesForTactic.Count} rule(s)" : "no coverage", FontSize = 9.5, Foreground = covered ? Br("OnAccentBrush") : Br("SubtleTextBrush"), Opacity = covered ? 0.85 : 0.7 });
                header.Child = hsp; colSp.Children.Add(header);

                var body = new StackPanel { Margin = new Thickness(8, 8, 8, 8) };
                if (!covered)
                {
                    body.Children.Add(new TextBlock { Text = "—", Foreground = Br("SubtleTextBrush"), FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center, Opacity = 0.5, Margin = new Thickness(0, 6, 0, 6) });
                }
                else
                {
                    foreach (var techGroup in rulesForTactic
                        .Where(r => !string.IsNullOrEmpty(r.MitreId))
                        .GroupBy(r => r.MitreId))
                    {
                        var anyRule = techGroup.First();
                        if (seenTech.Add(anyRule.MitreId)) techCount++;
                        int alerts = alertsByTech.TryGetValue(anyRule.MitreId, out var c) ? c : 0;
                        var maxSev = techGroup.Max(r => r.Severity);
                        var chip = new Border
                        {
                            CornerRadius = new CornerRadius(5), Margin = new Thickness(0, 0, 0, 5), Padding = new Thickness(8, 5, 8, 5),
                            Background = Br("BackgroundBrush"), BorderThickness = new Thickness(1),
                            BorderBrush = alerts > 0 ? Hex(SevColor(maxSev)) : Br("BorderBrush"),
                            ToolTip = $"{anyRule.MitreId} · {anyRule.MitreName}\n{techGroup.Count()} rule(s)" + (alerts > 0 ? $"\n{alerts} alert(s)" : ""),
                        };
                        var cdp = new DockPanel();
                        if (alerts > 0)
                        {
                            var badge = new Border { Background = Hex(SevColor(maxSev)), CornerRadius = new CornerRadius(8), MinWidth = 16, Height = 16, Padding = new Thickness(4, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(6, 0, 0, 0) };
                            badge.Child = new TextBlock { Text = alerts.ToString(), Foreground = Brushes.White, FontSize = 9, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                            DockPanel.SetDock(badge, Dock.Right); cdp.Children.Add(badge);
                        }
                        var tsp = new StackPanel();
                        tsp.Children.Add(new TextBlock { Text = anyRule.MitreId, FontSize = 10.5, FontWeight = FontWeights.SemiBold, FontFamily = new FontFamily("Consolas"), Foreground = Br("AccentBrush") });
                        tsp.Children.Add(new TextBlock { Text = anyRule.MitreName, FontSize = 10, Foreground = Br("TextBrush"), TextWrapping = TextWrapping.Wrap });
                        cdp.Children.Add(tsp);
                        chip.Child = cdp;
                        body.Children.Add(chip);
                    }
                }
                colSp.Children.Add(body);
                col.Child = colSp;
                cols.Children.Add(col);
            }
            _coverageHost.Child = cols;
            if (_coverageSummary != null)
                _coverageSummary.Text = $"{coveredTactics}/{SiemMitre.Tactics.Length} tactics covered  ·  {techCount} technique(s)  ·  {_rules.Rules.Count} rule(s).  Outlined chips have active alerts.";
        }

        private static string SevColor(SiemSeverity s) => s switch
        {
            SiemSeverity.Critical => "#F85149",
            SiemSeverity.High => "#FF7B72",
            SiemSeverity.Medium => "#E3B341",
            SiemSeverity.Low => "#58A6FF",
            _ => "#8B949E",
        };

        private object TabHeader(string icon, string text)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            sp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 13, Margin = new Thickness(0, 0, 7, 0), VerticalAlignment = VerticalAlignment.Center });
            sp.Children.Add(new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center });
            return sp;
        }

        private DataGrid BuildAlertGrid()
        {
            var grid = ThemedGrid(38);
            grid.Columns.Add(DotColumn("SeverityColor"));
            grid.Columns.Add(MakeTextColumn("Time", "TimeText", new DataGridLength(150), mono: true));
            grid.Columns.Add(SeverityBadgeColumnFor("SeverityColor", "SeverityText"));
            grid.Columns.Add(RiskBadgeColumn());
            grid.Columns.Add(MakeTextColumn("Rule", "RuleName", new DataGridLength(1.1, DataGridLengthUnitType.Star), bold: true));
            grid.Columns.Add(MakeTextColumn("Detail", "Message", new DataGridLength(1.6, DataGridLengthUnitType.Star), subtle: true));
            grid.Columns.Add(MakeTextColumn("MITRE", "MitreText", new DataGridLength(140), mono: true));
            grid.Columns.Add(MakeTextColumn("Assignee", "AssigneeText", new DataGridLength(110), subtle: true));
            grid.Columns.Add(StatusBadgeColumn());
            return grid;
        }

        /// <summary>A compact risk-score pill (0-100) coloured by risk band.</summary>
        private DataGridTemplateColumn RiskBadgeColumn()
        {
            var col = new DataGridTemplateColumn { Header = "Risk", Width = new DataGridLength(58) };
            var tmpl = new DataTemplate();
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            border.SetValue(Border.PaddingProperty, new Thickness(7, 2, 7, 2));
            border.SetValue(Border.MinWidthProperty, 30.0);
            border.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Left);
            border.SetBinding(Border.BackgroundProperty, new Binding("RiskColor") { Converter = _hex });
            var tb = new FrameworkElementFactory(typeof(TextBlock));
            tb.SetBinding(TextBlock.TextProperty, new Binding("RiskText"));
            tb.SetValue(TextBlock.ForegroundProperty, Brushes.White);
            tb.SetValue(TextBlock.FontWeightProperty, FontWeights.Bold);
            tb.SetValue(TextBlock.FontSizeProperty, 10.0);
            tb.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Center);
            border.AppendChild(tb);
            tmpl.VisualTree = border; col.CellTemplate = tmpl;
            return col;
        }

        private DataGridTemplateColumn StatusBadgeColumn()
        {
            var col = new DataGridTemplateColumn { Header = "Status", Width = new DataGridLength(116) };
            var tmpl = new DataTemplate();
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            border.SetValue(Border.PaddingProperty, new Thickness(8, 2, 8, 2));
            border.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Left);
            border.SetValue(Border.BackgroundProperty, Brushes.Transparent);
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            border.SetBinding(Border.BorderBrushProperty, new Binding("StatusColor") { Converter = _hex });
            var tb = new FrameworkElementFactory(typeof(TextBlock));
            tb.SetBinding(TextBlock.TextProperty, new Binding("StatusText"));
            tb.SetBinding(TextBlock.ForegroundProperty, new Binding("StatusColor") { Converter = _hex });
            tb.SetValue(TextBlock.FontWeightProperty, FontWeights.SemiBold);
            tb.SetValue(TextBlock.FontSizeProperty, 10.0);
            tb.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Center);
            border.AppendChild(tb);
            tmpl.VisualTree = border; col.CellTemplate = tmpl;
            return col;
        }

        /// <summary>Severity badge bound to arbitrary colour/text paths (reused by the alerts grid).</summary>
        private DataGridTemplateColumn SeverityBadgeColumnFor(string colorPath, string textPath)
        {
            var col = new DataGridTemplateColumn { Header = "Severity", Width = new DataGridLength(88) };
            var tmpl = new DataTemplate();
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            border.SetValue(Border.PaddingProperty, new Thickness(7, 2, 7, 2));
            border.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Left);
            border.SetBinding(Border.BackgroundProperty, new Binding(colorPath) { Converter = _hex });
            var tb = new FrameworkElementFactory(typeof(TextBlock));
            tb.SetBinding(TextBlock.TextProperty, new Binding(textPath));
            tb.SetValue(TextBlock.ForegroundProperty, Brushes.White);
            tb.SetValue(TextBlock.FontWeightProperty, FontWeights.Bold);
            tb.SetValue(TextBlock.FontSizeProperty, 9.5);
            border.AppendChild(tb);
            tmpl.VisualTree = border; col.CellTemplate = tmpl;
            return col;
        }

        private void RefreshAlerts()
        {
            if (_alertRows == null) return;
            var all = _rules.Alerts();
            int open = all.Count(a => a.Status == SiemAlertStatus.Open);
            var me = Environment.UserName;
            var shown = (_alertFilter?.SelectedItem as string) switch
            {
                "Open" => all.Where(a => a.Status == SiemAlertStatus.Open),
                "Acknowledged" => all.Where(a => a.Status == SiemAlertStatus.Acknowledged),
                "Closed" => all.Where(a => a.Status == SiemAlertStatus.Closed),
                "Assigned to me" => all.Where(a => string.Equals(a.Assignee, me, StringComparison.OrdinalIgnoreCase)),
                _ => all.AsEnumerable(),
            };
            _alertRows.Clear();
            foreach (var a in shown) _alertRows.Add(a);
            if (_alertsSummary != null)
                _alertsSummary.Text = all.Count == 0 ? "No alerts yet"
                    : $"{open:N0} open  ·  {all.Count:N0} total" + (_alertRows.Count != all.Count ? $"  ·  {_alertRows.Count:N0} shown" : "");
            UpdateAlertsBadge(open);
            RenderCoverage();
        }

        private void UpdateAlertsBadge(int open)
        {
            AlertsBadge.Visibility = open > 0 ? Visibility.Visible : Visibility.Collapsed;
            AlertsBadgeText.Text = open > 99 ? "99+" : open.ToString();
        }

        private void OnAlertRaised(object? sender, SiemAlert a) => Dispatcher.BeginInvoke(() =>
        {
            RefreshAlerts();
            ShowToast(a);
        });
        private void OnAlertsChanged() => Dispatcher.BeginInvoke(RefreshAlerts);
        private void OnRulesChanged() => Dispatcher.BeginInvoke(RenderRules);
        private void OnAgentsChanged() => Dispatcher.BeginInvoke(RefreshAgents);

        private void NewRule()
        {
            var r = new SiemRule { Name = "New rule", Severity = SiemSeverity.High };
            if (SiemRuleDialog.Edit(Window.GetWindow(this), r)) { _rules.AddRule(r); SiemAudit.Instance.Log("Rule", "Created rule", $"{r.Name} ({r.Type})"); }
        }

        private void EditRule(SiemRule r) { if (SiemRuleDialog.Edit(Window.GetWindow(this), r)) { _rules.Persist(); SiemAudit.Instance.Log("Rule", "Edited rule", r.Name); } }

        private void AddFromLibrary()
        {
            var menu = new ContextMenu();
            foreach (var t in SiemRuleLibrary.All())
            {
                var captured = t;
                var mi = new MenuItem { Header = $"{t.Name}    ({t.Severity})" };
                mi.ToolTip = t.Summary() + (string.IsNullOrEmpty(t.MitreText) ? "" : $"\n{t.MitreText}");
                mi.Click += (_, _) => { _rules.AddRule(SiemRuleLibrary.Clone(captured)); SiemAudit.Instance.Log("Rule", "Added from library", captured.Name); };
                menu.Items.Add(mi);
            }
            menu.Items.Add(new Separator());
            var addAll = new MenuItem { Header = "Add all library rules" };
            addAll.Click += (_, _) => { foreach (var t in SiemRuleLibrary.All()) _rules.AddRule(SiemRuleLibrary.Clone(t)); SiemAudit.Instance.Log("Rule", "Added all library rules", $"{SiemRuleLibrary.All().Count} rules"); };
            menu.Items.Add(addAll);
            menu.IsOpen = true;
        }

        private void RenderRules()
        {
            if (_rulesList == null) return;
            _rulesList.Items.Clear();
            if (_rules.Rules.Count == 0)
            {
                var empty = new Border { Style = (Style)FindResource("CardStyle"), Padding = new Thickness(24) };
                empty.Child = new TextBlock { Text = "No detection rules yet.\nClick “New rule” to build one, or “Add from library” for ready-made detections.", Foreground = Br("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center };
                _rulesList.Items.Add(empty);
                RenderCoverage();
                return;
            }
            foreach (var r in _rules.Rules) _rulesList.Items.Add(BuildRuleCard(r));
            RenderCoverage();
        }

        private Border BuildRuleCard(SiemRule r)
        {
            var card = new Border { Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(14, 10, 12, 10), Margin = new Thickness(0, 0, 0, 8) };
            var dp = new DockPanel { LastChildFill = true };

            var sevBar = new Border { Width = 4, CornerRadius = new CornerRadius(2), Background = Hex(r.SeverityColor), Margin = new Thickness(0, 0, 12, 0) };
            DockPanel.SetDock(sevBar, Dock.Left); dp.Children.Add(sevBar);

            var ctrls = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var en = new ToggleButton { Style = (Style)FindResource("ToggleSwitchStyle"), IsChecked = r.Enabled, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0), ToolTip = "Enable / disable" };
            en.Click += (_, _) => { r.Enabled = en.IsChecked == true; _rules.Persist(); };
            ctrls.Children.Add(en);
            Button IconBtn(string icon, string tip, Action act)
            {
                var b = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Cursor = Cursors.Hand, Width = 28, Height = 28, ToolTip = tip, Foreground = Br("SubtleTextBrush") };
                b.Content = new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Circle, FontSize = 12 };
                b.Click += (_, _) => act();
                return b;
            }
            ctrls.Children.Add(IconBtn("PenToSquare", "Edit", () => EditRule(r)));
            ctrls.Children.Add(IconBtn("TrashCan", "Remove", () => _rules.RemoveRule(r)));
            DockPanel.SetDock(ctrls, Dock.Right); dp.Children.Add(ctrls);

            var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Opacity = r.Enabled ? 1.0 : 0.5 };
            var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
            titleRow.Children.Add(new TextBlock { Text = r.Name, Foreground = Br("TextBrush"), FontSize = 13, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
            var sevBadge = new Border { Background = Hex(r.SeverityColor), CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 1, 6, 1), Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            sevBadge.Child = new TextBlock { Text = r.Severity.ToString().ToUpperInvariant(), Foreground = Brushes.White, FontSize = 9, FontWeight = FontWeights.Bold };
            titleRow.Children.Add(sevBadge);
            if (!string.IsNullOrEmpty(r.MitreText))
            {
                var m = new Border { BorderBrush = Br("BorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 1, 6, 1), Margin = new Thickness(6, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                m.Child = new TextBlock { Text = r.MitreText, Foreground = Br("SubtleTextBrush"), FontSize = 9.5, FontFamily = new FontFamily("Consolas") };
                titleRow.Children.Add(m);
            }
            info.Children.Add(titleRow);
            info.Children.Add(new TextBlock { Text = r.Summary(), Foreground = Br("SubtleTextBrush"), FontSize = 11, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 3, 0, 0), TextWrapping = TextWrapping.Wrap });
            dp.Children.Add(info);

            card.Child = dp;
            return card;
        }

        // ── in-page toast notifications ──
        private void SetupToastHost()
        {
            if (Content is not Grid root) return;
            _toastHost = new StackPanel
            {
                HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(0, 0, 20, 20), IsHitTestVisible = true,
            };
            Grid.SetRowSpan(_toastHost, Math.Max(1, root.RowDefinitions.Count));
            Panel.SetZIndex(_toastHost, 999);
            root.Children.Add(_toastHost);
        }

        private void ShowToast(SiemAlert a)
        {
            if (_toastHost == null) return;
            var card = new Border
            {
                Background = Br("SecondaryBackgroundBrush"), BorderBrush = Hex(a.SeverityColor), BorderThickness = new Thickness(1, 1, 1, 1),
                CornerRadius = new CornerRadius(8), Padding = new Thickness(0), Margin = new Thickness(0, 8, 0, 0), MaxWidth = 380,
                Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = Colors.Black, BlurRadius = 18, ShadowDepth = 3, Opacity = 0.4 },
            };
            var dp = new DockPanel { LastChildFill = true };
            var accent = new Border { Width = 4, Background = Hex(a.SeverityColor), CornerRadius = new CornerRadius(8, 0, 0, 8) };
            DockPanel.SetDock(accent, Dock.Left); dp.Children.Add(accent);

            var body = new StackPanel { Margin = new Thickness(14, 11, 14, 11) };
            var top = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
            top.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.TriangleExclamation, FontSize = 13, Foreground = Hex(a.SeverityColor), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            top.Children.Add(new TextBlock { Text = $"{a.SeverityText.ToUpperInvariant()} · {a.RuleName}", Foreground = Br("TextBrush"), FontWeight = FontWeights.Bold, FontSize = 12, VerticalAlignment = VerticalAlignment.Center });
            var close = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Width = 18, Height = 16, Foreground = Br("SubtleTextBrush"), Cursor = Cursors.Hand, HorizontalAlignment = HorizontalAlignment.Right };
            close.Content = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.Xmark, FontSize = 10 };
            close.Click += (_, _) => _toastHost.Children.Remove(card);
            DockPanel.SetDock(close, Dock.Right); top.Children.Add(close);
            body.Children.Add(top);
            body.Children.Add(new TextBlock { Text = a.Message, Foreground = Br("SubtleTextBrush"), FontSize = 11, TextWrapping = TextWrapping.Wrap });
            var view = new TextBlock { Text = "View alerts →", Foreground = Br("AccentBrush"), FontSize = 11, FontWeight = FontWeights.SemiBold, Cursor = Cursors.Hand, Margin = new Thickness(0, 6, 0, 0) };
            view.MouseLeftButtonUp += (_, _) => { if (_alertsTab != null) Tabs.SelectedItem = _alertsTab; _toastHost.Children.Remove(card); };
            body.Children.Add(view);
            dp.Children.Add(body);
            card.Child = dp;

            _toastHost.Children.Add(card);
            // fade/slide in
            var tt = new TranslateTransform(24, 0); card.RenderTransform = tt; card.Opacity = 0;
            card.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(220))));
            tt.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(24, 0, new Duration(TimeSpan.FromMilliseconds(260))) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });

            // auto-dismiss after 7s
            var dismiss = new DispatcherTimer { Interval = TimeSpan.FromSeconds(7) };
            dismiss.Tick += (_, _) =>
            {
                dismiss.Stop();
                if (!_toastHost.Children.Contains(card)) return;
                var fade = new DoubleAnimation(1, 0, new Duration(TimeSpan.FromMilliseconds(300)));
                fade.Completed += (_, _) => _toastHost.Children.Remove(card);
                card.BeginAnimation(OpacityProperty, fade);
            };
            dismiss.Start();
            // cap visible toasts
            while (_toastHost.Children.Count > 4) _toastHost.Children.RemoveAt(0);
        }

        /// <summary>A simple informational toast (e.g. "added to case").</summary>
        private void ShowToastText(string title, string message)
        {
            if (_toastHost == null) return;
            var card = new Border
            {
                Background = Br("SecondaryBackgroundBrush"), BorderBrush = Br("AccentBrush"), BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8), Margin = new Thickness(0, 8, 0, 0), MaxWidth = 360,
                Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = Colors.Black, BlurRadius = 18, ShadowDepth = 3, Opacity = 0.4 },
            };
            var body = new StackPanel { Margin = new Thickness(14, 11, 14, 11) };
            var top = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
            top.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.CircleCheck, FontSize = 13, Foreground = Br("SuccessBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            top.Children.Add(new TextBlock { Text = title, Foreground = Br("TextBrush"), FontWeight = FontWeights.Bold, FontSize = 12, VerticalAlignment = VerticalAlignment.Center });
            body.Children.Add(top);
            body.Children.Add(new TextBlock { Text = message, Foreground = Br("SubtleTextBrush"), FontSize = 11, TextWrapping = TextWrapping.Wrap });
            card.Child = body;
            _toastHost.Children.Add(card);
            var tt = new TranslateTransform(24, 0); card.RenderTransform = tt; card.Opacity = 0;
            card.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(220))));
            tt.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(24, 0, new Duration(TimeSpan.FromMilliseconds(260))) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
            var dismiss = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            dismiss.Tick += (_, _) => { dismiss.Stop(); if (_toastHost.Children.Contains(card)) { var f = new DoubleAnimation(1, 0, new Duration(TimeSpan.FromMilliseconds(300))); f.Completed += (_, _) => _toastHost.Children.Remove(card); card.BeginAnimation(OpacityProperty, f); } };
            dismiss.Start();
            while (_toastHost.Children.Count > 4) _toastHost.Children.RemoveAt(0);
        }

        // ════════════════════════════════════════════════════════════════════
        //  shared grid + data flow
        // ════════════════════════════════════════════════════════════════════
        // ── a themed, "alive" event grid: severity dot + badge, solid bg, taller rows ──
        private DataGrid BuildEventGrid(bool compact)
        {
            var grid = ThemedGrid(compact ? 30 : 34);
            grid.Columns.Add(SeverityDotColumn());
            grid.Columns.Add(MakeTextColumn("Time", "TimeText", new DataGridLength(compact ? 88 : 128), mono: true));
            grid.Columns.Add(SeverityBadgeColumn());
            if (!compact) grid.Columns.Add(MakeTextColumn("Host", "Host", new DataGridLength(130), bold: true));
            grid.Columns.Add(MakeTextColumn("Source", "Source", new DataGridLength(compact ? 118 : 150), mono: true));
            if (!compact) grid.Columns.Add(MakeTextColumn("Category", "Category", new DataGridLength(110)));
            grid.Columns.Add(MakeTextColumn("Event", "EventType", new DataGridLength(compact ? 130 : 170)));
            grid.Columns.Add(MakeTextColumn("Message", "Message", new DataGridLength(1, DataGridLengthUnitType.Star), subtle: true));
            return grid;
        }

        /// <summary>Base DataGrid styled like the IDS dashboard — solid panel, header bar, hover/selection.</summary>
        private DataGrid ThemedGrid(double rowHeight)
        {
            var grid = new DataGrid
            {
                AutoGenerateColumns = false, IsReadOnly = true, HeadersVisibility = DataGridHeadersVisibility.Column,
                Background = Br("SecondaryBackgroundBrush"), RowBackground = Br("SecondaryBackgroundBrush"),
                Foreground = Br("TextBrush"), BorderThickness = new Thickness(0),
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal, HorizontalGridLinesBrush = Br("BorderBrush"),
                SelectionMode = DataGridSelectionMode.Single, CanUserAddRows = false, CanUserDeleteRows = false,
                CanUserResizeRows = false, RowHeight = rowHeight, ColumnHeaderHeight = 36,
                EnableRowVirtualization = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                ColumnHeaderStyle = HeaderStyle(), RowStyle = RowStyle(), CellStyle = CellStyle(),
            };
            return grid;
        }

        private Style HeaderStyle()
        {
            var s = new Style(typeof(System.Windows.Controls.Primitives.DataGridColumnHeader));
            s.Setters.Add(new Setter(Control.BackgroundProperty, Br("SecondaryBackgroundBrush")));
            s.Setters.Add(new Setter(Control.ForegroundProperty, Br("SubtleTextBrush")));
            s.Setters.Add(new Setter(Control.FontWeightProperty, FontWeights.SemiBold));
            s.Setters.Add(new Setter(Control.FontSizeProperty, 10.5));
            s.Setters.Add(new Setter(Control.FontFamilyProperty, (FontFamily)FindResource("PrimaryFont")));
            s.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(10, 0, 8, 0)));
            s.Setters.Add(new Setter(Control.HeightProperty, 36.0));
            s.Setters.Add(new Setter(Control.VerticalContentAlignmentProperty, VerticalAlignment.Center));
            s.Setters.Add(new Setter(Control.BorderBrushProperty, Br("BorderBrush")));
            s.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0, 0, 0, 2)));
            return s;
        }

        private Style RowStyle()
        {
            var s = new Style(typeof(DataGridRow));
            s.Setters.Add(new Setter(DataGridRow.BackgroundProperty, Br("SecondaryBackgroundBrush")));
            s.Setters.Add(new Setter(Control.ForegroundProperty, Br("TextBrush")));
            var hover = new Trigger { Property = DataGridRow.IsMouseOverProperty, Value = true };
            hover.Setters.Add(new Setter(DataGridRow.BackgroundProperty, Br("HoverBrush")));
            s.Triggers.Add(hover);
            var sel = new Trigger { Property = DataGridRow.IsSelectedProperty, Value = true };
            sel.Setters.Add(new Setter(DataGridRow.BackgroundProperty, Br("SelectionBrush")));
            s.Triggers.Add(sel);
            return s;
        }

        private Style CellStyle()
        {
            var s = new Style(typeof(DataGridCell));
            s.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            s.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
            s.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(10, 0, 6, 0)));
            s.Setters.Add(new Setter(Control.VerticalContentAlignmentProperty, VerticalAlignment.Center));
            s.Setters.Add(new Setter(Control.FocusVisualStyleProperty, null));
            var tmpl = new ControlTemplate(typeof(DataGridCell));
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(BackgroundProperty));
            border.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
            var cp = new FrameworkElementFactory(typeof(ContentPresenter));
            cp.SetValue(VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(cp);
            tmpl.VisualTree = border;
            s.Setters.Add(new Setter(Control.TemplateProperty, tmpl));
            return s;
        }

        private DataGridTemplateColumn SeverityDotColumn() => DotColumn("SeverityColor");

        private DataGridTemplateColumn DotColumn(string colorPath, double size = 8)
        {
            var col = new DataGridTemplateColumn { Header = "", Width = new DataGridLength(22), CanUserResize = false };
            var tmpl = new DataTemplate();
            var dot = new FrameworkElementFactory(typeof(Ellipse));
            dot.SetValue(WidthProperty, size); dot.SetValue(HeightProperty, size);
            dot.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Center);
            dot.SetBinding(Shape.FillProperty, new Binding(colorPath) { Converter = _hex });
            tmpl.VisualTree = dot; col.CellTemplate = tmpl;
            return col;
        }

        private DataGridTemplateColumn SeverityBadgeColumn()
        {
            var col = new DataGridTemplateColumn { Header = "Severity", Width = new DataGridLength(88) };
            var tmpl = new DataTemplate();
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            border.SetValue(Border.PaddingProperty, new Thickness(7, 2, 7, 2));
            border.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Left);
            border.SetBinding(Border.BackgroundProperty, new Binding("SeverityColor") { Converter = _hex });
            var tb = new FrameworkElementFactory(typeof(TextBlock));
            tb.SetBinding(TextBlock.TextProperty, new Binding("SeverityText"));
            tb.SetValue(TextBlock.ForegroundProperty, Brushes.White);
            tb.SetValue(TextBlock.FontWeightProperty, FontWeights.Bold);
            tb.SetValue(TextBlock.FontSizeProperty, 9.5);
            border.AppendChild(tb);
            tmpl.VisualTree = border; col.CellTemplate = tmpl;
            return col;
        }

        private DataGridTextColumn MakeTextColumn(string header, string path, DataGridLength width, bool mono = false, bool bold = false, bool subtle = false)
        {
            var col = new DataGridTextColumn { Header = header, Binding = new Binding(path), Width = width };
            var st = new Style(typeof(TextBlock));
            if (mono) st.Setters.Add(new Setter(TextBlock.FontFamilyProperty, new FontFamily("Consolas")));
            if (bold) st.Setters.Add(new Setter(TextBlock.FontWeightProperty, FontWeights.SemiBold));
            if (subtle) st.Setters.Add(new Setter(TextBlock.ForegroundProperty, Br("SubtleTextBrush")));
            st.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));
            st.Setters.Add(new Setter(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center));
            col.ElementStyle = st;
            return col;
        }

        private void ColorCol(DataGridTextColumn col, string hex)
        {
            var st = new Style(typeof(TextBlock));
            st.Setters.Add(new Setter(TextBlock.ForegroundProperty, Hex(hex)));
            st.Setters.Add(new Setter(TextBlock.FontWeightProperty, FontWeights.Bold));
            st.Setters.Add(new Setter(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center));
            col.ElementStyle = st;
        }

        /// <summary>Wrap a grid in a panel that shows a friendly empty-state when it has no rows.</summary>
        private Grid WrapWithEmptyState(UIElement grid, System.Collections.Specialized.INotifyCollectionChanged rows, string icon, string title, string sub)
        {
            var host = new Grid();
            host.Children.Add(grid);
            var empty = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, IsHitTestVisible = false };
            empty.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = Enum.TryParse<FontAwesome.Sharp.IconChar>(icon, out var ic) ? ic : FontAwesome.Sharp.IconChar.Inbox, FontSize = 34, Foreground = Br("BorderBrush"), HorizontalAlignment = HorizontalAlignment.Center });
            empty.Children.Add(new TextBlock { Text = title, Foreground = Br("SubtleTextBrush"), FontSize = 13, FontWeight = FontWeights.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 10, 0, 2) });
            empty.Children.Add(new TextBlock { Text = sub, Foreground = Br("SubtleTextBrush"), FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center, MaxWidth = 320, TextWrapping = TextWrapping.Wrap, Opacity = 0.8 });
            host.Children.Add(empty);
            void Sync() => empty.Visibility = (rows as System.Collections.ICollection)?.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            rows.CollectionChanged += (_, _) => Sync();
            Sync();
            return host;
        }

        private void OnEventAdded(object? sender, SiemEvent e) => Dispatcher.BeginInvoke(() =>
        {
            if (!InWindow(e) || !_query.Matches(e)) return;
            if (_searchRows != null)
            {
                _searchRows.Insert(0, e);
                while (_searchRows.Count > FeedCap) _searchRows.RemoveAt(_searchRows.Count - 1);
            }
            if (e.Severity >= SiemSeverity.High)
                foreach (var c in _tileCtx.Values.Where(c => c.W.Type == SiemWidgetType.Watchlist && c.Rows != null))
                {
                    c.Rows!.Insert(0, e);
                    while (c.Rows.Count > FeedCap) c.Rows.RemoveAt(c.Rows.Count - 1);
                }
        });

        private bool InWindow(SiemEvent e) => _window?.Contains(e.Timestamp) ?? true;

        private void RefreshAll()
        {
            long total = _store.TotalIngested; var now = DateTime.Now;
            double secs = Math.Max(0.5, (now - _lastTick).TotalSeconds);
            _rate = (total - _lastTotal) / secs; _lastTotal = total; _lastTick = now;

            _store.PurgeExpired();
            RefreshKpis();
            RefreshTiles();
            RefreshMachines();
            if (ReferenceEquals(Tabs.SelectedItem, _sourcesTab)) RefreshAgents();   // keep Fleet last-check-in fresh
            UpdateSearchCount();
            if (ReferenceEquals(Tabs.SelectedItem, _searchTab)) RefreshDiscoverChrome();
            if (ReferenceEquals(Tabs.SelectedItem, _indexTab)) RefreshIndex();
            if (ReferenceEquals(Tabs.SelectedItem, _securityTab)) RefreshSecurity();
            if (ReferenceEquals(Tabs.SelectedItem, _entitiesTab)) RefreshEntities();
            if (ReferenceEquals(Tabs.SelectedItem, _networkTab)) RefreshNetwork();
            if (ReferenceEquals(Tabs.SelectedItem, _threatTab)) RefreshThreatIntel();
        }

        private DateTime _lastFieldRefresh = DateTime.MinValue;
        private void RefreshDiscoverChrome()
        {
            if (_histoHost != null) _histoHost.Child = BuildBrushHistogram(40, 56);
            // recompute the fields list at most ~every 3s (it samples the index)
            if ((DateTime.Now - _lastFieldRefresh).TotalSeconds >= 3) { RefreshFields(); _lastFieldRefresh = DateTime.Now; }
        }

        // ════════════════════════════════════════════════════════════════════
        //  toolbar / filters
        // ════════════════════════════════════════════════════════════════════
        private void ApplyQuery()
        {
            _query = SiemQuery.Parse(SearchBox.Text);
            RebuildSearch();
            RebuildFilterPills();
            RefreshFields();
            if (_histoHost != null) _histoHost.Child = BuildBrushHistogram(40, 56);
            foreach (var c in _tileCtx.Values.Where(c => c.W.Type == SiemWidgetType.Watchlist)) RebuildWatchlist(c);
            RefreshAll();
        }

        // ── filter pills (Kibana-style chips for each active query clause) ──
        private static List<string> RawTokens(string text)
        {
            var list = new List<string>(); var sb = new System.Text.StringBuilder(); bool q = false;
            foreach (var c in text)
            {
                if (c == '"') { q = !q; sb.Append(c); }
                else if (char.IsWhiteSpace(c) && !q) { if (sb.Length > 0) { list.Add(sb.ToString()); sb.Clear(); } }
                else sb.Append(c);
            }
            if (sb.Length > 0) list.Add(sb.ToString());
            return list;
        }

        private void RebuildFilterPills()
        {
            if (_filterBar == null) return;
            _filterBar.Children.Clear();
            var tokens = RawTokens(SearchBox.Text ?? "");
            _filterBar.Margin = tokens.Count > 0 ? new Thickness(0, 0, 0, 8) : new Thickness(0);
            for (int i = 0; i < tokens.Count; i++)
            {
                int idx = i; var tok = tokens[i];
                // don't render boolean operators / grouping as removable pills
                if (tok is "(" or ")" || tok.Equals("AND", StringComparison.OrdinalIgnoreCase)
                    || tok.Equals("OR", StringComparison.OrdinalIgnoreCase) || tok.Equals("NOT", StringComparison.OrdinalIgnoreCase))
                    continue;
                bool neg = tok.StartsWith("-") || tok.StartsWith("!");
                var core = neg ? tok[1..] : tok;
                int ci = core.IndexOf(':');
                string label = ci > 0 ? $"{core[..ci]}: {core[(ci + 1)..].Trim('"')}" : core.Trim('"');
                if (neg) label = "NOT " + label;

                var pill = new Border
                {
                    CornerRadius = new CornerRadius(4), Padding = new Thickness(9, 3, 4, 3), Margin = new Thickness(0, 0, 6, 6),
                    Background = Br("SecondaryBackgroundBrush"), BorderBrush = neg ? Br("CriticalBrush") : Br("AccentBrush"), BorderThickness = new Thickness(1),
                };
                var dp = new StackPanel { Orientation = Orientation.Horizontal };
                var txt = new TextBlock { Text = label, Foreground = Br("TextBrush"), FontSize = 11, FontFamily = new FontFamily("Consolas"), VerticalAlignment = VerticalAlignment.Center, Cursor = Cursors.Hand, ToolTip = "Click to toggle include / exclude" };
                txt.MouseLeftButtonUp += (_, _) => { tokens[idx] = neg ? core : "-" + core; SearchBox.Text = string.Join(" ", tokens); };
                dp.Children.Add(txt);
                var x = new Button { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Width = 18, Height = 16, Foreground = Br("SubtleTextBrush"), Cursor = Cursors.Hand, Margin = new Thickness(5, 0, 0, 0), ToolTip = "Remove filter" };
                x.Content = new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.Xmark, FontSize = 9 };
                x.Click += (_, _) => { tokens.RemoveAt(idx); SearchBox.Text = string.Join(" ", tokens); };
                dp.Children.Add(x);
                pill.Child = dp; _filterBar.Children.Add(pill);
            }
            if (tokens.Count > 1)
            {
                var clear = new Button { Content = "Clear all", Style = (Style)FindResource("GhostButtonStyle"), Height = 24, FontSize = 10, Margin = new Thickness(0, 0, 0, 6), Padding = new Thickness(8, 0, 8, 0) };
                clear.Click += (_, _) => SearchBox.Text = "";
                _filterBar.Children.Add(clear);
            }
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            SearchHint.Visibility = string.IsNullOrEmpty(SearchBox.Text) ? Visibility.Visible : Visibility.Collapsed;
            ClearSearchBtn.Visibility = string.IsNullOrEmpty(SearchBox.Text) ? Visibility.Collapsed : Visibility.Visible;
            ApplyQuery();
        }
        private void SearchBox_KeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { ApplyQuery(); RecordSearchHistory(SearchBox.Text); } }
        private void ClearSearch_Click(object sender, RoutedEventArgs e) => SearchBox.Text = "";

        // ── search history (recent committed queries) ──
        private readonly List<string> _searchHistory = new();

        private void RecordSearchHistory(string? query)
        {
            var q = (query ?? "").Trim();
            if (q.Length == 0) return;
            _searchHistory.RemoveAll(x => string.Equals(x, q, StringComparison.OrdinalIgnoreCase));
            _searchHistory.Insert(0, q);
            while (_searchHistory.Count > 20) _searchHistory.RemoveAt(_searchHistory.Count - 1);
        }

        private void History_Click(object sender, RoutedEventArgs e)
        {
            var menu = new ContextMenu();
            if (_searchHistory.Count == 0)
                menu.Items.Add(new MenuItem { Header = "No recent searches", IsEnabled = false });
            else
            {
                foreach (var q in _searchHistory)
                {
                    var captured = q;
                    var mi = new MenuItem { Header = q.Length > 80 ? q[..80] + "…" : q, ToolTip = q };
                    mi.Click += (_, _) => { SearchBox.Text = captured; ApplyQuery(); };
                    menu.Items.Add(mi);
                }
                menu.Items.Add(new Separator());
                var clear = new MenuItem { Header = "Clear history" };
                clear.Click += (_, _) => _searchHistory.Clear();
                menu.Items.Add(clear);
            }
            menu.PlacementTarget = HistoryBtn; menu.IsOpen = true;
        }

        private void AddFilter(string field, string value)
        {
            bool neg = value.StartsWith("-");
            if (neg) value = value[1..];
            string prefix = neg ? "-" : "";
            var clause = value.Contains(' ') ? $"{prefix}{field}:\"{value}\"" : $"{prefix}{field}:{value}";
            if (SearchBox.Text.Contains(clause)) return;
            SearchBox.Text = string.IsNullOrWhiteSpace(SearchBox.Text) ? clause : SearchBox.Text.TrimEnd() + " " + clause;
        }

        private void Range_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && int.TryParse(b.Tag?.ToString(), out var min)) ApplyRange(min);
        }

        // ── auto-refresh interval (Kibana-style; 0 = paused) ──
        private int _refreshSecs = 1;
        private void AutoRefresh_Click(object sender, RoutedEventArgs e)
        {
            var menu = new ContextMenu();
            void Opt(string label, int secs)
            {
                var mi = new MenuItem { Header = label, IsChecked = _refreshSecs == secs };
                mi.Click += (_, _) => SetAutoRefresh(secs);
                menu.Items.Add(mi);
            }
            Opt("Off", 0);
            menu.Items.Add(new Separator());
            Opt("1 second", 1);
            Opt("5 seconds", 5);
            Opt("10 seconds", 10);
            Opt("30 seconds", 30);
            Opt("1 minute", 60);
            Opt("5 minutes", 300);
            menu.PlacementTarget = RefreshBtn; menu.IsOpen = true;
        }

        private void SetAutoRefresh(int secs)
        {
            _refreshSecs = secs;
            if (secs <= 0)
            {
                _timer.Stop();
                RefreshBtn.Content = "⟳ off";
                RefreshBtn.Foreground = Br("SubtleTextBrush");
            }
            else
            {
                _timer.Interval = TimeSpan.FromSeconds(secs);
                _timer.Start();
                RefreshBtn.Content = "⟳ " + (secs < 60 ? $"{secs}s" : $"{secs / 60}m");
                RefreshBtn.Foreground = Br("AccentBrush");
                RefreshAll();   // refresh immediately so a shorter interval feels responsive
            }
        }

        /// <summary>Apply a rolling time window of <paramref name="min"/> minutes (0 = all time).</summary>
        private void ApplyRange(int min)
        {
            _window = min == 0 ? null : SiemRange.Rolling(TimeSpan.FromMinutes(min));
            _rangeMin = min;
            HighlightRange(min);
            AfterRangeChanged();
        }

        /// <summary>Apply an absolute from/to range (Discover histogram zoom + "Absolute range…").</summary>
        private void ApplyAbsoluteRange(DateTime from, DateTime to)
        {
            _window = SiemRange.Absolute(from, to);
            _rangeMin = -1;
            HighlightRange(-1);   // no quick-range chip matches an absolute range
            AfterRangeChanged();
        }

        private void AfterRangeChanged()
        {
            RebuildSearch();
            RefreshFields();
            if (_histoHost != null) _histoHost.Child = BuildBrushHistogram(40, 56);
            foreach (var c in _tileCtx.Values.Where(c => c.W.Type == SiemWidgetType.Watchlist)) RebuildWatchlist(c);
            RefreshAll();
        }

        private void PromptAbsoluteRange()
        {
            var now = DateTime.Now;
            var fromTxt = TextPromptDialog.Ask(Window.GetWindow(this), "Absolute range", "FROM  (yyyy-MM-dd HH:mm)", now.AddHours(-1).ToString("yyyy-MM-dd HH:mm"), "Next");
            if (string.IsNullOrWhiteSpace(fromTxt)) return;
            var toTxt = TextPromptDialog.Ask(Window.GetWindow(this), "Absolute range", "TO  (yyyy-MM-dd HH:mm)", now.ToString("yyyy-MM-dd HH:mm"), "Apply");
            if (string.IsNullOrWhiteSpace(toTxt)) return;
            if (DateTime.TryParse(fromTxt, out var f) && DateTime.TryParse(toTxt, out var t)) ApplyAbsoluteRange(f, t);
        }

        private void CustomRange_Click(object sender, RoutedEventArgs e)
        {
            var menu = new ContextMenu();
            void Preset(string label, int minutes)
            {
                var mi = new MenuItem { Header = label, IsChecked = _rangeMin == minutes };
                mi.Click += (_, _) => ApplyRange(minutes);
                menu.Items.Add(mi);
            }
            Preset("Last 30 minutes", 30);
            Preset("Last 6 hours", 360);
            Preset("Last 12 hours", 720);
            Preset("Last 3 days", 4320);
            Preset("Last 7 days", 10080);
            Preset("Last 30 days", 43200);
            menu.Items.Add(new Separator());
            var custom = new MenuItem { Header = "Custom (minutes)…" };
            custom.Click += (_, _) =>
            {
                var txt = TextPromptDialog.Ask(Window.GetWindow(this), "Custom time range", "LAST … MINUTES", _rangeMin > 0 ? _rangeMin.ToString() : "60", "Apply");
                if (int.TryParse(txt?.Trim(), out var m) && m > 0) ApplyRange(m);
            };
            menu.Items.Add(custom);
            var abs = new MenuItem { Header = "Absolute range (from / to)…" };
            abs.Click += (_, _) => PromptAbsoluteRange();
            menu.Items.Add(abs);
            menu.PlacementTarget = CustomRangeBtn; menu.IsOpen = true;
        }

        private void HighlightRange(int min)
        {
            // find the range button panel via the SearchBox's visual ancestry is awkward; instead colour by Tag
            foreach (var btn in FindRangeButtons())
                btn.Foreground = Br(btn.Tag?.ToString() == min.ToString() ? "AccentBrush" : "SubtleTextBrush");
        }

        private IEnumerable<Button> FindRangeButtons()
        {
            // the range buttons live in the header; walk the logical tree from the page root
            return EnumerateVisual(this).OfType<Button>().Where(b => b.Style == (Style)FindResource("RangeChip"));
        }

        private static IEnumerable<DependencyObject> EnumerateVisual(DependencyObject root)
        {
            int n = System.Windows.Media.VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++)
            {
                var c = System.Windows.Media.VisualTreeHelper.GetChild(root, i);
                yield return c;
                foreach (var d in EnumerateVisual(c)) yield return d;
            }
        }

        private void Visualize_Click(object sender, RoutedEventArgs e)
        {
            var fields = _store.FieldNames(_query, _window).Select(f => f.field).ToList();
            var w = new SiemWidget { Type = SiemWidgetType.Custom, Chart = SiemChart.Bar, Agg = SiemAgg.Count };
            if (SiemVizDialog.Edit(Window.GetWindow(this), w, fields))
            {
                _tiles.Add(w); BuildTile(w); SaveDashboards();
            }
        }

        /// <summary>Per-field Discover shortcut: build a sensible tile for the field's type and add it to Overview.</summary>
        private void VisualizeField(string field, SiemFieldType ftype)
        {
            var w = new SiemWidget { Type = SiemWidgetType.Custom, Field = field };
            switch (ftype)
            {
                case SiemFieldType.Date:
                    w.Chart = SiemChart.Line; w.Agg = SiemAgg.Count; break;
                case SiemFieldType.Number:
                    w.Chart = SiemChart.Metric; w.Agg = SiemAgg.Average; break;
                default:
                    w.Chart = SiemChart.Bar; w.Agg = SiemAgg.Count; w.TopN = 8; break;
            }
            _tiles.Add(w); BuildTile(w); SaveDashboards();
            Tabs.SelectedItem = _overviewTab;   // jump to Overview to show the new tile
            ShowToastText("Visualization added", $"“{w.DisplayTitle()}” added to the Overview dashboard.");
        }

        private void AddPanel_Click(object sender, RoutedEventArgs e)
        {
            var menu = new ContextMenu();
            foreach (SiemWidgetType t in new[] { SiemWidgetType.Histogram, SiemWidgetType.SeverityDonut, SiemWidgetType.TopSources, SiemWidgetType.TopCategories, SiemWidgetType.TopEventTypes, SiemWidgetType.Watchlist })
            {
                var mi = new MenuItem { Header = SiemWidget.Title(t) };
                var captured = t;
                mi.Click += (_, _) => { var w = new SiemWidget { Type = captured }; _tiles.Add(w); BuildTile(w); SaveDashboards(); };
                menu.Items.Add(mi);
            }
            menu.PlacementTarget = AddPanelBtn; menu.IsOpen = true;
        }

        private void Reset_Click(object sender, RoutedEventArgs e)
        {
            foreach (var c in _tileCtx.Values) TilesHost.Children.Remove(c.Card);
            _tileCtx.Clear(); _tiles.Clear();
            _tiles.AddRange(SiemWidget.Default());
            foreach (var w in _tiles) BuildTile(w);
            SaveDashboards();
        }

        // ════════════════════════════════════════════════════════════════════
        //  Multiple dashboards (Kibana saved dashboards)
        // ════════════════════════════════════════════════════════════════════
        private void SaveDashboards()
        {
            _dash.Tiles = _tiles;
            _dashDoc.Current = _dash.Name;
            SiemDashboardStore.Save(_dashDoc);
        }

        private void BuildDashboardSwitcher()
        {
            var btn = new Button { Style = (Style)FindResource("GhostButtonStyle"), Height = 30, Padding = new Thickness(12, 0, 12, 0), Cursor = Cursors.Hand };
            var sp = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            sp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.TableCells, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            sp.Children.Add(new TextBlock { Text = _dash.Name, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
            sp.Children.Add(new FontAwesome.Sharp.IconBlock { Icon = FontAwesome.Sharp.IconChar.AngleDown, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) });
            btn.Content = sp;
            btn.Click += (_, _) => OpenDashboardMenu(btn);
            DashSwitcherHost.Content = btn;
        }

        private void OpenDashboardMenu(Button anchor)
        {
            var menu = new ContextMenu();
            foreach (var d in _dashDoc.Dashboards)
            {
                var captured = d;
                var mi = new MenuItem { Header = d.Name, IsChecked = string.Equals(d.Name, _dash.Name, StringComparison.OrdinalIgnoreCase) };
                mi.Click += (_, _) => SwitchDashboard(captured);
                menu.Items.Add(mi);
            }
            menu.Items.Add(new Separator());
            var add = new MenuItem { Header = "New dashboard…" };
            add.Click += (_, _) => NewDashboard();
            menu.Items.Add(add);
            var rename = new MenuItem { Header = "Rename current…" };
            rename.Click += (_, _) => RenameDashboard();
            menu.Items.Add(rename);
            var del = new MenuItem { Header = "Delete current", IsEnabled = _dashDoc.Dashboards.Count > 1 };
            del.Click += (_, _) => DeleteDashboard();
            menu.Items.Add(del);
            menu.PlacementTarget = anchor; menu.IsOpen = true;
        }

        private void SwitchDashboard(SiemDashboard d)
        {
            if (ReferenceEquals(d, _dash)) return;
            SaveDashboards();   // persist the one we're leaving
            foreach (var c in _tileCtx.Values) TilesHost.Children.Remove(c.Card);
            _tileCtx.Clear();
            _dash = d;
            if (_dash.Tiles.Count == 0) _dash.Tiles = SiemWidget.Default();
            _tiles = _dash.Tiles;
            _dashDoc.Current = _dash.Name;
            foreach (var w in _tiles) BuildTile(w);
            BuildDashboardSwitcher();
            SaveDashboards();
            RefreshTiles();
        }

        private void NewDashboard()
        {
            var name = TextPromptDialog.Ask(Window.GetWindow(this), "New dashboard", "DASHBOARD NAME", "", "Create");
            if (string.IsNullOrWhiteSpace(name)) return;
            name = UniqueDashName(name);
            var d = new SiemDashboard { Name = name, Tiles = SiemWidget.Default() };
            _dashDoc.Dashboards.Add(d);
            SwitchDashboard(d);
        }

        private void RenameDashboard()
        {
            var name = TextPromptDialog.Ask(Window.GetWindow(this), "Rename dashboard", "DASHBOARD NAME", _dash.Name, "Rename");
            if (string.IsNullOrWhiteSpace(name)) return;
            _dash.Name = UniqueDashName(name, _dash);
            _dashDoc.Current = _dash.Name;
            BuildDashboardSwitcher();
            SaveDashboards();
        }

        private void DeleteDashboard()
        {
            if (_dashDoc.Dashboards.Count <= 1) return;
            _dashDoc.Dashboards.Remove(_dash);
            var next = _dashDoc.Dashboards[0];
            _dash = next;            // SwitchDashboard early-returns if same ref; force via manual swap
            foreach (var c in _tileCtx.Values) TilesHost.Children.Remove(c.Card);
            _tileCtx.Clear();
            if (_dash.Tiles.Count == 0) _dash.Tiles = SiemWidget.Default();
            _tiles = _dash.Tiles;
            _dashDoc.Current = _dash.Name;
            foreach (var w in _tiles) BuildTile(w);
            BuildDashboardSwitcher();
            SaveDashboards();
        }

        // ── E18: export / import a single dashboard (share) ──
        private void ShareDashboard_Click(object sender, RoutedEventArgs e)
        {
            var menu = new ContextMenu();
            var exp = new MenuItem { Header = $"Export “{_dash.Name}” to file…" };
            exp.Click += (_, _) => ExportDashboard();
            var imp = new MenuItem { Header = "Import dashboard from file…" };
            imp.Click += (_, _) => ImportDashboard();
            menu.Items.Add(exp); menu.Items.Add(imp);
            menu.PlacementTarget = ShareDashBtn; menu.IsOpen = true;
        }

        private void ExportDashboard()
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "SIEM dashboard (*.json)|*.json|All files (*.*)|*.*",
                FileName = $"privacore-dashboard-{_dash.Name}-{DateTime.Now:yyyyMMdd}.json",
                Title = "Export dashboard",
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                var doc = new SiemDashboard { Name = _dash.Name, Tiles = _tiles };
                System.IO.File.WriteAllText(dlg.FileName, System.Text.Json.JsonSerializer.Serialize(doc, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                SiemAudit.Instance.Log("Dashboard", "Exported dashboard", _dash.Name);
                ShowToastText("Dashboard exported", $"“{_dash.Name}” written to {System.IO.Path.GetFileName(dlg.FileName)}.");
            }
            catch (Exception ex) { MessageBox.Show(Window.GetWindow(this), ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }

        private void ImportDashboard()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "SIEM dashboard (*.json)|*.json|All files (*.*)|*.*", Title = "Import dashboard" };
            if (dlg.ShowDialog() != true) return;
            try
            {
                var doc = System.Text.Json.JsonSerializer.Deserialize<SiemDashboard>(System.IO.File.ReadAllText(dlg.FileName));
                if (doc is null || doc.Tiles is null) { MessageBox.Show(Window.GetWindow(this), "Not a valid dashboard file.", "Import failed", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
                doc.Name = UniqueDashName(string.IsNullOrWhiteSpace(doc.Name) ? "Imported" : doc.Name);
                _dashDoc.Dashboards.Add(doc);
                SwitchDashboard(doc);
                SiemAudit.Instance.Log("Dashboard", "Imported dashboard", $"{doc.Name} ({doc.Tiles.Count} tiles)");
                ShowToastText("Dashboard imported", $"“{doc.Name}” added with {doc.Tiles.Count} tile(s).");
            }
            catch (Exception ex) { MessageBox.Show(Window.GetWindow(this), ex.Message, "Import failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }

        private string UniqueDashName(string name, SiemDashboard? self = null)
        {
            name = name.Trim();
            bool Taken(string n) => _dashDoc.Dashboards.Any(d => !ReferenceEquals(d, self) && string.Equals(d.Name, n, StringComparison.OrdinalIgnoreCase));
            if (!Taken(name)) return name;
            for (int i = 2; ; i++) { var cand = $"{name} ({i})"; if (!Taken(cand)) return cand; }
        }
    }
}
