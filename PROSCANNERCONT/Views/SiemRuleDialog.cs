using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// A themed modal to add / edit one SIEM detection rule (query + threshold + window + group +
    /// severity + MITRE). Built in code so it links cleanly into the standalone SIEM app.
    /// </summary>
    public sealed class SiemRuleDialog : Window
    {
        private readonly SiemRule _r;
        private readonly TextBox _name = new();
        private readonly TextBox _query = new();
        private readonly ComboBox _type = new();
        private readonly TextBox _threshold = new();
        private readonly TextBox _window = new();
        private readonly TextBox _groupBy = new();
        private readonly ComboBox _severity = new();
        private readonly TextBox _mitreId = new();
        private readonly TextBox _mitreName = new();
        private readonly ComboBox _mitreTactic = new();
        private readonly TextBox _webhook = new();
        private readonly TextBox _emailTo = new();
        private readonly TextBox _risk = new();
        private readonly TextBox _suppress = new();
        private readonly TextBox _second = new();
        private readonly TextBox _exclude = new();
        private readonly TextBox _baseline = new();
        private readonly TextBox _maxSpan = new();
        private readonly StackPanel _groupRow = new();
        private readonly StackPanel _secondRow = new();
        private readonly StackPanel _baselineRow = new();

        private SiemRuleDialog(Window? owner, SiemRule r)
        {
            _r = r;
            if (owner != null) Owner = owner;
            Title = "Detection rule";
            Width = 520; SizeToContent = SizeToContent.Height;
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.ToolWindow;
            ResizeMode = ResizeMode.NoResize;
            Background = (Brush)FindResource("BackgroundBrush");

            var root = new StackPanel { Margin = new Thickness(22) };

            root.Children.Add(Label("RULE NAME"));
            Style(_name); _name.Text = r.Name;
            root.Children.Add(_name);

            root.Children.Add(Label("QUERY  (e.g.  event.action:logon event.outcome:failure)"));
            Style(_query); _query.Text = r.Query;
            root.Children.Add(_query);
            root.Children.Add(Hint("Same syntax as Discover. Leave empty to match every event."));

            // type + threshold + window row
            root.Children.Add(Label("CONDITION"));
            var cond = new Grid();
            cond.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.4, GridUnitType.Star) });
            cond.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            cond.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            foreach (SiemRuleType t in Enum.GetValues(typeof(SiemRuleType))) _type.Items.Add(t);
            Style(_type); _type.SelectedItem = r.Type; _type.Margin = new Thickness(0, 0, 8, 0);
            _type.SelectionChanged += (_, _) => UpdateGroupVisibility();
            Grid.SetColumn(_type, 0); cond.Children.Add(_type);
            Style(_threshold); _threshold.Text = r.Threshold.ToString(); _threshold.Margin = new Thickness(0, 0, 8, 0);
            _threshold.ToolTip = "Threshold count"; Grid.SetColumn(_threshold, 1); cond.Children.Add(_threshold);
            Style(_window); _window.Text = r.WindowMinutes.ToString(); _window.ToolTip = "Window (minutes)";
            Grid.SetColumn(_window, 2); cond.Children.Add(_window);
            root.Children.Add(cond);
            root.Children.Add(Hint("Threshold = how many events trip the rule (for Anomaly: σ above baseline);  Window = minutes to count over."));

            // baseline windows (only for Anomaly)
            _baselineRow.Children.Add(Label("BASELINE WINDOWS  (anomaly — how many prior windows form the baseline)"));
            Style(_baseline); _baseline.Text = r.BaselineWindows.ToString(); _baseline.ToolTip = "e.g. 12 windows of history to learn the normal rate";
            _baselineRow.Children.Add(_baseline);
            _baselineRow.Children.Add(Hint("The rule fires when the current window's rate exceeds mean + Threshold·σ of these prior windows."));
            root.Children.Add(_baselineRow);

            // second query (only for Sequence) — the "then" step
            _secondRow.Children.Add(Label("THEN  (sequence step B — e.g.  event.outcome:success)"));
            Style(_second); _second.Text = r.SecondQuery;
            _secondRow.Children.Add(_second);
            _secondRow.Children.Add(Hint("Fires when ≥Threshold of the first query are followed by a step-B event from the same group."));
            _secondRow.Children.Add(Label("MAX SPAN  (minutes from step-A to step-B; 0 = anywhere in the window)"));
            Style(_maxSpan); _maxSpan.Text = r.MaxSpanMinutes.ToString(); _maxSpan.ToolTip = "EQL maxspan — step-B must occur this many minutes after the first step-A";
            _secondRow.Children.Add(_maxSpan);
            root.Children.Add(_secondRow);

            // group-by (GroupThreshold / NewTerms / Sequence / Anomaly / IndicatorMatch)
            _groupRow.Children.Add(Label("GROUP BY FIELD  (e.g.  source.ip  —  or several:  source.ip,user.name)"));
            Style(_groupBy); _groupBy.Text = r.GroupBy;
            _groupRow.Children.Add(_groupBy);
            _groupRow.Children.Add(Hint("Counts per distinct value — fires when any one value crosses the threshold. Comma-separate fields for a composite key (all must be present)."));
            root.Children.Add(_groupRow);

            root.Children.Add(Label("EXCEPTION  (optional — matching events are ignored, e.g.  user.name:svc_backup)"));
            Style(_exclude); _exclude.Text = r.ExcludeQuery; _exclude.ToolTip = "Allowlist: events matching this query never trip the rule";
            root.Children.Add(_exclude);

            root.Children.Add(Label("ALERT SEVERITY"));
            foreach (SiemSeverity s in Enum.GetValues(typeof(SiemSeverity))) _severity.Items.Add(s);
            Style(_severity); _severity.SelectedItem = r.Severity;
            root.Children.Add(_severity);

            // risk score + suppression row
            root.Children.Add(Label("RISK SCORE & SUPPRESSION"));
            var rs = new Grid();
            rs.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            rs.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Style(_risk); _risk.Text = r.RiskScore > 0 ? r.RiskScore.ToString() : ""; _risk.Margin = new Thickness(0, 0, 8, 0); _risk.ToolTip = "Risk score 0-100 (blank = derive from severity)";
            Grid.SetColumn(_risk, 0); rs.Children.Add(_risk);
            Style(_suppress); _suppress.Text = r.SuppressMinutes > 0 ? r.SuppressMinutes.ToString() : ""; _suppress.ToolTip = "Suppress duplicate alerts per group for N minutes (blank = use the window)";
            Grid.SetColumn(_suppress, 1); rs.Children.Add(_suppress);
            root.Children.Add(rs);
            root.Children.Add(Hint("Risk score 0-100 (blank = from severity);  Suppress = minutes to dedupe repeat alerts per group."));

            // MITRE
            root.Children.Add(Label("MITRE ATT&CK  (optional — technique id + name)"));
            var mitre = new Grid();
            mitre.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            mitre.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
            Style(_mitreId); _mitreId.Text = r.MitreId; _mitreId.Margin = new Thickness(0, 0, 8, 0); _mitreId.ToolTip = "e.g. T1110";
            Grid.SetColumn(_mitreId, 0); mitre.Children.Add(_mitreId);
            Style(_mitreName); _mitreName.Text = r.MitreName; _mitreName.ToolTip = "e.g. Brute Force";
            Grid.SetColumn(_mitreName, 1); mitre.Children.Add(_mitreName);
            root.Children.Add(mitre);

            root.Children.Add(Label("MITRE TACTIC"));
            Style(_mitreTactic);
            _mitreTactic.Items.Add("(none)");
            foreach (var t in SiemMitre.Tactics) _mitreTactic.Items.Add(t);
            _mitreTactic.SelectedItem = string.IsNullOrEmpty(r.MitreTactic) ? "(none)" : r.MitreTactic;
            if (_mitreTactic.SelectedItem == null) _mitreTactic.SelectedIndex = 0;
            root.Children.Add(_mitreTactic);

            root.Children.Add(Label("WEBHOOK URL  (optional — POST the alert here on fire)"));
            Style(_webhook); _webhook.Text = r.WebhookUrl; _webhook.ToolTip = "Slack / Teams / generic JSON webhook";
            root.Children.Add(_webhook);

            root.Children.Add(Label("EMAIL TO  (optional — comma-separated; needs SMTP set on Sources & Agents)"));
            Style(_emailTo); _emailTo.Text = r.EmailTo; _emailTo.ToolTip = "Email the alert to these recipients when it fires";
            root.Children.Add(_emailTo);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 22, 0, 0) };
            var preview = new Button { Content = "Preview (24h)", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 110, ToolTip = "Backtest this rule against the last 24h of stored events — no alerts raised" };
            preview.Click += Preview_Click;
            var cancel = new Button { Content = "Cancel", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 90 };
            cancel.Click += (_, _) => { DialogResult = false; };
            var ok = new Button { Content = "Save rule", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 110 };
            ok.Click += Ok_Click;
            buttons.Children.Add(preview); buttons.Children.Add(cancel); buttons.Children.Add(ok);
            root.Children.Add(buttons);

            Content = root;
            UpdateGroupVisibility();
        }

        private TextBlock Label(string text) => new()
        {
            Text = text, FontSize = 10, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 12, 0, 4),
        };

        private TextBlock Hint(string text) => new()
        {
            Text = text, FontSize = 10, Foreground = (Brush)FindResource("SubtleTextBrush"),
            Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap,
        };

        private void Style(Control c)
        {
            if (c is ComboBox) c.Style = (Style)FindResource("ComboBoxStyle");
            else if (c is TextBox) c.Style = (Style)FindResource("InputBoxStyle");
        }

        private void UpdateGroupVisibility()
        {
            var t = (SiemRuleType)_type.SelectedItem;
            _groupRow.Visibility = t is SiemRuleType.GroupThreshold or SiemRuleType.NewTerms or SiemRuleType.Sequence or SiemRuleType.Anomaly or SiemRuleType.IndicatorMatch ? Visibility.Visible : Visibility.Collapsed;
            _secondRow.Visibility = t == SiemRuleType.Sequence ? Visibility.Visible : Visibility.Collapsed;
            _baselineRow.Visibility = t == SiemRuleType.Anomaly ? Visibility.Visible : Visibility.Collapsed;
        }

        /// <summary>Copy the current field values onto a rule (shared by Save and Preview).</summary>
        private void ApplyFields(SiemRule t)
        {
            t.Name = _name.Text.Trim();
            t.Query = _query.Text.Trim();
            t.Type = (SiemRuleType)_type.SelectedItem;
            t.Threshold = int.TryParse(_threshold.Text.Trim(), out var th) ? Math.Max(1, th) : 10;
            t.WindowMinutes = int.TryParse(_window.Text.Trim(), out var w) ? Math.Max(1, w) : 5;
            t.GroupBy = _groupBy.Text.Trim();
            t.Severity = (SiemSeverity)_severity.SelectedItem;
            t.MitreId = _mitreId.Text.Trim();
            t.MitreName = _mitreName.Text.Trim();
            t.MitreTactic = _mitreTactic.SelectedItem as string is { } tac && tac != "(none)" ? tac : "";
            t.WebhookUrl = _webhook.Text.Trim();
            t.EmailTo = _emailTo.Text.Trim();
            t.RiskScore = int.TryParse(_risk.Text.Trim(), out var rk) ? Math.Clamp(rk, 0, 100) : 0;
            t.SuppressMinutes = int.TryParse(_suppress.Text.Trim(), out var sp) ? Math.Max(0, sp) : 0;
            t.BaselineWindows = int.TryParse(_baseline.Text.Trim(), out var bw) ? Math.Max(3, bw) : 12;
            t.SecondQuery = _second.Text.Trim();
            t.MaxSpanMinutes = int.TryParse(_maxSpan.Text.Trim(), out var ms) ? Math.Max(0, ms) : 0;
            t.ExcludeQuery = _exclude.Text.Trim();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_name.Text)) { _name.Focus(); return; }
            ApplyFields(_r);
            DialogResult = true;
        }

        private void Preview_Click(object sender, RoutedEventArgs e)
        {
            var probe = new SiemRule();
            ApplyFields(probe);
            if (string.IsNullOrWhiteSpace(probe.Name)) probe.Name = "(unsaved rule)";
            const int lookback = 1440;   // last 24h of stored events
            var hits = PROSCANNERCONT.Services.Siem.SiemRuleEngine.Instance.Preview(probe, lookback);
            ShowPreviewResults(probe, hits, lookback);
        }

        private void ShowPreviewResults(SiemRule rule, System.Collections.Generic.List<PROSCANNERCONT.Services.Siem.SiemPreviewHit> hits, int lookbackMinutes)
        {
            var win = new Window
            {
                Title = "Rule preview", Owner = this, Width = 520, SizeToContent = SizeToContent.Height, MaxHeight = 560,
                WindowStartupLocation = WindowStartupLocation.CenterOwner, WindowStyle = WindowStyle.ToolWindow,
                ResizeMode = ResizeMode.NoResize, Background = (Brush)FindResource("BackgroundBrush"),
            };
            var sp = new StackPanel { Margin = new Thickness(20) };
            int totalEvents = 0; foreach (var h in hits) totalEvents += h.Count;
            string hours = (lookbackMinutes / 60) + "h";
            sp.Children.Add(new TextBlock
            {
                Text = hits.Count == 0 ? $"This rule would NOT have fired over the last {hours} of stored events."
                                       : $"This rule would have fired {hits.Count} time(s) over the last {hours} (≈{totalEvents:N0} matching event(s)).",
                FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource(hits.Count == 0 ? "SubtleTextBrush" : "TextBrush"),
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4),
            });
            sp.Children.Add(new TextBlock { Text = "Backtest over events already in the index — no alerts are raised.", FontSize = 10, Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 12) });

            if (hits.Count > 0)
            {
                var list = new StackPanel();
                foreach (var h in hits)
                    list.Children.Add(new TextBlock { Text = "•  " + h.Message, Foreground = (Brush)FindResource("TextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) });
                sp.Children.Add(new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = 360, Content = list });
            }

            var close = new Button { Content = "Close", Style = (Style)FindResource("AccentButtonStyle"), Height = 32, MinWidth = 90, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) };
            close.Click += (_, _) => win.Close();
            sp.Children.Add(close);
            win.Content = sp;
            win.ShowDialog();
        }

        public static bool Edit(Window? owner, SiemRule r)
            => new SiemRuleDialog(owner, r).ShowDialog() == true;
    }
}
