using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// A themed "Visualize" builder (Kibana Lens-style): pick a field + aggregation + chart type to
    /// produce a config-driven dashboard tile. Built in code so it links into the standalone SIEM app.
    /// </summary>
    public sealed class SiemVizDialog : Window
    {
        private readonly SiemWidget _w;
        private readonly ComboBox _chart = new();
        private readonly ComboBox _agg = new();
        private readonly ComboBox _field = new();
        private readonly TextBox _topN = new();
        private readonly TextBox _title = new();
        private readonly StackPanel _fieldRow = new();
        private readonly StackPanel _aggRow = new();
        private readonly StackPanel _topRow = new();

        private SiemVizDialog(Window? owner, SiemWidget w, IEnumerable<string> fields)
        {
            _w = w;
            if (owner != null) Owner = owner;
            Title = "Visualize";
            Width = 480; SizeToContent = SizeToContent.Height;
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.ToolWindow;
            ResizeMode = ResizeMode.NoResize;
            Background = (Brush)FindResource("BackgroundBrush");

            var root = new StackPanel { Margin = new Thickness(22) };

            root.Children.Add(Label("CHART TYPE"));
            foreach (SiemChart c in Enum.GetValues(typeof(SiemChart))) _chart.Items.Add(c);
            Style(_chart); _chart.SelectedItem = w.Chart;
            _chart.SelectionChanged += (_, _) => UpdateVisibility();
            root.Children.Add(_chart);

            _aggRow.Children.Add(Label("AGGREGATION"));
            foreach (SiemAgg a in Enum.GetValues(typeof(SiemAgg))) _agg.Items.Add(a);
            Style(_agg); _agg.SelectedItem = w.Agg;
            _agg.SelectionChanged += (_, _) => UpdateVisibility();
            _aggRow.Children.Add(_agg);
            root.Children.Add(_aggRow);

            _fieldRow.Children.Add(Label("FIELD"));
            Style(_field); _field.IsEditable = true;
            foreach (var f in fields) _field.Items.Add(f);
            _field.Text = w.Field;
            _fieldRow.Children.Add(_field);
            _fieldRow.Children.Add(Hint("Pick from existing fields or type any ECS field (e.g. source.ip, network.bytes)."));
            root.Children.Add(_fieldRow);

            _topRow.Children.Add(Label("TOP N (bar / donut / table)"));
            Style(_topN); _topN.Text = w.TopN.ToString();
            _topRow.Children.Add(_topN);
            root.Children.Add(_topRow);

            root.Children.Add(Label("TITLE (optional)"));
            Style(_title); _title.Text = w.CustomTitle;
            root.Children.Add(_title);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 22, 0, 0) };
            var cancel = new Button { Content = "Cancel", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 90 };
            cancel.Click += (_, _) => { DialogResult = false; };
            var ok = new Button { Content = "Add visualization", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 140 };
            ok.Click += Ok_Click;
            buttons.Children.Add(cancel); buttons.Children.Add(ok);
            root.Children.Add(buttons);

            Content = root;
            UpdateVisibility();
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

        private void UpdateVisibility()
        {
            var chart = (SiemChart)_chart.SelectedItem;
            var agg = (SiemAgg)_agg.SelectedItem;
            // Metric/Gauge use an aggregation; bar/donut/table/treemap/heatmap group by a field. Line = events over time.
            _aggRow.Visibility = chart is SiemChart.Metric or SiemChart.Gauge ? Visibility.Visible : Visibility.Collapsed;
            bool needsField = chart is SiemChart.Bar or SiemChart.Donut or SiemChart.Table or SiemChart.Treemap or SiemChart.Heatmap
                              || (chart is SiemChart.Metric or SiemChart.Gauge && agg != SiemAgg.Count);
            _fieldRow.Visibility = needsField ? Visibility.Visible : Visibility.Collapsed;
            _topRow.Visibility = chart is SiemChart.Bar or SiemChart.Donut or SiemChart.Table or SiemChart.Treemap or SiemChart.Heatmap ? Visibility.Visible : Visibility.Collapsed;
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            _w.Type = SiemWidgetType.Custom;
            _w.Chart = (SiemChart)_chart.SelectedItem;
            _w.Agg = (SiemAgg)_agg.SelectedItem;
            _w.Field = (_field.Text ?? "").Trim();
            _w.TopN = int.TryParse(_topN.Text.Trim(), out var n) ? Math.Clamp(n, 2, 25) : 8;
            _w.CustomTitle = _title.Text.Trim();
            DialogResult = true;
        }

        public static bool Edit(Window? owner, SiemWidget w, IEnumerable<string> fields)
            => new SiemVizDialog(owner, w, fields).ShowDialog() == true;
    }
}
