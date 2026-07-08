using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// A small themed modal for adding/editing one SIEM pipeline stage. Built in code so it
    /// links cleanly into the standalone SIEM app alongside the dashboard.
    /// </summary>
    public sealed class PipelineStageDialog : Window
    {
        private readonly SiemProcessor _p;
        private readonly ComboBox _type = new();
        private readonly ComboBox _field = new();
        private readonly TextBox _value = new();
        private readonly TextBox _arg = new();
        private readonly TextBlock _argLabel = new();
        private readonly StackPanel _argRow = new();
        private readonly TextBox _field2 = new();
        private readonly TextBlock _field2Label = new();
        private readonly StackPanel _field2Row = new();

        private PipelineStageDialog(Window owner, SiemProcessor p)
        {
            _p = p;
            Owner = owner;
            Title = "Pipeline stage";
            Width = 460; SizeToContent = SizeToContent.Height;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            WindowStyle = WindowStyle.ToolWindow;
            ResizeMode = ResizeMode.NoResize;
            Background = (Brush)FindResource("BackgroundBrush");

            var root = new StackPanel { Margin = new Thickness(22) };

            root.Children.Add(Label("ACTION"));
            foreach (SiemProcessorType t in Enum.GetValues(typeof(SiemProcessorType))) _type.Items.Add(t);
            Style(_type); _type.SelectedItem = p.Type;
            _type.SelectionChanged += (_, _) => UpdateArgVisibility();
            root.Children.Add(_type);

            root.Children.Add(Label("WHERE"));
            var where = new Grid { Margin = new Thickness(0, 0, 0, 0) };
            where.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
            where.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            foreach (SiemMatchField f in Enum.GetValues(typeof(SiemMatchField))) _field.Items.Add(f);
            Style(_field); _field.SelectedItem = p.MatchField; _field.Margin = new Thickness(0, 0, 8, 0);
            Grid.SetColumn(_field, 0); where.Children.Add(_field);
            Style(_value); _value.Text = p.MatchValue;
            _value.SetValue(System.Windows.Controls.Primitives.TextBoxBase.AcceptsReturnProperty, false);
            Grid.SetColumn(_value, 1); where.Children.Add(_value);
            root.Children.Add(where);
            root.Children.Add(new TextBlock { Text = "Substring match (case-insensitive). Leave the value empty to match every event. Choose “Query” to use a full KQL expression (AND/OR/NOT, ranges, wildcards, CIDR) — enables real conditional branching/routing.", FontSize = 10, Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap });

            _field2Label.Text = "FIELD";
            _field2Row.Children.Add(_field2Label);
            Style(_field2); _field2.Text = p.Field;
            _field2Row.Children.Add(_field2);
            root.Children.Add(_field2Row);

            _argLabel.Text = "VALUE";
            _argRow.Children.Add(_argLabel);
            Style(_arg); _arg.Text = p.Arg;
            _argRow.Children.Add(_arg);
            root.Children.Add(_argRow);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
            var cancel = new Button { Content = "Cancel", Style = (System.Windows.Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 90 };
            cancel.Click += (_, _) => { DialogResult = false; };
            var ok = new Button { Content = "Save stage", Style = (System.Windows.Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 110 };
            ok.Click += Ok_Click;
            buttons.Children.Add(cancel); buttons.Children.Add(ok);
            root.Children.Add(buttons);

            Content = root;
            UpdateArgVisibility();
        }

        private TextBlock Label(string text) => new()
        {
            Text = text, FontSize = 10, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 12, 0, 4),
        };

        private void Style(Control c)
        {
            if (c is ComboBox) c.Style = (System.Windows.Style)FindResource("ComboBoxStyle");
            else if (c is TextBox) c.Style = (System.Windows.Style)FindResource("InputBoxStyle");
        }

        private void UpdateArgVisibility()
        {
            var t = (SiemProcessorType)_type.SelectedItem;
            bool needsArg = t is SiemProcessorType.SetSeverity or SiemProcessorType.SetCategory or SiemProcessorType.AddTag
                            or SiemProcessorType.RenameSource or SiemProcessorType.ExtractRegex or SiemProcessorType.Grok or SiemProcessorType.RenameField
                            or SiemProcessorType.Dedupe or SiemProcessorType.IndicatorMatch or SiemProcessorType.ParseTimestamp
                            or SiemProcessorType.Enrich or SiemProcessorType.CallPipeline;
            _argRow.Visibility = needsArg ? Visibility.Visible : Visibility.Collapsed;
            _argLabel.Text = t switch
            {
                SiemProcessorType.SetSeverity => "NEW SEVERITY  (Info / Low / Medium / High / Critical)",
                SiemProcessorType.SetCategory => "NEW CATEGORY",
                SiemProcessorType.AddTag => "FIELD  (key=value)",
                SiemProcessorType.RenameSource => "NEW SOURCE NAME",
                SiemProcessorType.ExtractRegex => "REGEX  (use named groups e.g.  (?<user>\\w+))",
                SiemProcessorType.Grok => "GROK  (e.g.  %{IP:source.ip} - %{USER:user.name} \\[%{GREEDYDATA:msg}\\])",
                SiemProcessorType.RenameField => "NEW FIELD NAME",
                SiemProcessorType.Dedupe => "WINDOW  (seconds)",
                SiemProcessorType.IndicatorMatch => "INDICATORS  (known-bad values, comma/space separated)",
                SiemProcessorType.ParseTimestamp => "DATE FORMAT  (optional, e.g. yyyy-MM-dd HH:mm:ss)",
                SiemProcessorType.Enrich => "LOOKUP TABLE  (one per line:  key => field=value; field2=value2)",
                SiemProcessorType.CallPipeline => "PIPELINE NAME  (the named pipeline to route matching events to)",
                _ => "VALUE",
            };
            // multiline value box for table/regex stages
            bool multi = t is SiemProcessorType.Enrich or SiemProcessorType.IndicatorMatch;
            _arg.AcceptsReturn = multi;
            _arg.Height = multi ? 110 : double.NaN;
            _arg.TextWrapping = multi ? TextWrapping.Wrap : TextWrapping.NoWrap;
            _arg.VerticalScrollBarVisibility = multi ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden;

            bool needsField = t is SiemProcessorType.ExtractRegex or SiemProcessorType.Grok or SiemProcessorType.RenameField or SiemProcessorType.RemoveField
                              or SiemProcessorType.Lowercase or SiemProcessorType.Dedupe or SiemProcessorType.IndicatorMatch
                              or SiemProcessorType.ParseTimestamp or SiemProcessorType.GeoEnrich or SiemProcessorType.Enrich;
            _field2Row.Visibility = needsField ? Visibility.Visible : Visibility.Collapsed;
            _field2Label.Text = t switch
            {
                SiemProcessorType.ExtractRegex => "SOURCE FIELD  (blank = message)",
                SiemProcessorType.Grok => "SOURCE FIELD  (blank = message)",
                SiemProcessorType.RenameField => "FIELD TO RENAME",
                SiemProcessorType.RemoveField => "FIELD TO REMOVE",
                SiemProcessorType.Lowercase => "FIELD  (blank = message)",
                SiemProcessorType.Dedupe => "FINGERPRINT FIELD  (blank = message)",
                SiemProcessorType.IndicatorMatch => "FIELD TO CHECK  (blank = source/dest IP, user, hash)",
                SiemProcessorType.ParseTimestamp => "SOURCE FIELD  (blank = message)",
                SiemProcessorType.GeoEnrich => "IP FIELD  (blank = source.ip)",
                SiemProcessorType.Enrich => "KEY FIELD  (blank = host.name)",
                _ => "FIELD",
            };
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            _p.Type = (SiemProcessorType)_type.SelectedItem;
            _p.MatchField = (SiemMatchField)_field.SelectedItem;
            _p.MatchValue = _value.Text.Trim();
            _p.Arg = _p.Type is SiemProcessorType.ExtractRegex or SiemProcessorType.Grok or SiemProcessorType.Enrich or SiemProcessorType.IndicatorMatch ? _arg.Text : _arg.Text.Trim();
            _p.Field = _field2.Text.Trim();
            DialogResult = true;
        }

        public static bool Edit(Window owner, SiemProcessor p)
            => new PipelineStageDialog(owner, p).ShowDialog() == true;
    }
}
