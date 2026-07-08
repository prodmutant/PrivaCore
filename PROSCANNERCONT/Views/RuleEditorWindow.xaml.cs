using System;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Views
{
    public partial class RuleEditorWindow : Window
    {
        public IDSRule? Result { get; private set; }
        private readonly IDSRule? _editing;

        public RuleEditorWindow(IDSRule? existing = null)
        {
            InitializeComponent();
            _editing = existing;

            if (existing != null)
            {
                TitleText.Text = "Edit Rule";
                RuleIdBox.Text   = existing.RuleId;
                NameBox.Text     = existing.Name;
                DescBox.Text     = existing.Description;
                SrcIpBox.Text    = existing.SourceIP      ?? "any";
                SrcPortBox.Text  = existing.SourcePort    ?? "any";
                DstIpBox.Text    = existing.DestinationIP ?? "any";
                DstPortBox.Text  = existing.DestinationPort ?? "any";
                PatternBox.Text  = existing.Pattern       ?? "";
                CategoryBox.Text = existing.AttackCategory ?? "";
                MinSizeBox.Text  = existing.MinPacketSize.ToString();
                MaxSizeBox.Text  = existing.MaxPacketSize.ToString();
                NullFlagsBox.IsChecked = existing.RequireNullFlags;
                XmasFlagsBox.IsChecked = existing.RequireXmasFlags;
                SelectCombo(SeverityBox, existing.Severity.ToString());
                SelectCombo(ProtoBox, string.IsNullOrEmpty(existing.Protocol) ? "any" : existing.Protocol);
                SelectCombo(RuleKindBox, existing.RuleKind.ToString());
            }
            else
            {
                RuleIdBox.Text = $"CUSTOM-{DateTime.Now:HHmmss}";
            }
        }

        private void SelectCombo(System.Windows.Controls.ComboBox box, string value)
        {
            foreach (System.Windows.Controls.ComboBoxItem item in box.Items)
                if (item.Content?.ToString()?.Equals(value, StringComparison.OrdinalIgnoreCase) == true)
                { box.SelectedItem = item; return; }
        }

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed) DragMove();
        }

        private void TestPattern_Click(object sender, RoutedEventArgs e)
        {
            var pattern = PatternBox.Text.Trim();
            if (string.IsNullOrEmpty(pattern))
            {
                PatternTestResult.Text = "Enter a pattern first.";
                PatternTestResult.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255,193,7));
                PatternTestResult.Visibility = Visibility.Visible;
                return;
            }
            try
            {
                var rx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
                PatternTestResult.Text = $"✓  Valid regex — matches: {(rx.IsMatch("test payload GET /admin HTTP/1.1") ? "sample payload" : "not sample payload")}";
                PatternTestResult.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(78,201,176));
                PatternTestResult.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                PatternTestResult.Text = $"✗  Invalid regex: {ex.Message}";
                PatternTestResult.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(244,71,71));
                PatternTestResult.Visibility = Visibility.Visible;
            }
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            ErrorText.Text = "";

            if (string.IsNullOrWhiteSpace(RuleIdBox.Text))  { ErrorText.Text = "Rule ID is required."; return; }
            if (string.IsNullOrWhiteSpace(NameBox.Text))     { ErrorText.Text = "Name is required."; return; }
            if (!int.TryParse(MinSizeBox.Text, out int minSz) || minSz < 0) { ErrorText.Text = "Min size must be a non-negative integer."; return; }
            if (!int.TryParse(MaxSizeBox.Text, out int maxSz) || maxSz < 0) { ErrorText.Text = "Max size must be a non-negative integer."; return; }
            if (!string.IsNullOrEmpty(PatternBox.Text.Trim()))
            {
                try { _ = new Regex(PatternBox.Text.Trim()); }
                catch (Exception ex) { ErrorText.Text = $"Invalid regex pattern: {ex.Message}"; return; }
            }

            var severityStr = (SeverityBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "Medium";
            var proto       = (ProtoBox.SelectedItem    as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "any";
            var kindStr     = (RuleKindBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "Signature";

            Enum.TryParse<IDSAlertSeverity>(severityStr, out var severity);
            Enum.TryParse<RuleKind>(kindStr, out var kind);

            Result = new IDSRule
            {
                Id              = _editing?.Id ?? Guid.NewGuid(),
                RuleId          = RuleIdBox.Text.Trim(),
                Name            = NameBox.Text.Trim(),
                Description     = DescBox.Text.Trim(),
                IsEnabled       = _editing?.IsEnabled ?? true,
                Severity        = severity,
                Protocol        = proto,
                SourceIP        = string.IsNullOrWhiteSpace(SrcIpBox.Text)  ? "any" : SrcIpBox.Text.Trim(),
                SourcePort      = string.IsNullOrWhiteSpace(SrcPortBox.Text) ? "any" : SrcPortBox.Text.Trim(),
                DestinationIP   = string.IsNullOrWhiteSpace(DstIpBox.Text)  ? "any" : DstIpBox.Text.Trim(),
                DestinationPort = string.IsNullOrWhiteSpace(DstPortBox.Text) ? "any" : DstPortBox.Text.Trim(),
                Pattern         = PatternBox.Text.Trim(),
                AttackCategory  = CategoryBox.Text.Trim(),
                MinPacketSize   = minSz,
                MaxPacketSize   = maxSz,
                RequireNullFlags = NullFlagsBox.IsChecked == true,
                RequireXmasFlags = XmasFlagsBox.IsChecked == true,
                RuleKind        = kind,
                TriggerCount    = _editing?.TriggerCount ?? 0,
                LastTriggered   = _editing?.LastTriggered ?? DateTime.MinValue,
                CreatedDate     = _editing?.CreatedDate  ?? DateTime.Now,
                ModifiedDate    = DateTime.Now
            };

            DialogResult = true;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    }
}
