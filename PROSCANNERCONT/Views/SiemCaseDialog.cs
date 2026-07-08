using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Views
{
    /// <summary>A themed modal to create / edit a SOC case (title, description, severity, status).</summary>
    public sealed class SiemCaseDialog : Window
    {
        private readonly SiemCase _c;
        private readonly TextBox _title = new();
        private readonly TextBox _desc = new();
        private readonly ComboBox _sev = new();
        private readonly ComboBox _status = new();

        private SiemCaseDialog(Window? owner, SiemCase c)
        {
            _c = c;
            if (owner != null) Owner = owner;
            Title = "Case";
            Width = 480; SizeToContent = SizeToContent.Height;
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.ToolWindow;
            ResizeMode = ResizeMode.NoResize;
            Background = (Brush)FindResource("BackgroundBrush");

            var root = new StackPanel { Margin = new Thickness(22) };

            root.Children.Add(Label("TITLE"));
            _title.Style = (Style)FindResource("InputBoxStyle"); _title.Text = c.Title;
            root.Children.Add(_title);

            root.Children.Add(Label("DESCRIPTION"));
            _desc.Style = (Style)FindResource("InputBoxStyle");
            _desc.Text = c.Description; _desc.AcceptsReturn = true; _desc.TextWrapping = TextWrapping.Wrap;
            _desc.MinHeight = 80; _desc.VerticalContentAlignment = VerticalAlignment.Top;
            _desc.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            root.Children.Add(_desc);

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var sevSp = new StackPanel { Margin = new Thickness(0, 0, 8, 0) };
            sevSp.Children.Add(Label("SEVERITY"));
            foreach (SiemSeverity s in Enum.GetValues(typeof(SiemSeverity))) _sev.Items.Add(s);
            _sev.Style = (Style)FindResource("ComboBoxStyle"); _sev.SelectedItem = c.Severity;
            sevSp.Children.Add(_sev);
            Grid.SetColumn(sevSp, 0); grid.Children.Add(sevSp);
            var stSp = new StackPanel();
            stSp.Children.Add(Label("STATUS"));
            foreach (SiemCaseStatus s in Enum.GetValues(typeof(SiemCaseStatus))) _status.Items.Add(s);
            _status.Style = (Style)FindResource("ComboBoxStyle"); _status.SelectedItem = c.Status;
            stSp.Children.Add(_status);
            Grid.SetColumn(stSp, 1); grid.Children.Add(stSp);
            root.Children.Add(grid);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
            var cancel = new Button { Content = "Cancel", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 90 };
            cancel.Click += (_, _) => { DialogResult = false; };
            var ok = new Button { Content = "Save case", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 110 };
            ok.Click += Ok_Click;
            buttons.Children.Add(cancel); buttons.Children.Add(ok);
            root.Children.Add(buttons);

            Content = root;
            Loaded += (_, _) => { _title.Focus(); _title.SelectAll(); };
        }

        private TextBlock Label(string text) => new()
        {
            Text = text, FontSize = 10, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 12, 0, 4),
        };

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_title.Text)) { _title.Focus(); return; }
            _c.Title = _title.Text.Trim();
            _c.Description = _desc.Text.Trim();
            _c.Severity = (SiemSeverity)_sev.SelectedItem;
            _c.Status = (SiemCaseStatus)_status.SelectedItem;
            DialogResult = true;
        }

        public static bool Edit(Window? owner, SiemCase c)
            => new SiemCaseDialog(owner, c).ShowDialog() == true;
    }
}
