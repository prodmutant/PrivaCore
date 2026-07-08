using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Views
{
    /// <summary>A themed editor for an agent's Fleet policy (heartbeat / demo generator / tail files).</summary>
    public sealed class SiemAgentPolicyDialog : Window
    {
        private readonly ToggleButton _heartbeat = new();
        private readonly TextBox _heartbeatSecs = new();
        private readonly ToggleButton _gen = new();
        private readonly TextBox _tail = new();

        public AgentPolicy Result { get; private set; } = new();

        private SiemAgentPolicyDialog(Window? owner, string agentName, AgentPolicy current)
        {
            if (owner != null) Owner = owner;
            Title = $"Policy — {agentName}";
            Width = 460; SizeToContent = SizeToContent.Height;
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.ToolWindow;
            ResizeMode = ResizeMode.NoResize;
            Background = (Brush)FindResource("BackgroundBrush");

            var root = new StackPanel { Margin = new Thickness(22) };
            root.Children.Add(new TextBlock { Text = $"Push configuration to “{agentName}”. The agent applies it live.", FontSize = 12, Foreground = (Brush)FindResource("SubtleTextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) });

            var hb = new DockPanel { Margin = new Thickness(0, 12, 0, 0) };
            _heartbeat.Style = (Style)FindResource("ToggleSwitchStyle"); _heartbeat.IsChecked = current.Heartbeat; _heartbeat.VerticalAlignment = VerticalAlignment.Center;
            DockPanel.SetDock(_heartbeat, Dock.Right); hb.Children.Add(_heartbeat);
            hb.Children.Add(new TextBlock { Text = "Heartbeat", Foreground = (Brush)FindResource("TextBrush"), FontSize = 13, VerticalAlignment = VerticalAlignment.Center });
            root.Children.Add(hb);

            root.Children.Add(Label("HEARTBEAT INTERVAL (seconds)"));
            _heartbeatSecs.Style = (Style)FindResource("InputBoxStyle"); _heartbeatSecs.Text = current.HeartbeatSeconds.ToString();
            root.Children.Add(_heartbeatSecs);

            var gn = new DockPanel { Margin = new Thickness(0, 14, 0, 0) };
            _gen.Style = (Style)FindResource("ToggleSwitchStyle"); _gen.IsChecked = current.DemoGenerator; _gen.VerticalAlignment = VerticalAlignment.Center;
            DockPanel.SetDock(_gen, Dock.Right); gn.Children.Add(_gen);
            gn.Children.Add(new TextBlock { Text = "Demo generator", Foreground = (Brush)FindResource("TextBrush"), FontSize = 13, VerticalAlignment = VerticalAlignment.Center });
            root.Children.Add(gn);

            root.Children.Add(Label("TAIL FILES  (comma-separated paths)"));
            _tail.Style = (Style)FindResource("InputBoxStyle"); _tail.Text = string.Join(", ", current.TailFiles);
            root.Children.Add(_tail);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
            var cancel = new Button { Content = "Cancel", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 90 };
            cancel.Click += (_, _) => { DialogResult = false; };
            var ok = new Button { Content = "Push policy", Style = (Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 120 };
            ok.Click += (_, _) =>
            {
                Result = new AgentPolicy
                {
                    Heartbeat = _heartbeat.IsChecked == true,
                    HeartbeatSeconds = int.TryParse(_heartbeatSecs.Text.Trim(), out var s) ? Math.Max(5, s) : 30,
                    DemoGenerator = _gen.IsChecked == true,
                    TailFiles = _tail.Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(),
                };
                DialogResult = true;
            };
            buttons.Children.Add(cancel); buttons.Children.Add(ok);
            root.Children.Add(buttons);

            Content = root;
        }

        private TextBlock Label(string text) => new()
        {
            Text = text, FontSize = 10, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 12, 0, 4),
        };

        public static AgentPolicy? Edit(Window? owner, string agentName, AgentPolicy current)
        {
            var dlg = new SiemAgentPolicyDialog(owner, agentName, current);
            return dlg.ShowDialog() == true ? dlg.Result : null;
        }
    }
}
