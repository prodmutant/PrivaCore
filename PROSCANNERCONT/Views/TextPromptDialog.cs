using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// A small themed single-line input dialog (e.g. "name this saved search"). Built in code so it
    /// links cleanly into the standalone SIEM app. Returns the entered text, or null if cancelled.
    /// </summary>
    public sealed class TextPromptDialog : Window
    {
        private readonly TextBox _input = new();

        private TextPromptDialog(Window? owner, string title, string label, string initial, string okText)
        {
            if (owner != null) Owner = owner;
            Title = title;
            Width = 440; SizeToContent = SizeToContent.Height;
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.ToolWindow;
            ResizeMode = ResizeMode.NoResize;
            Background = (Brush)FindResource("BackgroundBrush");

            var root = new StackPanel { Margin = new Thickness(22) };
            root.Children.Add(new TextBlock
            {
                Text = label, FontSize = 10, FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("SubtleTextBrush"), Margin = new Thickness(0, 0, 0, 6),
            });
            _input.Style = (Style)FindResource("InputBoxStyle");
            _input.Text = initial;
            _input.KeyDown += (_, e) => { if (e.Key == Key.Enter) Ok(); };
            root.Children.Add(_input);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
            var cancel = new Button { Content = "Cancel", Style = (Style)FindResource("GhostButtonStyle"), Height = 34, Margin = new Thickness(0, 0, 8, 0), MinWidth = 90 };
            cancel.Click += (_, _) => { DialogResult = false; };
            var ok = new Button { Content = okText, Style = (Style)FindResource("AccentButtonStyle"), Height = 34, MinWidth = 110 };
            ok.Click += (_, _) => Ok();
            buttons.Children.Add(cancel); buttons.Children.Add(ok);
            root.Children.Add(buttons);

            Content = root;
            Loaded += (_, _) => { _input.Focus(); _input.SelectAll(); };
        }

        private void Ok()
        {
            if (string.IsNullOrWhiteSpace(_input.Text)) return;
            DialogResult = true;
        }

        /// <summary>Show the prompt. Returns the trimmed text, or null if cancelled / empty.</summary>
        public static string? Ask(Window? owner, string title, string label, string initial = "", string okText = "Save")
        {
            var dlg = new TextPromptDialog(owner, title, label, initial, okText);
            return dlg.ShowDialog() == true ? dlg._input.Text.Trim() : null;
        }
    }
}
