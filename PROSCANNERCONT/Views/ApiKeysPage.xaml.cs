using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// Central, secure manager for every third-party API key the app can use. Each key is stored via
    /// <see cref="SecretsManager"/> (DPAPI-encrypted at rest, current-user scope). Saved values are never
    /// displayed back — only a "Configured / Not set" status — matching how the rest of the app treats secrets.
    /// </summary>
    public partial class ApiKeysPage : Page
    {
        private sealed record KeyDef(string Key, string Title, string Description);

        private static readonly KeyDef[] Keys =
        {
            new(SecretsManager.KeyNvdApiKey,       "NVD (National Vulnerability Database)",
                "Higher CVE-lookup rate limits for the Port & Vulnerability Scanner. Free key from nvd.nist.gov/developers."),
            new(SecretsManager.KeyOpenAiApiKey,    "OpenAI",
                "Powers the optional AI security assistant and CVE service-name normalization."),
            new(SecretsManager.KeyAnthropicApiKey, "Anthropic (Claude)",
                "Alternative provider for the optional AI security assistant."),
            new(SecretsManager.KeyShodanApiKey,    "Shodan",
                "Host/service intelligence enrichment during discovery and scanning."),
            new(SecretsManager.KeyCensysApiId,     "Censys — API ID",
                "Censys host/certificate lookups (used together with the API secret below)."),
            new(SecretsManager.KeyCensysApiSecret, "Censys — API Secret",
                "The secret paired with the Censys API ID above."),
            new(SecretsManager.KeyVirusTotalKey,   "VirusTotal",
                "File/URL/IP reputation lookups for threat enrichment."),
            new(SecretsManager.KeyOtxApiKey,       "AlienVault OTX",
                "Open Threat Exchange indicator feeds for enrichment."),
        };

        public ApiKeysPage()
        {
            InitializeComponent();
            BuildRows();
        }

        private void BuildRows()
        {
            KeysHost.Children.Clear();
            foreach (var def in Keys)
                KeysHost.Children.Add(BuildRow(def));
        }

        private Border BuildRow(KeyDef def)
        {
            var card = new Border
            {
                Style = (Style)FindResource("CardStyle"),
                Padding = new Thickness(18),
                Margin = new Thickness(0, 0, 0, 12)
            };

            var outer = new StackPanel();

            outer.Children.Add(new TextBlock
            {
                Text = def.Title,
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brush("TextBrush")
            });
            outer.Children.Add(new TextBlock
            {
                Text = def.Description,
                FontSize = 12,
                Foreground = Brush("SubtleTextBrush"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 3, 0, 10)
            });

            var status = new TextBlock
            {
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0, 0, 0)
            };
            SetStatus(status, SecretsManager.Has(def.Key));

            var pwd = new PasswordBox
            {
                Style = (Style)FindResource("PasswordBoxStyle"),
                Width = 340,
                Height = 38,
                VerticalAlignment = VerticalAlignment.Center
            };

            var save = new Button
            {
                Content = "Save",
                Style = (Style)FindResource("AccentButtonStyle"),
                MinWidth = 76,
                Margin = new Thickness(8, 0, 0, 0)
            };
            save.Click += (_, __) =>
            {
                var value = pwd.Password?.Trim() ?? "";
                if (value.Length == 0)
                {
                    AppDialog.Show("Enter a key value before saving.", "Nothing to save",
                                   MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                SecretsManager.Set(def.Key, value);
                pwd.Clear();
                SetStatus(status, true);
                AppDialog.Show($"{def.Title} key saved securely.", "Saved",
                               MessageBoxButton.OK, MessageBoxImage.Information);
            };

            var clear = new Button
            {
                Content = "Clear",
                Style = (Style)FindResource("GhostButtonStyle"),
                MinWidth = 76,
                Margin = new Thickness(8, 0, 0, 0)
            };
            clear.Click += (_, __) =>
            {
                if (!SecretsManager.Has(def.Key)) { pwd.Clear(); return; }
                var confirm = AppDialog.Show($"Remove the saved {def.Title} key?", "Remove key",
                                             MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;
                SecretsManager.Set(def.Key, "");
                pwd.Clear();
                SetStatus(status, false);
            };

            var row = new StackPanel { Orientation = Orientation.Horizontal };
            row.Children.Add(pwd);
            row.Children.Add(save);
            row.Children.Add(clear);
            row.Children.Add(status);

            outer.Children.Add(row);
            card.Child = outer;
            return card;
        }

        private void SetStatus(TextBlock status, bool configured)
        {
            status.Text = configured ? "● Configured" : "○ Not set";
            status.Foreground = configured ? Brush("SuccessBrush") : Brush("SubtleTextBrush");
        }

        private Brush Brush(string key) =>
            (Application.Current.Resources[key] as Brush) ?? Brushes.Gray;
    }
}
