using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using PROSCANNERCONT.Managers;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class SettingsPage : Page
    {
        private string _activeTheme = "Phantom Dark";

        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PrivaCore", "appsettings.json");

        // Map theme name â†’ (card border, selection indicator border)
        private Dictionary<string, (Border card, Border indicator)> _cards;

        public SettingsPage()
        {
            InitializeComponent();
            Loaded += OnLoaded;
        }

        // â”€â”€ Load â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            _cards = new Dictionary<string, (Border, Border)>
            {
                ["Phantom Dark"]   = (Card_PhantomDark,   Sel_PhantomDark),
                ["Neon Terminal"]  = (Card_NeonTerminal,  Sel_NeonTerminal),
                ["Arctic"]         = (Card_Arctic,         Sel_Arctic),
                ["Midnight Ocean"] = (Card_MidnightOcean, Sel_MidnightOcean),
                ["Crimson Void"]   = (Card_CrimsonVoid,   Sel_CrimsonVoid),
                ["Carbon"]         = (Card_Carbon,         Sel_Carbon),
                ["Dracula"]        = (Card_Dracula,        Sel_Dracula),
                ["Solar Warm"]     = (Card_SolarWarm,      Sel_SolarWarm),
            };

            // Detect active theme by matching the current background brush
            var bg = (Application.Current.Resources["BackgroundBrush"] as SolidColorBrush)?.Color;
            foreach (var kv in ThemeManager.Themes)
            {
                try
                {
                    var themeBg = (Color)ColorConverter.ConvertFromString(kv.Value.Background);
                    if (bg.HasValue && bg.Value == themeBg) { _activeTheme = kv.Key; break; }
                }
                catch { }
            }

            HighlightCard(_activeTheme);
            UpdateColorPickers();
            LoadAppSettings();
        }

        // â”€â”€ Theme cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void ThemeCard_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border card && card.Tag is string themeName)
            {
                _activeTheme = themeName;
                ThemeManager.Apply(themeName);
                ThemeManager.SaveTheme(themeName);
                HighlightCard(themeName);
                UpdateColorPickers();
            }
        }

        private void HighlightCard(string themeName)
        {
            if (_cards == null) return;

            foreach (var kv in _cards)
            {
                bool active = kv.Key == themeName;
                kv.Value.indicator.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
                kv.Value.card.BorderThickness = active ? new Thickness(3) : new Thickness(2);
            }

            if (CurrentThemeLabel != null)
            {
                CurrentThemeLabel.Text = ThemeManager.Themes.TryGetValue(themeName, out var def)
                    ? $"Active: {themeName}  Â·  {def.PrimaryFont}  Â·  radius {def.CornerNormal}px"
                    : $"Active: {themeName}";
            }
        }

        // â”€â”€ Colour pickers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void UpdateColorPickers()
        {
            SafeSet(PrimaryBackgroundPicker,   "BackgroundBrush",          PrimaryBackgroundPreview);
            SafeSet(SecondaryBackgroundPicker, "SecondaryBackgroundBrush", SecondaryBackgroundPreview);
            SafeSet(AccentColorPicker,         "AccentBrush",              AccentColorPreview);
            SafeSet(AccentLightPicker,         "AccentLightBrush",         AccentLightPreview);
            SafeSet(TextColorPicker,           "TextBrush",                TextColorPreview);
            SafeSet(BorderColorPicker,         "BorderBrush",              BorderColorPreview);
            SafeSet(HoverColorPicker,          "HoverBrush",               HoverColorPreview);
            SafeSet(SelectionColorPicker,      "SelectionBrush",           SelectionColorPreview);
            SafeSet(SuccessColorPicker,        "SuccessBrush",             SuccessColorPreview);
            SafeSet(WarningColorPicker,        "WarningBrush",             WarningColorPreview);
            SafeSet(CriticalColorPicker,       "CriticalBrush",            CriticalColorPreview);
        }

        private static void SafeSet(TextBox box, string key, Border preview)
        {
            if (box == null || preview == null) return;
            if (Application.Current.Resources[key] is SolidColorBrush b)
            {
                box.Text = b.Color.ToString();
                preview.Background = b;
            }
        }

        private void ColorPicker_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (sender is not TextBox tb) return;
            try
            {
                var color = (Color)ColorConverter.ConvertFromString(tb.Text);
                var brush = new SolidColorBrush(color);
                // Map each picker to its preview swatch
                var map = new (TextBox picker, Border preview)[]
                {
                    (PrimaryBackgroundPicker,   PrimaryBackgroundPreview),
                    (SecondaryBackgroundPicker, SecondaryBackgroundPreview),
                    (AccentColorPicker,         AccentColorPreview),
                    (AccentLightPicker,         AccentLightPreview),
                    (TextColorPicker,           TextColorPreview),
                    (BorderColorPicker,         BorderColorPreview),
                    (HoverColorPicker,          HoverColorPreview),
                    (SelectionColorPicker,      SelectionColorPreview),
                    (SuccessColorPicker,        SuccessColorPreview),
                    (WarningColorPicker,        WarningColorPreview),
                    (CriticalColorPicker,       CriticalColorPreview),
                };
                foreach (var (picker, preview) in map)
                    if (tb == picker && preview != null) preview.Background = brush;
            }
            catch { }
        }

        private void ApplyCustomTheme_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var c = new CustomThemeColors
                {
                    Background          = ValidateHex(PrimaryBackgroundPicker?.Text)   ?? "#0D1117",
                    SecondaryBackground = ValidateHex(SecondaryBackgroundPicker?.Text) ?? "#161B22",
                    Accent              = ValidateHex(AccentColorPicker?.Text)         ?? "#58A6FF",
                    AccentLight         = ValidateHex(AccentLightPicker?.Text)         ?? "#79C0FF",
                    Text                = ValidateHex(TextColorPicker?.Text)           ?? "#E6EDF3",
                    Border              = ValidateHex(BorderColorPicker?.Text)         ?? "#30363D",
                    Hover               = ValidateHex(HoverColorPicker?.Text)          ?? "#21262D",
                    Selection           = ValidateHex(SelectionColorPicker?.Text)      ?? "#1F6FEB",
                    Success             = ValidateHex(SuccessColorPicker?.Text)        ?? "#3FB950",
                    Warning             = ValidateHex(WarningColorPicker?.Text)        ?? "#D29922",
                    Critical            = ValidateHex(CriticalColorPicker?.Text)       ?? "#F85149",
                };
                ThemeManager.ApplyCustomColors(c);
                ThemeManager.SaveTheme("Custom", c);
                HighlightCard(""); // deselect all cards
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Invalid colour value:\n{ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void ResetCustomTheme_Click(object sender, RoutedEventArgs e)
        {
            ThemeManager.Apply(_activeTheme);
            UpdateColorPickers();
        }

        // â”€â”€ Notification sound setting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        public static bool AlertSoundsEnabled { get; private set; } = true;

        private void AlertSounds_Changed(object sender, RoutedEventArgs e)
        {
            AlertSoundsEnabled = AlertSoundsCheckbox?.IsChecked == true;
            try
            {
                var settings = LoadOrCreateSettings();
                settings.AlertSoundsEnabled = AlertSoundsEnabled;
                SaveSettings(settings);
            }
            catch { }
        }

        // â”€â”€ AI assistant settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void AIProviderCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (AIProviderCombo?.SelectedItem is ComboBoxItem item)
                Services.AIProviderService.Set(item.Tag?.ToString() ?? "openai-gpt35");
            UpdateAIStatus();
        }

        private void OpenAIKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            UpdateAIStatus();
        }

        private void SaveAPIKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Persist API key to DPAPI-encrypted secrets store (not plaintext JSON).
                Services.SecretsManager.Set(Services.SecretsManager.KeyOpenAiApiKey,
                    OpenAIKeyBox?.Password ?? string.Empty);

                // Settings JSON now only tracks non-sensitive provider preference.
                var settings = LoadOrCreateSettings();
                settings.OpenAIKey = string.Empty; // never persist plaintext
                if (AIProviderCombo?.SelectedItem is ComboBoxItem item)
                    settings.AIProvider = item.Tag?.ToString() ?? "openai-gpt35";
                SaveSettings(settings);

                UpdateAIStatus();
                AppDialog.Show("API key saved securely (DPAPI encrypted).", "Saved",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Failed to save API key:\n{ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void UpdateAIStatus()
        {
            if (AIStatusDot == null || AIStatusLabel == null) return;

            bool hasKey = !string.IsNullOrWhiteSpace(OpenAIKeyBox?.Password)
                       || Services.SecretsManager.Has(Services.SecretsManager.KeyOpenAiApiKey);

            if (hasKey)
            {
                AIStatusDot.Fill   = Application.Current.Resources["SuccessBrush"] as SolidColorBrush
                                     ?? new SolidColorBrush(Colors.LimeGreen);
                AIStatusLabel.Text = "Configured";
            }
            else
            {
                AIStatusDot.Fill   = Application.Current.Resources["WarningBrush"] as SolidColorBrush
                                     ?? new SolidColorBrush(Colors.Orange);
                AIStatusLabel.Text = "No API key";
            }
        }

        // â”€â”€ App settings persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private void LoadAppSettings()
        {
            try
            {
                var settings = LoadOrCreateSettings();

                // Restore API key from secure store (one-shot migration from
                // any legacy plaintext value in settings JSON).
                if (OpenAIKeyBox != null)
                {
                    var stored = Services.SecretsManager.Get(Services.SecretsManager.KeyOpenAiApiKey);
                    if (string.IsNullOrEmpty(stored) && !string.IsNullOrEmpty(settings.OpenAIKey))
                    {
                        // Migrate plaintext key → DPAPI store, then strip from JSON.
                        Services.SecretsManager.Set(Services.SecretsManager.KeyOpenAiApiKey, settings.OpenAIKey);
                        stored = settings.OpenAIKey;
                        settings.OpenAIKey = string.Empty;
                        SaveSettings(settings);
                    }
                    if (!string.IsNullOrEmpty(stored)) OpenAIKeyBox.Password = stored;
                }

                // Restore checkboxes
                if (EnableAnimationsCheckbox != null) EnableAnimationsCheckbox.IsChecked = settings.EnableAnimations;
                if (ShowTooltipsCheckbox    != null) ShowTooltipsCheckbox.IsChecked    = settings.ShowTooltips;
                if (AutoSaveCheckbox        != null) AutoSaveCheckbox.IsChecked        = settings.AutoSave;
                if (ShowStatusBarCheckbox   != null) ShowStatusBarCheckbox.IsChecked   = settings.ShowStatusBar;
                if (AlertSoundsCheckbox     != null) AlertSoundsCheckbox.IsChecked     = settings.AlertSoundsEnabled;
                AlertSoundsEnabled = settings.AlertSoundsEnabled;

                // Restore provider combo
                if (AIProviderCombo != null && !string.IsNullOrEmpty(settings.AIProvider))
                {
                    foreach (ComboBoxItem item in AIProviderCombo.Items)
                    {
                        if (item.Tag?.ToString() == settings.AIProvider)
                        {
                            AIProviderCombo.SelectedItem = item;
                            break;
                        }
                    }
                }

                UpdateAIStatus();

                // Wire up checkbox auto-save
                if (EnableAnimationsCheckbox != null) EnableAnimationsCheckbox.Checked   += OnBehaviourChanged;
                if (EnableAnimationsCheckbox != null) EnableAnimationsCheckbox.Unchecked += OnBehaviourChanged;
                if (ShowTooltipsCheckbox    != null) ShowTooltipsCheckbox.Checked   += OnBehaviourChanged;
                if (ShowTooltipsCheckbox    != null) ShowTooltipsCheckbox.Unchecked += OnBehaviourChanged;
                if (AutoSaveCheckbox        != null) AutoSaveCheckbox.Checked   += OnBehaviourChanged;
                if (AutoSaveCheckbox        != null) AutoSaveCheckbox.Unchecked += OnBehaviourChanged;
                if (ShowStatusBarCheckbox   != null) ShowStatusBarCheckbox.Checked   += OnBehaviourChanged;
                if (ShowStatusBarCheckbox   != null) ShowStatusBarCheckbox.Unchecked += OnBehaviourChanged;
            }
            catch { }
        }

        private void OnBehaviourChanged(object sender, RoutedEventArgs e)
        {
            try
            {
                var settings = LoadOrCreateSettings();
                settings.EnableAnimations = EnableAnimationsCheckbox?.IsChecked ?? true;
                settings.ShowTooltips     = ShowTooltipsCheckbox?.IsChecked    ?? true;
                settings.AutoSave         = AutoSaveCheckbox?.IsChecked        ?? true;
                settings.ShowStatusBar    = ShowStatusBarCheckbox?.IsChecked   ?? true;
                SaveSettings(settings);
            }
            catch { }
        }

        private AppSettings LoadOrCreateSettings()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch { }
            return new AppSettings();
        }

        private void SaveSettings(AppSettings settings)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath,
                JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
        }

        // â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        private static string? ValidateHex(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            try { ColorConverter.ConvertFromString(s); return s; } catch { return null; }
        }

        // Legacy compatibility
        public string CurrentTheme => _activeTheme;
        public void SetTheme(string name) { ThemeManager.Apply(name); _activeTheme = name; HighlightCard(name); }

        // Stubs prevent compile errors if referenced elsewhere
        private RadioButton? DarkThemeRadio   => null;
        private RadioButton? LightThemeRadio  => null;
        private RadioButton? BlueThemeRadio   => null;
        private RadioButton? CustomThemeRadio => null;
        private Border?      CustomThemeEditor => null;
    }

    // â”€â”€ Settings model â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    internal class AppSettings
    {
        public string OpenAIKey          { get; set; } = string.Empty;
        public string AIProvider         { get; set; } = "openai-gpt35";
        public bool   EnableAnimations   { get; set; } = true;
        public bool   ShowTooltips       { get; set; } = true;
        public bool   AutoSave           { get; set; } = true;
        public bool   ShowStatusBar      { get; set; } = true;
        public bool   AlertSoundsEnabled { get; set; } = true;
    }
}



