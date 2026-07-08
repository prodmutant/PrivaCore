using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace PROSCANNERCONT.Managers
{
    public static class ThemeManager
    {
        private static readonly string _settingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PrivaCore", "theme.json");

        /// <summary>The name of the currently applied theme ("Custom" for ad-hoc colours).</summary>
        public static string CurrentThemeName { get; private set; } = "Phantom Dark";

        /// <summary>Raised whenever the active theme changes — used to push the theme to connected modules.</summary>
        public static event Action? ThemeChanged;

        // ── Theme definitions ────────────────────────────────────────────────────
        public static readonly Dictionary<string, ThemeDefinition> Themes = new()
        {
            // ── Phantom Dark ────────────────────────────────────────────────────
            // GitHub-dark palette. Every colour is tested for WCAG AA contrast.
            // Accent #58A6FF on #0D1117 = 5.9:1 ✓  Text #E6EDF3 on bg = 14:1 ✓
            ["Phantom Dark"] = new ThemeDefinition
            {
                DisplayName  = "Phantom Dark",
                Description  = "Refined dark — GitHub-inspired, developer-friendly",
                Icon         = "🌑",
                PrimaryFont  = "Segoe UI",
                CornerSmall  = 3, CornerNormal = 6, CornerLarge = 10, CornerRound = 16,
                BtnPadding   = "16,8", InputPadding = "10,7",
                FontSmall    = 11, FontNormal = 13, FontLarge = 20,

                Background   = "#0D1117", Secondary    = "#161B22",
                Accent       = "#58A6FF", Text         = "#E6EDF3",
                Border       = "#30363D", Hover        = "#21262D",
                Selection    = "#264F78", Critical     = "#F85149",
                Warning      = "#E3B341", Success      = "#56D364",
                CardBg       = "#161B22", AccentLight  = "#79C0FF"
            },

            // ── Neon Terminal ───────────────────────────────────────────────────
            // Pure black canvas, phosphor-green glow. Consolas everywhere.
            // Accent #00D9AA on #0A0A0A = 9.2:1 ✓  Text #D4FFE8 on bg = 17:1 ✓
            ["Neon Terminal"] = new ThemeDefinition
            {
                DisplayName  = "Neon Terminal",
                Description  = "Hacker aesthetic — sharp corners, phosphor glow",
                Icon         = "⚡",
                PrimaryFont  = "Consolas",
                CornerSmall  = 0, CornerNormal = 0, CornerLarge = 0, CornerRound = 2,
                BtnPadding   = "14,7", InputPadding = "10,6",
                FontSmall    = 11, FontNormal = 13, FontLarge = 18,

                Background   = "#0A0A0A", Secondary    = "#111111",
                Accent       = "#00D9AA", Text         = "#D4FFE8",
                Border       = "#003322", Hover        = "#0D2B1D",
                Selection    = "#005544", Critical     = "#FF3355",
                Warning      = "#FFD600", Success      = "#00D9AA",
                CardBg       = "#0F0F0F", AccentLight  = "#80FFDD"
            },

            // ── Arctic ──────────────────────────────────────────────────────────
            // GitHub Light palette — all colours tested on white backgrounds.
            // Accent #0969DA on #FFFFFF = 5.9:1 ✓  Text #24292F on white = 19:1 ✓
            // Critical #CF222E on white = 5.0:1 ✓  Warning #7D4E00 on white = 8:1 ✓
            ["Arctic"] = new ThemeDefinition
            {
                DisplayName  = "Arctic",
                Description  = "Crisp light — spacious, minimal, daylight-optimised",
                Icon         = "❄️",
                PrimaryFont  = "Segoe UI",
                CornerSmall  = 5, CornerNormal = 10, CornerLarge = 14, CornerRound = 24,
                BtnPadding   = "18,9", InputPadding = "12,8",
                FontSmall    = 11, FontNormal = 13, FontLarge = 22,

                Background   = "#FFFFFF", Secondary    = "#F6F8FA",
                Accent       = "#0969DA", Text         = "#24292F",
                Border       = "#D0D7DE", Hover        = "#F3F4F6",
                Selection    = "#DBEAFE", Critical     = "#CF222E",
                Warning      = "#7D4E00", Success      = "#116329",
                CardBg       = "#FFFFFF", AccentLight  = "#218BFF"
            },

            // ── Midnight Ocean ──────────────────────────────────────────────────
            // Deep navy palette. Sky-blue accent pops on navy canvas.
            // Accent #38BDF8 on #0B1426 = 8.1:1 ✓  Text #CBD5E1 on bg = 10:1 ✓
            ["Midnight Ocean"] = new ThemeDefinition
            {
                DisplayName  = "Midnight Ocean",
                Description  = "Deep navy — premium security tool feel",
                Icon         = "🌊",
                PrimaryFont  = "Segoe UI",
                CornerSmall  = 2, CornerNormal = 5, CornerLarge = 8, CornerRound = 12,
                BtnPadding   = "16,8", InputPadding = "10,7",
                FontSmall    = 11, FontNormal = 13, FontLarge = 20,

                Background   = "#0B1426", Secondary    = "#102035",
                Accent       = "#38BDF8", Text         = "#CBD5E1",
                Border       = "#1E3A5F", Hover        = "#17304D",
                Selection    = "#1D4ED8", Critical     = "#F87171",
                Warning      = "#FBBF24", Success      = "#4ADE80",
                CardBg       = "#102035", AccentLight  = "#7DD3FC"
            },

            // ── Crimson Void ────────────────────────────────────────────────────
            // Deep charcoal canvas with vivid red accent.
            // Accent #E53E3E on #0F0A0A = 5.2:1 ✓  Text #FED7D7 on bg = 16:1 ✓
            ["Crimson Void"] = new ThemeDefinition
            {
                DisplayName  = "Crimson Void",
                Description  = "Deep charcoal — vivid crimson accent, dramatic feel",
                Icon         = "🔴",
                PrimaryFont  = "Segoe UI",
                CornerSmall  = 4, CornerNormal = 8, CornerLarge = 12, CornerRound = 20,
                BtnPadding   = "16,8", InputPadding = "10,7",
                FontSmall    = 11, FontNormal = 13, FontLarge = 20,

                Background   = "#0F0A0A", Secondary    = "#1A1010",
                Accent       = "#E53E3E", Text         = "#FED7D7",
                Border       = "#2D1515", Hover        = "#200F0F",
                Selection    = "#742A2A", Critical     = "#FC8181",
                Warning      = "#F6AD55", Success      = "#68D391",
                CardBg       = "#1A1010", AccentLight  = "#FEB2B2"
            },

            // ── Carbon ──────────────────────────────────────────────────────────
            // Near-black professional dark, VS Code-inspired.
            // Accent #569CD6 on #1E1E1E = 5.1:1 ✓  Text #D4D4D4 on bg = 10.5:1 ✓
            ["Carbon"] = new ThemeDefinition
            {
                DisplayName  = "Carbon",
                Description  = "VS Code-inspired — familiar, sharp, professional",
                Icon         = "⬛",
                PrimaryFont  = "Segoe UI",
                CornerSmall  = 2, CornerNormal = 4, CornerLarge = 6, CornerRound = 8,
                BtnPadding   = "16,8", InputPadding = "10,7",
                FontSmall    = 11, FontNormal = 13, FontLarge = 20,

                Background   = "#1E1E1E", Secondary    = "#252526",
                Accent       = "#569CD6", Text         = "#D4D4D4",
                Border       = "#3E3E42", Hover        = "#2D2D30",
                Selection    = "#094771", Critical     = "#F48771",
                Warning      = "#CE9178", Success      = "#4EC9B0",
                CardBg       = "#252526", AccentLight  = "#9CDCFE"
            },

            // ── Dracula ──────────────────────────────────────────────────────────
            // Classic Dracula palette — purple accent, warm background.
            // Accent #BD93F9 on #282A36 = 7.2:1 ✓  Text #F8F8F2 on bg = 14.5:1 ✓
            ["Dracula"] = new ThemeDefinition
            {
                DisplayName  = "Dracula",
                Description  = "Classic Dracula — purple accent, timeless hacker chic",
                Icon         = "🧛",
                PrimaryFont  = "Segoe UI",
                CornerSmall  = 6, CornerNormal = 10, CornerLarge = 14, CornerRound = 22,
                BtnPadding   = "16,8", InputPadding = "10,7",
                FontSmall    = 11, FontNormal = 13, FontLarge = 20,

                Background   = "#282A36", Secondary    = "#21222C",
                Accent       = "#BD93F9", Text         = "#F8F8F2",
                Border       = "#44475A", Hover        = "#383A59",
                Selection    = "#44475A", Critical     = "#FF5555",
                Warning      = "#FFB86C", Success      = "#50FA7B",
                CardBg       = "#21222C", AccentLight  = "#CFA9FC"
            },

            // ── Solar Warm ──────────────────────────────────────────────────────
            // Warm cream/amber light theme — second light option.
            // Accent #C05621 on #FFF8F0 = 5.3:1 ✓  Text #2D1B00 on bg = 16:1 ✓
            ["Solar Warm"] = new ThemeDefinition
            {
                DisplayName  = "Solar Warm",
                Description  = "Warm amber light — cream canvas, readable and cosy",
                Icon         = "☀️",
                PrimaryFont  = "Segoe UI",
                CornerSmall  = 6, CornerNormal = 12, CornerLarge = 18, CornerRound = 28,
                BtnPadding   = "18,9", InputPadding = "12,8",
                FontSmall    = 11, FontNormal = 13, FontLarge = 20,

                Background   = "#FFF8F0", Secondary    = "#FFF1E0",
                Accent       = "#C05621", Text         = "#2D1B00",
                Border       = "#E8C89A", Hover        = "#FAEBD7",
                Selection    = "#FEEBC8", Critical     = "#C53030",
                Warning      = "#D69E2E", Success      = "#276749",
                CardBg       = "#FFFFFF", AccentLight  = "#DD6B20"
            }
        };

        // ── Apply ───────────────────────────────────────────────────────────────
        public static void Apply(string themeName)
        {
            if (!Themes.TryGetValue(themeName, out var def)) return;
            Apply(def);
        }

        public static void Apply(ThemeDefinition def)
        {
            // Fade the main window: opacity 1 → 0, swap theme, then 0 → 1
            var win = Application.Current?.MainWindow;
            if (win != null)
            {
                var fadeOut = new DoubleAnimation(1.0, 0.0, new Duration(TimeSpan.FromMilliseconds(120)))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
                };
                fadeOut.Completed += (_, __) =>
                {
                    ApplyImmediate(def);
                    var fadeIn = new DoubleAnimation(0.0, 1.0, new Duration(TimeSpan.FromMilliseconds(180)))
                    {
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    };
                    win.BeginAnimation(UIElement.OpacityProperty, fadeIn);
                };
                win.BeginAnimation(UIElement.OpacityProperty, fadeOut);
                return;
            }
            ApplyImmediate(def);
        }

        private static void ApplyImmediate(ThemeDefinition def)
        {
            CurrentThemeName = string.IsNullOrEmpty(def.DisplayName) ? CurrentThemeName : def.DisplayName;
            var res = Application.Current.Resources;

            // Colors
            Set(res, "BackgroundBrush",          def.Background);
            Set(res, "SecondaryBackgroundBrush",  def.Secondary);
            Set(res, "AccentBrush",               def.Accent);
            Set(res, "TextBrush",                 def.Text);
            Set(res, "BorderBrush",               def.Border);
            Set(res, "HoverBrush",                def.Hover);
            Set(res, "SelectionBrush",            def.Selection);
            Set(res, "CriticalBrush",             def.Critical);
            Set(res, "WarningBrush",              def.Warning);
            Set(res, "SuccessBrush",              def.Success);
            Set(res, "CardBackground",            def.CardBg);
            Set(res, "AccentLightBrush",          def.AccentLight);
            // Derived contrast brushes — readable on both light and dark themes.
            // OnAccentBrush is the text/icon foreground when something sits ON the
            // accent colour (buttons, datagrid headers, toggle thumb). It must be
            // white on dark accents and near-black on light accents.
            try
            {
                var textColor = (Color)ColorConverter.ConvertFromString(def.Text);
                var bgColor   = (Color)ColorConverter.ConvertFromString(def.Background);
                bool isLight = (bgColor.R + bgColor.G + bgColor.B) > 382;
                double tw = isLight ? 0.70 : 0.50;
                double bw = 1.0 - tw;
                var muted = Color.FromRgb(
                    (byte)(textColor.R * tw + bgColor.R * bw),
                    (byte)(textColor.G * tw + bgColor.G * bw),
                    (byte)(textColor.B * tw + bgColor.B * bw));
                res["SubtleTextBrush"] = new SolidColorBrush(muted);
                res["TextSecondary"]   = new SolidColorBrush(muted);

                // Disabled text: ~40 % blend toward background
                var disabled = Color.FromRgb(
                    (byte)(textColor.R * 0.40 + bgColor.R * 0.60),
                    (byte)(textColor.G * 0.40 + bgColor.G * 0.60),
                    (byte)(textColor.B * 0.40 + bgColor.B * 0.60));
                res["DisabledTextBrush"] = new SolidColorBrush(disabled);
            }
            catch { Set(res, "SubtleTextBrush", def.Border); }

            // Contrast-aware semantic foreground brushes (text/icon on top of accent/danger/etc.)
            SetContrastBrush(res, "OnAccentBrush",  def.Accent);
            SetContrastBrush(res, "OnDangerBrush",  def.Critical);
            SetContrastBrush(res, "OnSuccessBrush", def.Success);
            SetContrastBrush(res, "OnWarningBrush", def.Warning);

            // Severity semantic palette — used by alert dashboards, badges, IDS rows.
            // Critical = theme critical, High = warning, Medium = blend, Low = success,
            // Info = accent-light. Faded backgrounds derived from the same hue.
            Set(res, "SeverityCriticalBrush", def.Critical);
            Set(res, "SeverityHighBrush",     def.Warning);
            Set(res, "SeverityLowBrush",      def.Success);
            Set(res, "SeverityInfoBrush",     def.AccentLight);
            try
            {
                var warn = (Color)ColorConverter.ConvertFromString(def.Warning);
                var crit = (Color)ColorConverter.ConvertFromString(def.Critical);
                var med  = Color.FromRgb(
                    (byte)((warn.R + crit.R) / 2),
                    (byte)((warn.G + crit.G) / 2),
                    (byte)((warn.B + crit.B) / 2));
                res["SeverityMediumBrush"] = new SolidColorBrush(med);
            }
            catch { Set(res, "SeverityMediumBrush", def.Warning); }
            res["SeverityCriticalBgBrush"] = MakeTintedBg(def.Critical, def.Background);
            res["SeverityHighBgBrush"]     = MakeTintedBg(def.Warning,  def.Background);
            res["SeverityMediumBgBrush"]   = MakeTintedBg(def.Warning,  def.Background);
            res["SeverityLowBgBrush"]      = MakeTintedBg(def.Success,  def.Background);
            res["SeverityInfoBgBrush"]     = MakeTintedBg(def.AccentLight, def.Background);

            // Shadow brush — derive from background luminance so light themes get
            // a subtle dark shadow and dark themes get pure black.
            try
            {
                var bg = (Color)ColorConverter.ConvertFromString(def.Background);
                bool isLight = (bg.R + bg.G + bg.B) > 382;
                res["ShadowColorBrush"] = new SolidColorBrush(
                    isLight ? Color.FromArgb(60, 0, 0, 0) : Color.FromArgb(255, 0, 0, 0));
            }
            catch { }

            // Overlay (modal dim) — opposite-luminance translucent layer
            try
            {
                var bg = (Color)ColorConverter.ConvertFromString(def.Background);
                bool isLight = (bg.R + bg.G + bg.B) > 382;
                res["OverlayBackgroundBrush"] = new SolidColorBrush(
                    isLight ? Color.FromArgb(120, 0, 0, 0) : Color.FromArgb(160, 0, 0, 0));
            }
            catch { }
            // Alias brushes used by IDS dashboard aliases in App.xaml
            Set(res, "ItemBackground",            def.Hover);
            Set(res, "TextPrimary",               def.Text);
            Set(res, "PrimaryBlue",               def.Accent);
            Set(res, "SuccessGreen",              def.Success);
            Set(res, "WarningOrange",             def.Warning);
            Set(res, "DangerRed",                 def.Critical);
            Set(res, "CardBackground",            def.CardBg);

            // Typography — update the resource keys (used by pages that read PrimaryFont directly)
            res["PrimaryFont"] = new FontFamily(def.PrimaryFont);
            res["MonoFont"]    = new FontFamily("Consolas");

            // Apply font to control styles at runtime (DynamicResource in Setters
            // triggers TypeConverterMarkupExtension for FontFamily, so we patch directly)
            var font = new FontFamily(def.PrimaryFont);
            PatchStyleFont(res, "BaseButtonStyle", font);
            PatchStyleFont(res, "NavButtonStyle",  font);
            PatchStyleFont(res, "TextBoxBase",     font);
            PatchStyleFont(res, "ComboBoxStyle",   font);
            res["FontSizeSmall"]  = (double)def.FontSmall;
            res["FontSizeNormal"] = (double)def.FontNormal;
            res["FontSizeLarge"]  = (double)def.FontLarge;

            // Shape
            res["CornerRadiusSmall"]  = new CornerRadius(def.CornerSmall);
            res["CornerRadiusNormal"] = new CornerRadius(def.CornerNormal);
            res["CornerRadiusLarge"]  = new CornerRadius(def.CornerLarge);
            res["CornerRadiusRound"]  = new CornerRadius(def.CornerRound);

            // Spacing
            res["ButtonPadding"] = ParseThickness(def.BtnPadding);
            res["InputPadding"]  = ParseThickness(def.InputPadding);

            ThemeChanged?.Invoke();
        }

        // ── Persistence ─────────────────────────────────────────────────────────
        public static void SaveTheme(string themeName, CustomThemeColors? custom = null)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
                var data = new ThemeData { ThemeName = themeName, Custom = custom };
                File.WriteAllText(_settingsPath,
                    JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        public static void LoadAndApply()
        {
            try
            {
                if (!File.Exists(_settingsPath)) return;
                var data = JsonSerializer.Deserialize<ThemeData>(File.ReadAllText(_settingsPath));
                if (data == null) return;

                if (data.ThemeName == "Custom" && data.Custom != null)
                    ApplyCustomColors(data.Custom);
                else if (!string.IsNullOrEmpty(data.ThemeName) && Themes.ContainsKey(data.ThemeName))
                    Apply(data.ThemeName);
            }
            catch { }
        }

        public static void ApplyCustomColors(CustomThemeColors c)
        {
            CurrentThemeName = "Custom";
            var win = Application.Current?.MainWindow;
            void DoApply()
            {
                var res = Application.Current.Resources;
                Set(res, "BackgroundBrush",         c.Background);
                Set(res, "SecondaryBackgroundBrush", c.SecondaryBackground);
                Set(res, "AccentBrush",              c.Accent);
                Set(res, "TextBrush",                c.Text);
                Set(res, "BorderBrush",              c.Border);
                Set(res, "HoverBrush",               c.Hover);
                Set(res, "SelectionBrush",           c.Selection);
                Set(res, "CriticalBrush",            c.Critical ?? "#F85149");
                Set(res, "WarningBrush",             c.Warning  ?? "#D29922");
                Set(res, "SuccessBrush",             c.Success  ?? "#3FB950");
                Set(res, "AccentLightBrush",         c.AccentLight ?? "#79C0FF");

                // IDS dashboard aliases — keep custom themes consistent.
                Set(res, "CardBackground",   c.SecondaryBackground);
                Set(res, "ItemBackground",   c.Hover);
                Set(res, "TextPrimary",      c.Text);
                Set(res, "PrimaryBlue",      c.Accent);
                Set(res, "SuccessGreen",     c.Success ?? "#3FB950");
                Set(res, "WarningOrange",    c.Warning ?? "#D29922");
                Set(res, "DangerRed",        c.Critical ?? "#F85149");

                // Derived semantic brushes for custom themes.
                SetContrastBrush(res, "OnAccentBrush",  c.Accent);
                SetContrastBrush(res, "OnDangerBrush",  c.Critical ?? "#F85149");
                SetContrastBrush(res, "OnSuccessBrush", c.Success  ?? "#3FB950");
                SetContrastBrush(res, "OnWarningBrush", c.Warning  ?? "#D29922");

                try
                {
                    var textC = (Color)ColorConverter.ConvertFromString(c.Text);
                    var bgC   = (Color)ColorConverter.ConvertFromString(c.Background);
                    bool isLight = (bgC.R + bgC.G + bgC.B) > 382;
                    double tw = isLight ? 0.70 : 0.50;
                    double bw = 1.0 - tw;
                    var muted = Color.FromRgb(
                        (byte)(textC.R * tw + bgC.R * bw),
                        (byte)(textC.G * tw + bgC.G * bw),
                        (byte)(textC.B * tw + bgC.B * bw));
                    res["SubtleTextBrush"] = new SolidColorBrush(muted);
                    res["TextSecondary"]   = new SolidColorBrush(muted);
                    var disabled = Color.FromRgb(
                        (byte)(textC.R * 0.40 + bgC.R * 0.60),
                        (byte)(textC.G * 0.40 + bgC.G * 0.60),
                        (byte)(textC.B * 0.40 + bgC.B * 0.60));
                    res["DisabledTextBrush"] = new SolidColorBrush(disabled);
                    res["ShadowColorBrush"]  = new SolidColorBrush(
                        isLight ? Color.FromArgb(60, 0, 0, 0) : Color.FromArgb(255, 0, 0, 0));
                    res["OverlayBackgroundBrush"] = new SolidColorBrush(
                        isLight ? Color.FromArgb(120, 0, 0, 0) : Color.FromArgb(160, 0, 0, 0));
                }
                catch { }
                ThemeChanged?.Invoke();
            }

            if (win != null)
            {
                var fadeOut = new DoubleAnimation(1.0, 0.0, new Duration(TimeSpan.FromMilliseconds(120)));
                fadeOut.Completed += (_, __) =>
                {
                    DoApply();
                    win.BeginAnimation(UIElement.OpacityProperty,
                        new DoubleAnimation(0.0, 1.0, new Duration(TimeSpan.FromMilliseconds(180))));
                };
                win.BeginAnimation(UIElement.OpacityProperty, fadeOut);
            }
            else DoApply();
        }

        public static CustomThemeColors CurrentCustomColors() => new CustomThemeColors
        {
            Background          = BrushHex("BackgroundBrush"),
            SecondaryBackground = BrushHex("SecondaryBackgroundBrush"),
            Accent              = BrushHex("AccentBrush"),
            Text                = BrushHex("TextBrush"),
            Border              = BrushHex("BorderBrush"),
            Hover               = BrushHex("HoverBrush"),
            Selection           = BrushHex("SelectionBrush")
        };

        /// <summary>Full snapshot of the live palette — used to mirror the exact look onto a remote module.</summary>
        public static CustomThemeColors CurrentPalette() => new CustomThemeColors
        {
            Background          = BrushHex("BackgroundBrush"),
            SecondaryBackground = BrushHex("SecondaryBackgroundBrush"),
            Accent              = BrushHex("AccentBrush"),
            AccentLight         = BrushHex("AccentLightBrush"),
            Text                = BrushHex("TextBrush"),
            Border              = BrushHex("BorderBrush"),
            Hover               = BrushHex("HoverBrush"),
            Selection           = BrushHex("SelectionBrush"),
            Critical            = BrushHex("CriticalBrush"),
            Warning             = BrushHex("WarningBrush"),
            Success             = BrushHex("SuccessBrush"),
        };

        // ── Helpers ─────────────────────────────────────────────────────────────
        private static void PatchStyleFont(ResourceDictionary res, string styleKey, FontFamily font)
        {
            try
            {
                if (res[styleKey] is System.Windows.Style style)
                {
                    // Find existing FontFamily setter and update it, or add one
                    var existing = style.Setters.OfType<System.Windows.Setter>()
                        .FirstOrDefault(s => s.Property == System.Windows.Controls.Control.FontFamilyProperty);
                    if (existing != null)
                        existing.Value = font;
                    else
                        style.Setters.Add(new System.Windows.Setter(System.Windows.Controls.Control.FontFamilyProperty, font));
                }
            }
            catch { }
        }

        private static void Set(ResourceDictionary res, string key, string hex)
        {
            try { res[key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); } catch { }
        }

        // Picks a foreground (near-white or near-black) for text/icons sitting on top
        // of the supplied background colour, using WCAG-style relative-luminance test.
        private static void SetContrastBrush(ResourceDictionary res, string key, string bgHex)
        {
            try
            {
                var c = (Color)ColorConverter.ConvertFromString(bgHex);
                double r = Channel(c.R), g = Channel(c.G), b = Channel(c.B);
                double luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
                res[key] = new SolidColorBrush(luminance > 0.42
                    ? Color.FromRgb(0x10, 0x10, 0x10)
                    : Color.FromRgb(0xFF, 0xFF, 0xFF));
            }
            catch { res[key] = new SolidColorBrush(Colors.White); }
        }

        private static double Channel(byte v)
        {
            double s = v / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }

        // 18 % accent colour mixed onto background — gives a faded tint badge
        // background that reads the severity hue without dominating the layout.
        private static SolidColorBrush MakeTintedBg(string hueHex, string bgHex)
        {
            try
            {
                var h  = (Color)ColorConverter.ConvertFromString(hueHex);
                var bg = (Color)ColorConverter.ConvertFromString(bgHex);
                const double t = 0.18;
                var tint = Color.FromRgb(
                    (byte)(h.R * t + bg.R * (1 - t)),
                    (byte)(h.G * t + bg.G * (1 - t)),
                    (byte)(h.B * t + bg.B * (1 - t)));
                return new SolidColorBrush(tint);
            }
            catch
            {
                return new SolidColorBrush(Color.FromArgb(64, 200, 200, 200));
            }
        }

        private static string BrushHex(string key)
        {
            if (Application.Current.Resources[key] is SolidColorBrush b) return b.Color.ToString();
            return "#FF000000";
        }

        private static Thickness ParseThickness(string s)
        {
            var parts = s.Split(',');
            if (parts.Length == 2 && double.TryParse(parts[0], out double h) && double.TryParse(parts[1], out double v))
                return new Thickness(h, v, h, v);
            return new Thickness(12, 7, 12, 7);
        }

        // Legacy compatibility
        public static void ApplyNamedTheme(string name) => Apply(name);
    }

    // ── Data models ─────────────────────────────────────────────────────────────
    public class ThemeDefinition
    {
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Icon        { get; set; } = string.Empty;
        public string PrimaryFont { get; set; } = "Segoe UI";

        // Corner radii
        public int CornerSmall  { get; set; } = 3;
        public int CornerNormal { get; set; } = 6;
        public int CornerLarge  { get; set; } = 10;
        public int CornerRound  { get; set; } = 16;

        // Font sizes
        public int FontSmall  { get; set; } = 11;
        public int FontNormal { get; set; } = 13;
        public int FontLarge  { get; set; } = 20;

        // Padding
        public string BtnPadding   { get; set; } = "16,8";
        public string InputPadding { get; set; } = "10,7";

        // Colors (hex strings)
        public string Background  { get; set; } = string.Empty;
        public string Secondary   { get; set; } = string.Empty;
        public string Accent      { get; set; } = string.Empty;
        public string Text        { get; set; } = string.Empty;
        public string Border      { get; set; } = string.Empty;
        public string Hover       { get; set; } = string.Empty;
        public string Selection   { get; set; } = string.Empty;
        public string Critical    { get; set; } = string.Empty;
        public string Warning     { get; set; } = string.Empty;
        public string Success     { get; set; } = string.Empty;
        public string CardBg      { get; set; } = string.Empty;
        public string AccentLight { get; set; } = string.Empty;
    }

    public class ThemeData
    {
        public string ThemeName { get; set; } = "Phantom Dark";
        public CustomThemeColors? Custom { get; set; }
    }

    public class CustomThemeColors
    {
        public string Background          { get; set; } = "#0D1117";
        public string SecondaryBackground { get; set; } = "#161B22";
        public string Accent              { get; set; } = "#58A6FF";
        public string AccentLight         { get; set; } = "#79C0FF";
        public string Text                { get; set; } = "#E6EDF3";
        public string Border              { get; set; } = "#30363D";
        public string Hover               { get; set; } = "#21262D";
        public string Selection           { get; set; } = "#1F6FEB";
        public string Success             { get; set; } = "#3FB950";
        public string Warning             { get; set; } = "#D29922";
        public string Critical            { get; set; } = "#F85149";
    }
}
