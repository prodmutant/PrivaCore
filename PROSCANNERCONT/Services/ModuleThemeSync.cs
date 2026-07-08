using System;
using System.Collections.Generic;
using System.Text.Json;
using PROSCANNERCONT.Managers;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Live theme propagation: the controlling console pushes its active colour theme to every
    /// module it controls, so a standalone module's window matches the console — and updates the
    /// moment the operator switches themes. The module applies it live and reports which theme it
    /// is running.
    /// </summary>
    public static class ModuleThemeSync
    {
        public const string CmdTheme = "module.theme";

        // ── module (host) side ───────────────────────────────────────────────
        /// <summary>Raised on the module when a controller pushes a theme (name of the applied theme).</summary>
        public static event Action<string>? HostThemeChanged;

        /// <summary>Wire a module host so incoming theme commands are applied on the UI thread.</summary>
        public static void AttachHost(ModuleHost host, Action<Action> dispatch)
        {
            host.CommandReceived += (_, m) =>
            {
                if (m.EventName != CmdTheme) return;
                var name = m.Str("name");
                var paletteJson = m.Str("palette");
                dispatch(() =>
                {
                    try
                    {
                        if (!string.IsNullOrEmpty(name) && name != "Custom" && ThemeManager.Themes.ContainsKey(name))
                            ThemeManager.Apply(name);
                        else if (paletteJson != null)
                        {
                            var c = JsonSerializer.Deserialize<CustomThemeColors>(paletteJson);
                            if (c != null) ThemeManager.ApplyCustomColors(c);
                        }
                        HostThemeChanged?.Invoke(string.IsNullOrEmpty(name) ? "Custom" : name);
                    }
                    catch { }
                });
            };
        }

        // ── console (controller) side ────────────────────────────────────────
        private static ModuleClient? _client;
        private static Action? _onThemeChanged;

        /// <summary>Push the console's current theme to a module, and keep pushing on every theme change.</summary>
        public static void AttachConsole(ModuleClient client)
        {
            DetachConsole();
            _client = client;
            void Push()
            {
                var c = _client;
                if (c == null) return;
                var data = new Dictionary<string, object>
                {
                    ["name"] = ThemeManager.CurrentThemeName,
                    ["palette"] = JsonSerializer.Serialize(ThemeManager.CurrentPalette()),
                };
                try { _ = c.SendCommandAsync(CmdTheme, data); } catch { }
            }
            _onThemeChanged = Push;
            ThemeManager.ThemeChanged += _onThemeChanged;
            Push();   // send the current theme immediately on connect
        }

        public static void DetachConsole()
        {
            if (_onThemeChanged != null) ThemeManager.ThemeChanged -= _onThemeChanged;
            _onThemeChanged = null; _client = null;
        }
    }
}
