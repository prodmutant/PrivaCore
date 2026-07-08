using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// IDS Router - Handles first-time setup and routes to appropriate IDS dashboard
    /// </summary>
    public partial class IDSRouterPage : Page
    {
        private const string ConfigFileName = "ids_config.json";

        public IDSRouterPage()
        {
            InitializeComponent();
            Debug.WriteLine("=== IDSRouterPage: Constructor ===");

            // Use Loaded event to ensure NavigationService is ready
            this.Loaded += IDSRouterPage_Loaded;
        }

        private void IDSRouterPage_Loaded(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("=== IDSRouterPage: Loaded event fired ===");

            // Check if setup is complete
            var config = LoadIDSConfiguration();

            if (config == null)
            {
                // First time - show wizard
                Debug.WriteLine("IDSRouterPage: First time setup - showing wizard");
                ShowSetupWizard();
            }
            else
            {
                // Already configured - navigate to appropriate dashboard
                Debug.WriteLine($"IDSRouterPage: Already configured - Mode={config.Mode}");
                NavigateToIDSDashboard(config.Mode);
            }
        }

        private IDSConfiguration LoadIDSConfiguration()
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string idsDataPath = Path.Combine(appDataPath, "PROSCANNERCONT", "IDS");
                string configFilePath = Path.Combine(idsDataPath, ConfigFileName);

                if (!File.Exists(configFilePath))
                {
                    // Fall back to the mode stored in the last PrivaCore config
                    if (ConfigManager.IdsMode != null)
                    {
                        Debug.WriteLine($"LoadIDSConfiguration: ids_config.json absent, using ConfigManager.IdsMode={ConfigManager.IdsMode}");
                        return new IDSConfiguration { Mode = ConfigManager.IdsMode, ConfiguredDate = DateTime.Now };
                    }
                    Debug.WriteLine("LoadIDSConfiguration: No config file found - first time setup");
                    return null;
                }

                string text = File.ReadAllText(configFilePath);

                // Try JSON first; fall back to legacy key:value format
                try
                {
                    var json = JsonSerializer.Deserialize<JsonConfig>(text);
                    if (json?.Mode != null)
                    {
                        Debug.WriteLine($"LoadIDSConfiguration: JSON config — Mode={json.Mode}");
                        return new IDSConfiguration { Mode = json.Mode, ConfiguredDate = json.ConfiguredDate };
                    }
                }
                catch { }

                // Legacy plain-text fallback
                string mode = null; DateTime configDate = DateTime.Now;
                foreach (string line in text.Split('\n'))
                {
                    if (line.StartsWith("Mode:")) mode = line.Substring(5).Trim();
                    else if (line.StartsWith("Completed:")) DateTime.TryParse(line.Substring(10).Trim(), out configDate);
                }
                if (mode != null)
                {
                    Debug.WriteLine($"LoadIDSConfiguration: Legacy config — Mode={mode}");
                    SaveIDSConfiguration(mode); // upgrade to JSON
                    return new IDSConfiguration { Mode = mode, ConfiguredDate = configDate };
                }

                return null;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LoadIDSConfiguration ERROR: {ex.Message}");
                return null;
            }
        }

        private void SaveIDSConfiguration(string mode)
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string idsDataPath = Path.Combine(appDataPath, "PROSCANNERCONT", "IDS");
                string configFilePath = Path.Combine(idsDataPath, ConfigFileName);

                // Ensure directory exists
                Directory.CreateDirectory(idsDataPath);

                var json = new JsonConfig { Mode = mode, ConfiguredDate = DateTime.Now };
                File.WriteAllText(configFilePath, JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true }));

                Debug.WriteLine($"SaveIDSConfiguration: Config saved - Mode={mode}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SaveIDSConfiguration ERROR: {ex.Message}");
            }
        }

        private void ShowSetupWizard()
        {
            try
            {
                Debug.WriteLine("ShowSetupWizard: Navigating to wizard page...");
                var wizardPage = new IDSSetupWizardPage();
                wizardPage.SetupCompletedEvent += WizardPage_SetupCompleted;
                GetMainWindow()?.NavigateDirect(wizardPage);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ShowSetupWizard ERROR: {ex.Message}");
                AppDialog.Show($"Error showing setup wizard:\n\n{ex.Message}", "Setup Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void WizardPage_SetupCompleted(object sender, IDSSetupWizardPage.IDSMode mode)
        {
            try
            {
                string modeString = mode == IDSSetupWizardPage.IDSMode.HostBased ? "Host" : "Network";

                Debug.WriteLine($"WizardPage_SetupCompleted: Setup completed - Mode={modeString}");

                // Persist mode in both the router's own file and the central ConfigManager config
                SaveIDSConfiguration(modeString);
                ConfigManager.SetIdsMode(modeString);

                // Navigate to appropriate dashboard
                NavigateToIDSDashboard(modeString);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"WizardPage_SetupCompleted ERROR: {ex.Message}");
                AppDialog.Show(
                    $"Error completing setup:\n\n{ex.Message}",
                    "Setup Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void NavigateToIDSDashboard(string mode)
        {
            try
            {
                Debug.WriteLine($"NavigateToIDSDashboard: mode={mode}");

                Page targetPage = mode switch
                {
                    "Host"    => (Page)new HostIDSDashboardPage(),
                    "Network" => (Page)new NetworkIDSDashboardPage(),
                    _ => null
                };

                if (targetPage == null)
                {
                    AppDialog.Show($"Unknown IDS mode: {mode}\n\nPlease reconfigure the IDS.",
                        "Configuration Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                GetMainWindow()?.NavigateDirect(targetPage);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"NavigateToIDSDashboard ERROR: {ex.Message}");
                AppDialog.Show($"Error navigating to IDS dashboard:\n\n{ex.Message}",
                    "Navigation Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static MainWindow GetMainWindow() =>
            Application.Current.MainWindow as MainWindow;

        private class IDSConfiguration
        {
            public string Mode { get; set; }
            public DateTime ConfiguredDate { get; set; }
        }

        private class JsonConfig
        {
            public string Mode { get; set; }
            public DateTime ConfiguredDate { get; set; }
        }
    }
}


