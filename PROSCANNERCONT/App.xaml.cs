using System;
using System.Threading.Tasks;
using System.Windows;
using System.Diagnostics;
using PROSCANNERCONT.Managers;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.PortScanProtocols;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT
{
    public partial class App : Application
    {
        private HyperVManager? _hyperVManager;
        private SSHConnectionManager? _sshManager;

        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            Debug.WriteLine("=== Application Starting ===");

            // Initialise structured logging first so every subsequent step lands in the log.
            AppLogger.Log.Information("=== PrivaCore starting up (v{Version}) ===", UpdateCheckerService.CurrentVersion);

            // Wire up DI container — used by new code; legacy .Instance still works.
            try { ServiceContainer.Build(); }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "ServiceContainer.Build failed"); }

            // Global exception handlers — surface in log instead of crashing silently.
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                if (args.ExceptionObject is Exception ex)
                    AppLogger.Log.Fatal(ex, "Unhandled AppDomain exception");
            };
            DispatcherUnhandledException += (_, args) =>
            {
                AppLogger.Log.Error(args.Exception, "Unhandled dispatcher exception");
            };
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                AppLogger.Log.Warning(args.Exception, "Unobserved task exception");
                args.SetObserved();
            };

            // Restore persisted theme before any UI is shown (default: Phantom Dark)
            ThemeManager.LoadAndApply();
            if (!System.IO.File.Exists(System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "PrivaCore", "theme.json")))
                ThemeManager.Apply("Phantom Dark");

            // ── Module mode: launch one module's real GUI standalone + host it for the
            //    console to connect to. Same code/theme as the full app — just a focused window. ──
            var moduleKey = GetModuleArg(e.Args);
            if (moduleKey != null)
            {
                ConfigManager.TryLoadLastConfig();
                if (moduleKey.Equals("IDS", StringComparison.OrdinalIgnoreCase))
                    StartupUri = new Uri("Views/IDSModuleWindow.xaml", UriKind.Relative); // WPF shows this instead of MainWindow
                else { AppDialog.Show($"Unknown module '{moduleKey}'.", "Module", MessageBoxButton.OK, MessageBoxImage.Error); Shutdown(); }
                return;
            }

            // ── Console auth gate: require sign-in before the console opens. Module mode above is
            //    exempt (those are standalone hosts with their own pairing + challenge/response auth). ──
            this.ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown;   // no window yet
            var login = new Views.LoginWindow();
            if (login.ShowDialog() != true || login.AuthenticatedUser == null)
            {
                Shutdown();
                return;
            }
            Security.Auth.SessionService.Instance.SignIn(login.AuthenticatedUser);

            // Enforce SIEM data-loss guards against the console role. (Standalone module apps leave this
            // null → the local operator keeps full control; enforcement is a console concern.)
            System.Func<string, bool> roleGate = key =>
                Enum.TryParse<Security.Auth.Permission>(key, out var p) && Security.Auth.SessionService.Instance.Can(p);
            Views.SiemDashboardPage.PermissionGate = roleGate;
            Views.NetworkIDSDashboardPage.PermissionGate = roleGate;

            // Start persisted honeypot decoys as an always-on sensor; restore the SIEM feed if enabled.
            try
            {
                var hp = Services.Honeypot.HoneypotCaptureService.Instance.StartConfigured();
                if (hp.FeedSiem) Services.Honeypot.HoneypotSiemBridge.Attach();
            }
            catch { }

            // Restore last IDS config (rules, thresholds, HIDS settings, IDS mode)
            ConfigManager.TryLoadLastConfig();

            // Pre-initialize Service Detection in background (non-blocking)
            _ = InitializeServiceDetectionAsync();

            // Start threat-intel background refresh (non-blocking).
            try { ThreatIntelService.Instance.StartBackgroundRefresh(); }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "ThreatIntelService start failed"); }

            // Npcap dependency check — Traffic Analysis and IDS need it; surface
            // a friendly prompt instead of crashing on first capture attempt.
            _ = Task.Run(() =>
            {
                var npcap = NpcapDetector.Detect();
                AppLogger.Log.Information("Npcap detection: installed={Installed} version={Version} compat={Compat}",
                    npcap.Installed, npcap.Version, npcap.WinPcapCompat);
                if (!npcap.Installed)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        try
                        {
                            var msg = "Npcap is not installed.\n\n" +
                                      "PrivaCore needs Npcap (or WinPcap-compat mode) for:\n" +
                                      "  • Traffic Analysis\n  • Intrusion Detection (NIDS)\n\n" +
                                      $"Reason: {npcap.Reason}\n\n" +
                                      "Download from npcap.com and install with WinPcap compatibility mode.";
                            AppDialog.Show(msg, "Npcap missing", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                        catch { }
                    });
                }
            });

            // Check for updates in background — don't block startup
            _ = Task.Run(async () =>
            {
                await Task.Delay(3000); // wait 3s after app starts
                var update = await UpdateCheckerService.CheckForUpdateAsync();
                if (update.UpdateAvailable)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Debug.WriteLine($"[UpdateChecker] Update available: v{update.LatestVersion}");
                        try { AlertToast.Show("Update Available", $"PrivaCore v{update.LatestVersion} is available.", "#58A6FF"); }
                        catch { }
                    });
                }
            });

            try
            {
                // Initialize HyperV Manager
                Debug.WriteLine("Initializing HyperVManager...");
                _hyperVManager = new HyperVManager();
                Debug.WriteLine("✅ HyperVManager initialized successfully");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"⚠️ Warning: Could not initialize HyperVManager: {ex.Message}");
                AppDialog.Show(
                    "Warning: Could not connect to Hyper-V.\n\n" +
                    "VM management features may be limited.\n\n" +
                    "Please ensure:\n" +
                    "1. Hyper-V is installed\n" +
                    "2. You're running as Administrator\n" +
                    "3. Hyper-V services are running",
                    "Hyper-V Warning",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }

            try
            {
                // Initialize SSH Connection Manager
                Debug.WriteLine("Initializing SSH Connection Manager...");
                _sshManager = new SSHConnectionManager();
                Debug.WriteLine("✅ SSH Connection Manager initialized successfully");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"⚠️ Warning: Could not initialize SSH Manager: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                AppDialog.Show(
                    "Warning: Could not initialize SSH Manager.\n\n" +
                    "SSH terminal features may be limited.\n\n" +
                    $"Error: {ex.Message}",
                    "SSH Manager Warning",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }

            // Auth passed — open the console and bind app lifetime to it.
            var main = new MainWindow();
            this.MainWindow = main;
            this.ShutdownMode = System.Windows.ShutdownMode.OnMainWindowClose;
            main.Show();

            Debug.WriteLine("=== Application Startup Complete ===");
        }

        /// <summary>Returns the module key if launched as "--module &lt;KEY&gt;" (or "--module=KEY").</summary>
        private static string? GetModuleArg(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("--module", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) return args[i + 1];
                if (args[i].StartsWith("--module=", StringComparison.OrdinalIgnoreCase)) return args[i]["--module=".Length..];
            }
            return null;
        }

        /// <summary>
        /// Pre-initializes service detection database in background
        /// This runs asynchronously without blocking the main UI startup
        /// </summary>
        private async Task InitializeServiceDetectionAsync()
        {
            try
            {
                Debug.WriteLine("=== Starting Service Detection Pre-Initialization ===");
                Console.WriteLine("🚀 Pre-loading service detection database...");

                await Task.Run(async () =>
                {
                    try
                    {
                        // Initialize service detection for port scanning
                        await PortScanProtocols.ServiceDetection.InitializeAsync();
                        Debug.WriteLine("✅ Service Detection pre-initialized successfully");
                        Console.WriteLine($"✅ Service database ready with {PortScanProtocols.ServiceDetection.ServiceCount} services");
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"⚠️ Service Detection pre-initialization failed: {ex.Message}");
                        Console.WriteLine($"⚠️ Service detection will initialize on first use: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Warning: Background service detection init failed: {ex.Message}");
                // Silently fail - it will initialize on first use
            }
        }

        protected override async void OnExit(ExitEventArgs e)
        {
            Debug.WriteLine("=== Application Closing ===");

            try
            {
                // Disconnect all active SSH connections
                if (_sshManager != null)
                {
                    Debug.WriteLine("Disconnecting all SSH connections...");
                    _sshManager.DisconnectAll();
                    Debug.WriteLine("✅ All SSH connections closed");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"⚠️ Error disconnecting SSH: {ex.Message}");
            }

            try
            {
                // Stop all VMs before exit
                if (_hyperVManager != null)
                {
                    Debug.WriteLine("Stopping all VMs before exit...");
                    var task = _hyperVManager.StopAllVMs();

                    // Wait max 10 seconds for VMs to stop
                    if (await Task.WhenAny(task, Task.Delay(10000)) == task)
                    {
                        Debug.WriteLine("✅ All VMs stopped successfully");
                    }
                    else
                    {
                        Debug.WriteLine("⚠️ VM shutdown timeout - some VMs may still be running");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"⚠️ Error stopping VMs on exit: {ex.Message}");
            }

            base.OnExit(e);
            Debug.WriteLine("=== Application Closed ===");
            AppLogger.Log.Information("=== PrivaCore exited cleanly ===");
            AppLogger.Shutdown();
        }

        /// <summary>
        /// Get the global SSH manager instance
        /// </summary>
        public static SSHConnectionManager? GetSSHManager()
        {
            var app = Current as App;
            return app?._sshManager;
        }

        /// <summary>
        /// Get the global HyperV manager instance
        /// </summary>
        public static HyperVManager? GetHyperVManager()
        {
            var app = Current as App;
            return app?._hyperVManager;
        }
    }
}
