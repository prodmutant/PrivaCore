using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.PortScanProtocols;
using PROSCANNERCONT.port_scan_protocols;
using PROSCANNERCONT.Security;
using PROSCANNERCONT.ServiceDetection;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class MiscellaneousPage : Page
    {
        // Static so scan state and results persist across page navigations
        private static ObservableCollection<PortScanResult> _scanResults = new();
        private static CancellationTokenSource _scanCancellationTokenSource;
        private static bool _isScanning = false;
        private string _selectedScannerType = "TCP Connect Scan (-sT)";
        private int _timeout = 2000;
        private ServiceDetectionManager _serviceDetectionManager;
        private readonly NVDChecker _nvdChecker = new NVDChecker();

        // Advanced options
        private bool _bannerGrabbing = true;
        private bool _versionDetection = true;
        private bool _aggressiveProbes = false;
        private int _timingTemplate = 3; // Normal
        private bool _randomizeOrder = false;

        private TextBox _ipTextBox;
        private TextBox _startPortTextBox;
        private TextBox _endPortTextBox;
        private Button _startScanButton;
        private DataGrid _resultsDataGrid;
        private ComboBox _scanTypeComboBox;
        private ProgressBar _scanProgressBar;

        public MiscellaneousPage()
        {
            InitializeComponent();

            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });

            _serviceDetectionManager = new ServiceDetectionManager(loggerFactory.CreateLogger<ServiceDetectionManager>());

            InitializeUIElements();

            // Start async initialization without blocking UI
            _ = InitializeServiceDetectionAsync();
        }

        private async Task InitializeServiceDetectionAsync()
        {
            try
            {
                // Only show "Initializing" if a scan is not already running
                await Dispatcher.InvokeAsync(() =>
                {
                    if (!_isScanning && _startScanButton != null)
                    {
                        _startScanButton.IsEnabled = false;
                        _startScanButton.Content = "Initializing...";
                    }
                    if (!_isScanning && ProgressText != null)
                    {
                        ProgressText.Text = "Initializing service detection database...";
                        ProgressText.Visibility = Visibility.Visible;
                    }
                });

                await PortScanProtocols.ServiceDetection.InitializeAsync();

                await Dispatcher.InvokeAsync(() =>
                {
                    LoadPageState();

                    // Restore scan state FIRST — if a scan is running, keep "Stop Scan"
                    RestoreScanState();

                    // Only reset to "Start Scan" if nothing is running
                    if (!_isScanning)
                    {
                        if (_startScanButton != null)
                        {
                            _startScanButton.IsEnabled = true;
                            _startScanButton.Content = "Start Scan";
                        }
                        if (ProgressText != null)
                        {
                            ProgressText.Text = "";
                            ProgressText.Visibility = Visibility.Collapsed;
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Service Detection initialization warning: {ex.Message}");

                await Dispatcher.InvokeAsync(() =>
                {
                    LoadPageState();
                    RestoreScanState();

                    if (!_isScanning)
                    {
                        if (_startScanButton != null)
                        {
                            _startScanButton.IsEnabled = true;
                            _startScanButton.Content = "Start Scan";
                        }
                        if (ProgressText != null)
                        {
                            ProgressText.Text = "";
                            ProgressText.Visibility = Visibility.Collapsed;
                        }
                    }

                    AppDialog.Show(
                        $"Service detection initialization encountered an issue:\n\n{ex.Message}\n\n" +
                        "The application will continue, but service detection may be limited.",
                        "Service Detection Warning",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                });
            }
        }

        private void RestoreScanState()
        {
            if (!_isScanning) return;
            if (_startScanButton != null)
                _startScanButton.Content = "Stop Scan";
            if (ScanProgressBar != null)
            {
                ScanProgressBar.Visibility = Visibility.Visible;
                ScanProgressBar.IsIndeterminate = true;
            }
            if (ProgressText != null)
            {
                ProgressText.Text = "Scan in progress...";
                ProgressText.Visibility = Visibility.Visible;
            }
        }

        private void InitializeUIElements()
        {
            _ipTextBox = IpTextBox;
            _startPortTextBox = StartPortTextBox;
            _endPortTextBox = EndPortTextBox;
            _startScanButton = StartScanButton;
            _resultsDataGrid = ResultsDataGrid;
            _scanTypeComboBox = ScanTypeComboBox;
            _scanProgressBar = ScanProgressBar;

            _resultsDataGrid.ItemsSource = _scanResults;
            _startScanButton.Click += StartScanButton_Click;

            foreach (var scanType in ScannerFactory.AvailableScanTypes)
            {
                _scanTypeComboBox.Items.Add(scanType);
            }
            _scanTypeComboBox.SelectedIndex = 0;
            _scanTypeComboBox.SelectionChanged += ScanTypeComboBox_SelectionChanged;
        }

        private void LoadPageState()
        {
            var stateService = StateService.Instance;

            if (!string.IsNullOrEmpty(stateService.MiscPageLastIp))
                _ipTextBox.Text = stateService.MiscPageLastIp;

            if (!string.IsNullOrEmpty(stateService.MiscPageLastStartPort))
                _startPortTextBox.Text = stateService.MiscPageLastStartPort;

            if (!string.IsNullOrEmpty(stateService.MiscPageLastEndPort))
                _endPortTextBox.Text = stateService.MiscPageLastEndPort;

            if (!string.IsNullOrEmpty(stateService.MiscPageLastScanType))
            {
                _selectedScannerType = stateService.MiscPageLastScanType;
                var index = _scanTypeComboBox.Items.Cast<string>().ToList().IndexOf(_selectedScannerType);
                if (index >= 0)
                    _scanTypeComboBox.SelectedIndex = index;
            }

            _timeout = stateService.MiscPageTimeout;

            // Only restore from StateService when the static collection is empty
            // (i.e. first ever load). If it already has data it's from a live/prior scan.
            if (!_scanResults.Any() && stateService.MiscPageScanResults.Any())
            {
                foreach (var result in stateService.MiscPageScanResults)
                    _scanResults.Add(result);
            }
        }

        private void SavePageState()
        {
            var stateService = StateService.Instance;

            stateService.MiscPageLastIp = _ipTextBox?.Text?.Trim() ?? "";
            stateService.MiscPageLastStartPort = _startPortTextBox?.Text?.Trim() ?? "";
            stateService.MiscPageLastEndPort = _endPortTextBox?.Text?.Trim() ?? "";
            stateService.MiscPageLastScanType = _selectedScannerType;
            stateService.MiscPageTimeout = _timeout;

            stateService.MiscPageScanResults.Clear();
            foreach (var result in _scanResults)
            {
                stateService.MiscPageScanResults.Add(result);
            }

            stateService.SaveMiscellaneousPageState();
        }

        private void CVEViewButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var button = sender as Button;
                if (button?.DataContext is PortScanResult scanResult)
                {
                    var cveWindow = new CVEDetailsWindow(scanResult)
                    {
                        Owner = Window.GetWindow(this)
                    };

                    cveWindow.ShowDialog();
                }
                else
                {
                    AppDialog.Show("Could not retrieve scan result information.", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error opening CVE details: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ScanTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_scanTypeComboBox.SelectedItem != null)
            {
                _selectedScannerType = _scanTypeComboBox.SelectedItem.ToString();
                SavePageState();

                var scanner = ScannerFactory.GetScanner(_selectedScannerType);
                if (scanner.RequiresElevatedPrivileges)
                {
                    // Optionally show a warning
                }
            }
        }

        private async void StartScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning)
            {
                StopScan();
                return;
            }

            string ipAddress = _ipTextBox.Text.Trim();
            if (!IsValidIpAddress(ipAddress))
            {
                AppDialog.Show("Please enter a valid IP address.", "Invalid Input",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!int.TryParse(_startPortTextBox.Text, out int startPort) || startPort < 1 || startPort > 65535)
            {
                AppDialog.Show("Start port must be a number between 1 and 65535.", "Invalid Input",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!int.TryParse(_endPortTextBox.Text, out int endPort) || endPort < 1 || endPort > 65535)
            {
                AppDialog.Show("End port must be a number between 1 and 65535.", "Invalid Input",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (startPort > endPort)
            {
                AppDialog.Show("Start port must be less than or equal to end port.", "Invalid Range",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var scanner = ScannerFactory.GetScanner(_selectedScannerType);
            if (scanner.RequiresElevatedPrivileges && !IsRunningAsAdmin())
            {
                var result = AppDialog.Show(
                    $"The {_selectedScannerType} requires administrator privileges. Do you want to continue?",
                    "Elevated Privileges Required",
                    MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result == MessageBoxResult.No)
                    return;
            }

            // Read advanced options
            _bannerGrabbing = BannerGrabbingCheckBox.IsChecked ?? true;
            _versionDetection = VersionDetectionCheckBox.IsChecked ?? true;
            _aggressiveProbes = AggressiveProbesCheckBox.IsChecked ?? false;
            _timingTemplate = TimingComboBox.SelectedIndex;
            _randomizeOrder = RandomizeOrderCheckBox.IsChecked ?? false;

            SavePageState();
            _scanResults.Clear();
            _isScanning = true;
            _startScanButton.Content = "Stop Scan";
            _scanCancellationTokenSource = new CancellationTokenSource();

            try
            {
                await StartScanAsync(ipAddress, startPort, endPort, _scanCancellationTokenSource.Token);
                ProgressText.Text = "Scan completed successfully!";
            }
            catch (OperationCanceledException)
            {
                ProgressText.Text = "Scan was cancelled.";
            }
            catch (Exception ex)
            {
                AppDialog.Show($"An error occurred during the scan: {ex.Message}", "Scan Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isScanning = false;
                _startScanButton.Content = "Start Scan";
                _scanCancellationTokenSource = null;
                SavePageState();
            }
        }

        private void StopScan()
        {
            if (_scanCancellationTokenSource != null && !_scanCancellationTokenSource.IsCancellationRequested)
            {
                _scanCancellationTokenSource.Cancel();
            }
        }

        private bool IsValidIpAddress(string ipAddress)
        {
            return IPAddress.TryParse(ipAddress, out _);
        }

        private bool IsRunningAsAdmin()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private async Task StartScanAsync(string ipAddress, int startPort, int endPort, CancellationToken cancellationToken)
        {
            var scanner = ScannerFactory.GetScanner(_selectedScannerType);
            var openPorts = new List<PortScanResult>();

            int totalPorts = endPort - startPort + 1;
            int processedPorts = 0;

            // Calculate delay based on timing template
            int delayBetweenPorts = _timingTemplate switch
            {
                0 => 300000,  // Paranoid: 5 minutes
                1 => 15000,   // Sneaky: 15 seconds
                2 => 1000,    // Polite: 1 second
                3 => 0,       // Normal: no delay
                4 => 0,       // Aggressive: no delay
                5 => 0,       // Insane: no delay
                _ => 0
            };

            // Prepare port list
            var portsToScan = Enumerable.Range(startPort, totalPorts).ToList();

            // Randomize port order if requested
            if (_randomizeOrder)
            {
                var random = new Random();
                portsToScan = portsToScan.OrderBy(x => random.Next()).ToList();
                Console.WriteLine("🔀 Randomizing port scan order for stealth");
            }

            Application.Current.Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = 0;
                ScanProgressBar.Visibility = Visibility.Visible;
                ProgressText.Text = "Phase 1: Scanning for open ports...";
                ProgressText.Visibility = Visibility.Visible;
            });

            // Phase 1: Port Scanning
            foreach (int port in portsToScan)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var result = await scanner.ScanPortAsync(ipAddress, port, _timeout, cancellationToken);

                    if (result.IsOpen || result.Status == "Open" || result.Status == "Open|Filtered")
                    {
                        openPorts.Add(result);

                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            _scanResults.Add(result);
                        });
                    }

                    // Apply timing delay
                    if (delayBetweenPorts > 0)
                    {
                        await Task.Delay(delayBetweenPorts, cancellationToken);
                    }
                }
                catch (Exception ex) when (!(ex is OperationCanceledException))
                {
                    Console.WriteLine($"Error scanning port {port}: {ex.Message}");
                }

                processedPorts++;
                if (processedPorts % 10 == 0 || processedPorts == totalPorts)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        ScanProgressBar.Value = (double)processedPorts / totalPorts * 100;
                        ProgressText.Text = $"Phase 1: Scanning ports... {processedPorts}/{totalPorts}";
                    });
                }
            }

            // Phase 2: Service Detection (only if enabled)
            if (openPorts.Count > 0 && (_bannerGrabbing || _versionDetection))
            {
                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    ScanProgressBar.Value = 0;
                    ProgressText.Text = $"Phase 2: Detecting services on {openPorts.Count} open ports...";
                });

                processedPorts = 0;

                // Adjust detection timeout based on aggressive probes setting
                int detectionTimeout = _aggressiveProbes ? _timeout * 3 : _timeout * 2;

                foreach (var result in openPorts)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        if (_versionDetection || _bannerGrabbing)
                        {
                            var enhancedResult = await _serviceDetectionManager.DetectServiceAsync(
                                result,
                                detectionTimeout,
                                cancellationToken);

                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                int index = _scanResults.IndexOf(result);
                                if (index >= 0)
                                {
                                    _scanResults[index] = enhancedResult;
                                }
                            });
                        }
                    }
                    catch (Exception ex) when (!(ex is OperationCanceledException))
                    {
                        Console.WriteLine($"Error detecting service on port {result.Port}: {ex.Message}");
                    }

                    processedPorts++;
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (openPorts.Count > 0)
                        {
                            ScanProgressBar.Value = (double)processedPorts / openPorts.Count * 100;
                            ProgressText.Text = $"Phase 2: Detecting services... {processedPorts}/{openPorts.Count}";
                        }
                    });
                }
            }
            else if (!_bannerGrabbing && !_versionDetection)
            {
                Console.WriteLine("⚠️ Service detection skipped (disabled by user)");
            }

            Application.Current.Dispatcher.Invoke(() =>
            {
                string timingInfo = _timingTemplate switch
                {
                    0 => " (Paranoid timing)",
                    1 => " (Sneaky timing)",
                    2 => " (Polite timing)",
                    3 => "",
                    4 => " (Aggressive timing)",
                    5 => " (Insane timing)",
                    _ => ""
                };

                ProgressText.Text = $"Scan complete: {openPorts.Count} open ports found{timingInfo}";
            });

            SaveScanResultsToDashboard(ipAddress, startPort, endPort, _scanResults.ToList());
            SavePageState();
        }

        private async void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            if (!_scanResults.Any())
            {
                AppDialog.Show("Run a scan first.", "No Data", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Step 1: Run CVE checks FIRST before asking where to save
            var openPorts = _scanResults
                .Where(r => r.Status == "Open" && !string.IsNullOrWhiteSpace(r.Service))
                .ToList();

            if (openPorts.Any())
            {
                if (ExportReportButton != null) ExportReportButton.IsEnabled = false;
                ScanProgressBar.Visibility = Visibility.Visible;
                ScanProgressBar.Value = 0;
                ProgressText.Visibility = Visibility.Visible;

                foreach (var r in openPorts) { r.RiskLevel = "Checking…"; r.RiskColor = "#555555"; r.CveChecked = false; }

                var groups = openPorts
                    .GroupBy(r => $"{r.Service?.ToLower()}|{r.Version ?? ""}")
                    .ToList();

                int done = 0;
                foreach (var group in groups)
                {
                    var sample = group.First();
                    ProgressText.Text = $"CVE check {done + 1}/{groups.Count}: {sample.Service}…";

                    try
                    {
                        var issues = await _nvdChecker.CheckServiceVulnerabilities(
                            sample.Service, sample.Version ?? "");

                        var cves = issues
                            .Where(i => i.Category == "Vulnerability")
                            .Select(i => new CveSummary
                            {
                                CveId     = ParseCveIdFromDesc(i.Description),
                                Cvss      = i.CvssScore,
                                Severity  = i.Severity ?? "Low",
                                Summary   = ParseCveSummaryFromDesc(i.Description),
                                Reference = i.Recommendation ?? ""
                            })
                            .ToList();

                        string topSeverity = cves.Count == 0 ? "Clean"
                            : cves.Any(c => c.Severity == "Critical") ? "Critical"
                            : cves.Any(c => c.Severity == "High")     ? "High"
                            : cves.Any(c => c.Severity == "Medium")   ? "Medium"
                            : "Low";

                        string riskColor = topSeverity switch
                        {
                            "Critical" => "#F44747",
                            "High"     => "#FF8C00",
                            "Medium"   => "#FFA500",
                            "Low"      => "#4EC9B0",
                            _          => "#2E7D32"
                        };

                        foreach (var port in group)
                        {
                            port.CveFindings = cves;
                            port.VulnCount   = cves.Count;
                            port.RiskLevel   = topSeverity;
                            port.RiskColor   = riskColor;
                            port.CveChecked  = true;
                        }
                    }
                    catch
                    {
                        foreach (var port in group)
                        {
                            port.RiskLevel  = "Unknown";
                            port.RiskColor  = "#555555";
                            port.CveChecked = true;
                        }
                    }

                    done++;
                    ScanProgressBar.Value = (done * 100.0) / groups.Count;
                }

                ProgressText.Text = "CVE check complete — generating report…";
                if (ExportReportButton != null) ExportReportButton.IsEnabled = true;
            }

            // Step 2: CVE checks done — now ask where to save
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title  = "Save Scan Report",
                Filter = "HTML Report (*.html)|*.html",
                FileName = $"PortScan_{_ipTextBox?.Text?.Replace("/", "_")}_{DateTime.Now:yyyyMMdd_HHmmss}.html"
            };
            if (dlg.ShowDialog() != true)
            {
                ScanProgressBar.Visibility = Visibility.Collapsed;
                ProgressText.Visibility    = Visibility.Collapsed;
                return;
            }

            // Step 3: Generate and write the report
            try
            {
                string html = ReportGenerator.GeneratePortScanReport(
                    _ipTextBox?.Text ?? "Unknown",
                    int.TryParse(_startPortTextBox?.Text, out int sp) ? sp : 1,
                    int.TryParse(_endPortTextBox?.Text,   out int ep) ? ep : 1024,
                    _selectedScannerType,
                    _scanResults.ToList());

                File.WriteAllText(dlg.FileName, html, System.Text.Encoding.UTF8);
                ScanProgressBar.Visibility = Visibility.Collapsed;
                ProgressText.Visibility    = Visibility.Collapsed;
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                ScanProgressBar.Visibility = Visibility.Collapsed;
                ProgressText.Visibility    = Visibility.Collapsed;
                AppDialog.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string ParseCveIdFromDesc(string desc)
        {
            var m = System.Text.RegularExpressions.Regex.Match(desc ?? "", @"CVE-\d{4}-\d+");
            return m.Success ? m.Value : "N/A";
        }

        private static string ParseCveSummaryFromDesc(string desc)
        {
            if (string.IsNullOrEmpty(desc)) return "";
            var idx = desc.IndexOf(" - ");
            return idx >= 0 ? desc[(idx + 3)..].Trim() : desc;
        }


        private void ClearResultsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = AppDialog.Show(
                    "Are you sure you want to clear all scan results? This action cannot be undone.",
                    "Clear Results",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    // Clear the collection in-place — no ItemsSource rebind which resets column widths
                    _scanResults.Clear();

                    var stateService = StateService.Instance;
                    stateService.ClearMiscellaneousPageState();

                    ScanProgressBar.Value = 0;
                    ScanProgressBar.Visibility = Visibility.Collapsed;
                    ProgressText.Text = "";
                    ProgressText.Visibility = Visibility.Collapsed;

                    StartScanButton.IsEnabled = true;

                    AppDialog.Show("All scan results have been cleared.", "Results Cleared",
                                  MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error clearing results: {ex.Message}", "Error",
                              MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveScanResultsToDashboard(string ipAddress, int startPort, int endPort, List<PortScanResult> results)
        {
            try
            {
                var openPorts = results.Where(r => r.IsOpen).ToList();
                var portsWithVulnerabilities = openPorts.Where(r => HasVulnerabilities(r)).ToList();
                int totalVulnerabilities = portsWithVulnerabilities.Sum(r => CountVulnerabilities(r));
                string status = DetermineScanStatus(openPorts.Count, totalVulnerabilities);
                string emoji = GetVulnerabilityEmoji(totalVulnerabilities, openPorts.Count);
                string description = CreateScanDescription(ipAddress, openPorts.Count, totalVulnerabilities, portsWithVulnerabilities.Count);

                var mainWindow = Application.Current.MainWindow as MainWindow;
                var currentPage = mainWindow?.GetCurrentPage();

                var stateService = StateService.Instance;
                var scanResult = stateService.CreateScanResultWithContext(
                    type: $"Miscellaneous Port Scan {emoji}",
                    description: description,
                    status: status,
                    details: CreateScanDetails(ipAddress, startPort, endPort, openPorts, portsWithVulnerabilities, totalVulnerabilities),
                    pageType: PageTypes.Miscellaneous,
                    currentPage: currentPage
                );

                stateService.AddScanResult(scanResult);

                var scanHistory = ScanHistoryManager.LoadScanHistory();
                var date = DateTime.Now.Date;
                if (!scanHistory.ContainsKey(date))
                    scanHistory[date] = new List<ScanResult>();

                scanHistory[date].Add(scanResult);
                ScanHistoryManager.SaveScanHistory(scanHistory);

                Console.WriteLine($"Scan results saved to dashboard: {openPorts.Count} open ports, {totalVulnerabilities} vulnerabilities");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving scan results: {ex.Message}");
            }
        }

        private bool HasVulnerabilities(PortScanResult result)
        {
            return !string.IsNullOrEmpty(result.Service) &&
                   result.Service != "Unknown" &&
                   !string.IsNullOrEmpty(result.Version) &&
                   result.Version != "Unknown";
        }

        private int CountVulnerabilities(PortScanResult result)
        {
            // Use real CVE count if a check has been run, otherwise fall back to service-based estimate
            if (result.CveChecked) return result.VulnCount;
            if (HasVulnerabilities(result)) return 1; // unknown count, at least flag it
            return 0;
        }

        private string DetermineScanStatus(int openPorts, int totalVulnerabilities)
        {
            if (totalVulnerabilities == 0)
                return "Good";
            else if (totalVulnerabilities <= 5)
                return "Warning";
            else
                return "Error";
        }

        private string GetVulnerabilityEmoji(int totalVulnerabilities, int openPorts)
        {
            if (totalVulnerabilities == 0 && openPorts == 0)
                return "🔒";
            else if (totalVulnerabilities == 0)
                return "🛡️";
            else if (totalVulnerabilities <= 2)
                return "⚠️";
            else if (totalVulnerabilities <= 5)
                return "🚨";
            else
                return "💥";
        }

        private string CreateScanDescription(string ipAddress, int openPorts, int totalVulnerabilities, int vulnerablePorts)
        {
            if (openPorts == 0)
                return $"Scan of {ipAddress}: No open ports found - System appears secure";

            if (totalVulnerabilities == 0)
                return $"Scan of {ipAddress}: {openPorts} open ports found, no vulnerabilities detected";

            return $"Scan of {ipAddress}: {openPorts} open ports, {vulnerablePorts} potentially vulnerable, {totalVulnerabilities} total vulnerabilities";
        }

        private List<string> CreateScanDetails(string ipAddress, int startPort, int endPort,
            List<PortScanResult> openPorts, List<PortScanResult> vulnerablePorts, int totalVulnerabilities)
        {
            var details = new List<string>
            {
                $"Target: {ipAddress}",
                $"Port Range: {startPort}-{endPort}",
                $"Scan Type: {_selectedScannerType}",
                $"Open Ports: {openPorts.Count}",
                $"Vulnerable Services: {vulnerablePorts.Count}",
                $"Total Vulnerabilities: {totalVulnerabilities}",
                $"Scan Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}"
            };

            // Add advanced options info
            if (_randomizeOrder)
                details.Add("IDS Evasion: Port randomization enabled");

            if (_aggressiveProbes)
                details.Add("Service Detection: Aggressive probes enabled");

            string timingName = _timingTemplate switch
            {
                0 => "Paranoid",
                1 => "Sneaky",
                2 => "Polite",
                3 => "Normal",
                4 => "Aggressive",
                5 => "Insane",
                _ => "Unknown"
            };
            details.Add($"Timing Template: {timingName}");

            if (vulnerablePorts.Any())
            {
                details.Add("Top Vulnerable Services:");
                foreach (var port in vulnerablePorts.Take(3))
                {
                    var vulnCount = CountVulnerabilities(port);
                    details.Add($"  • Port {port.Port}: {port.Service} ({vulnCount} vulnerabilities)");
                }
            }

            if (openPorts.Any())
            {
                details.Add("Open Ports Summary:");
                var portSummary = string.Join(", ", openPorts.Take(10).Select(p => p.Port.ToString()));
                if (openPorts.Count > 10)
                    portSummary += $" (+{openPorts.Count - 10} more)";
                details.Add($"  {portSummary}");
            }

            return details;
        }
    }
}
