using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Net.NetworkInformation;
using System.Net;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.IO;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Models;
using System.Windows.Media;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class NetworkDiscoveryPage : Page, INotifyPropertyChanged
    {
        private readonly StateService _stateService = StateService.Instance;
        // Static so the running scan and its CTS survive page navigation
        private static CancellationTokenSource _cancellationTokenSource;
        private static volatile bool _isScanningInProgress;
        private readonly SemaphoreSlim _throttler;
        private Timer _continuousMonitoringTimer;
        private readonly OSDetector _osDetector = new OSDetector();

        // Observable Properties
        private string _networkInterfaceInfo;
        private int _activeDeviceCount;
        private string _currentIP;
        private string _searchFilter;

        public string NetworkInterfaceInfo
        {
            get => _networkInterfaceInfo;
            set
            {
                _networkInterfaceInfo = value;
                OnPropertyChanged();
            }
        }

        public int ActiveDeviceCount
        {
            get => _activeDeviceCount;
            set
            {
                if (_activeDeviceCount != value)
                {
                    _activeDeviceCount = value;
                    OnPropertyChanged();
                    // Remove this line that's causing the problem:
                    // UpdateDashboardCount(); 
                }
            }
        }

        public string CurrentIP
        {
            get => _currentIP;
            set
            {
                _currentIP = value;
                OnPropertyChanged(nameof(CurrentIP));
            }
        }

        public string SearchFilter
        {
            get => _searchFilter;
            set
            {
                _searchFilter = value;
                OnPropertyChanged();
                FilterDevices();
            }
        }


        public NetworkDiscoveryPage()
        {
            InitializeComponent();
            DataContext = _stateService;

            _throttler = new SemaphoreSlim(Environment.ProcessorCount * 2);
            _isScanningInProgress = false;
            ScanResultsGrid.ItemsSource = _stateService.NetworkScanResults;

            InitializeNetworkInfo();

            // Add this event handler for when the page loads
            this.Loaded += NetworkDiscoveryPage_Loaded;

            Debug.WriteLine("NetworkDiscoveryPage: Constructor completed");
        }
        private void NetworkDiscoveryPage_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                Debug.WriteLine("NetworkDiscoveryPage_Loaded: Page loaded event triggered");

                // First check if controls are accessible
                DebugControlAccess();

                // Delay UI restoration to ensure everything is fully loaded
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    Debug.WriteLine("NetworkDiscoveryPage_Loaded: Triggering UI state restoration");
                    RestoreUIState();
                    RestoreScanState();
                }), System.Windows.Threading.DispatcherPriority.Loaded);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"NetworkDiscoveryPage_Loaded: Error in loaded handler: {ex.Message}");
            }
        }

        private void InitializeNetworkInfo()
        {
            try
            {
                var activeInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.OperationalStatus == OperationalStatus.Up &&
                                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback);

                if (activeInterface != null)
                {
                    var ipProperties = activeInterface.GetIPProperties();
                    var ipAddress = ipProperties.UnicastAddresses
                        .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                    _stateService.CurrentIP = ipAddress?.Address.ToString() ?? "Not Found";
                    NetworkInterfaceInfo = $"{activeInterface.Name} - {activeInterface.Description}";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error initializing network info: {ex.Message}");
                CurrentIP = "Not Available";
                NetworkInterfaceInfo = "Network information unavailable";
            }
        }

        //private void LoadDefaultSettings()
        //{
        //    TimeoutInput.Text = "1000";
        //    ScanRangeInput.Text = $"{GetLocalNetworkPrefix()}.1";
        //    EnableOSDetection.IsChecked = true;
        //}

        //private string GetLocalNetworkPrefix()
        //{
        //    try
        //    {
        //        var ipParts = CurrentIP.Split('.');
        //        return string.Join(".", ipParts.Take(3));
        //    }
        //    catch
        //    {
        //        return "192.168.1";
        //    }
        //}

        private async Task<NetworkDevice> ScanDevice(string ip, int timeout)
        {
            string scanType = await Dispatcher.InvokeAsync(() =>
                (ScanTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString());

            try
            {
                NetworkDevice device = null;

                if (scanType == "ARP Scan (Fast)")
                {
                    device = await ARPScan(ip);
                }
                else // ICMP Scan
                {
                    device = await ICMPScan(ip, timeout);
                }

                if (device != null)
                {
                    bool shouldEnrich = await Dispatcher.InvokeAsync(() => EnableOSDetection.IsChecked ?? false);
                    if (shouldEnrich)
                    {
                        await EnrichDeviceInfo(device);
                    }
                }

                return device;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error scanning {ip}: {ex.Message}");
                return null;
            }
        }

        private async Task<NetworkDevice> ICMPScan(string ip, int timeout)
        {
            using var ping = new Ping();
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var reply = await ping.SendPingAsync(ip, timeout);
                sw.Stop();
                if (reply.Status == IPStatus.Success)
                {
                    return new NetworkDevice
                    {
                        IPAddress     = ip,
                        IsOnline      = true,
                        ResponseTimeMs = reply.RoundtripTime > 0 ? reply.RoundtripTime : sw.ElapsedMilliseconds
                    };
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ICMP scan error for {ip}: {ex.Message}");
            }
            return null;
        }

        private async Task<NetworkDevice> ARPScan(string ip)
        {
            try
            {
                using var ping = new Ping();
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var reply = await ping.SendPingAsync(ip, 150);
                sw.Stop();

                long rtt = reply.Status == IPStatus.Success
                    ? (reply.RoundtripTime > 0 ? reply.RoundtripTime : sw.ElapsedMilliseconds)
                    : -1;

                // Read ARP cache (no extra network probe needed — ping above populates it)
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName               = "arp",
                        Arguments              = $"-a {ip}",
                        UseShellExecute        = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow         = true
                    }
                };

                proc.Start();
                string output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                var match = output.Split('\n')
                    .FirstOrDefault(l => l.Contains(ip))
                    ?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .ElementAtOrDefault(1);

                if (!string.IsNullOrEmpty(match) && match.Contains("-"))
                {
                    return new NetworkDevice
                    {
                        IPAddress      = ip,
                        IsOnline       = true,
                        MACAddress     = match,
                        ResponseTimeMs = rtt
                    };
                }

                // ARP entry missing but ping succeeded
                if (reply.Status == IPStatus.Success)
                    return new NetworkDevice { IPAddress = ip, IsOnline = true, ResponseTimeMs = rtt };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ARP scan error for {ip}: {ex.Message}");
            }
            return null;
        }

        private static readonly int[] _quickPorts = { 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080 };

        private async Task EnrichDeviceInfo(NetworkDevice device)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));

                // Hostname
                try
                {
                    var hostTask = Dns.GetHostEntryAsync(device.IPAddress);
                    var entry    = await hostTask.WaitAsync(cts.Token);
                    device.Hostname = entry.HostName;
                }
                catch { device.Hostname = "—"; }

                // MAC address (from ARP cache)
                if (string.IsNullOrEmpty(device.MACAddress) || device.MACAddress == "Unknown")
                    device.MACAddress = await GetMacAddress(device.IPAddress);

                // Quick port scan (parallel, 300ms per port)
                var openPorts = new System.Collections.Concurrent.ConcurrentBag<int>();
                var portTasks = _quickPorts.Select(async p =>
                {
                    try
                    {
                        using var tcp = new System.Net.Sockets.TcpClient();
                        var conn = tcp.ConnectAsync(device.IPAddress, p);
                        if (await Task.WhenAny(conn, Task.Delay(300)) == conn && tcp.Connected)
                            openPorts.Add(p);
                    }
                    catch { }
                });
                await Task.WhenAll(portTasks);

                var sortedPorts = openPorts.OrderBy(x => x).ToList();
                device.OpenPorts = sortedPorts.Count > 0
                    ? string.Join(", ", sortedPorts)
                    : "—";

                // OS detection with timeout
                try
                {
                    var osTask = _osDetector.DetectOS(device.IPAddress);
                    device.OS = await osTask.WaitAsync(TimeSpan.FromSeconds(6));
                }
                catch (TimeoutException) { device.OS = DetermineOSFromPorts(sortedPorts); }
                catch              { device.OS = "Unknown"; }

                device.DeviceType = DetermineDeviceType(device.OS);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error enriching {device.IPAddress}: {ex.Message}");
            }
        }

        private static string DetermineOSFromPorts(List<int> ports)
        {
            if (ports.Contains(3389) || ports.Contains(445) || ports.Contains(139)) return "Windows";
            if (ports.Contains(22) && !ports.Contains(3389))                        return "Linux/Unix";
            if (ports.Contains(80) || ports.Contains(443))                          return "Network Device";
            return "Unknown";
        }

        private async Task<string> GetMacAddress(string ipAddress)
        {
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = $"-a {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                proc.Start();
                string output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                var macAddress = output.Split('\n')
                    .FirstOrDefault(l => l.Contains(ipAddress))
                    ?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .ElementAtOrDefault(1);

                return macAddress ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }



        private string DetermineDeviceType(string os)
        {
            return os switch
            {
                var x when x.Contains("Windows") => "Windows",
                var x when x.Contains("Linux") || x.Contains("Unix") => "Linux",
                var x when x.Contains("Network Device") => "Router",
                _ => "Unknown"
            };
        }

        private async void StartScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanningInProgress)
            {
                AppDialog.Show("A scan is already in progress.", "Scan in Progress",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!ValidateInput())
                return;

            _stateService.NetworkScanResults.Clear();
            UpdateUIForScanStart();
            await StartNetworkScan();
        }

        private async Task StartNetworkScan()
        {
            bool cancelled = false;
            try
            {
                _isScanningInProgress = true;
                _cancellationTokenSource = new CancellationTokenSource();

                string ipRange = await Dispatcher.InvokeAsync(() => ScanRangeInput.Text.Trim());
                int    timeout = await Dispatcher.InvokeAsync(() => int.TryParse(TimeoutInput.Text, out int t) ? t : 1000);

                await Task.Run(async () =>
                {
                    var (prefix, startHost, endHost) = ParseIPRange(ipRange);

                    if (startHost == endHost)
                        await ScanSingleIP($"{prefix}.{startHost}", timeout);
                    else
                        await ScanIPRange(prefix, startHost, endHost, timeout);
                }, _cancellationTokenSource.Token);

                bool enableContinuous = await Dispatcher.InvokeAsync(() =>
                    EnableContinuousMonitoring.IsChecked ?? false);
                if (enableContinuous)
                    StartContinuousMonitoring();
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
                await Dispatcher.InvokeAsync(() => UpdateStatus("Scan stopped"));
            }
            catch (Exception ex)
            {
                await Dispatcher.InvokeAsync(() =>
                    AppDialog.Show($"Scan error: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error));
            }
            finally
            {
                _isScanningInProgress = false;
                await Dispatcher.InvokeAsync(() => UpdateUIForScanComplete(cancelled));
            }
        }

        /// <summary>
        /// Parses any of: "192.168.1.1", "192.168.1.0/24", "192.168.1.1-50",
        /// "192.168.1.1-192.168.1.50", "192.168.1" (bare prefix → 1-254).
        /// Returns (threeOctetPrefix, startHostByte, endHostByte).
        /// </summary>
        private static (string prefix, int start, int end) ParseIPRange(string input)
        {
            input = input.Trim();

            // CIDR: 192.168.1.0/24
            if (input.Contains('/'))
            {
                var parts  = input.Split('/');
                var octets = parts[0].Split('.');
                return (string.Join(".", octets.Take(3)), 1, 254);
            }

            // Dash range: 192.168.1.1-50  or  192.168.1.1-192.168.1.50
            if (input.Contains('-'))
            {
                var dashParts  = input.Split('-');
                var startOcts  = dashParts[0].Trim().Split('.');
                var prefix     = string.Join(".", startOcts.Take(3));
                int startHost  = int.TryParse(startOcts.ElementAtOrDefault(3), out int sh) ? sh : 1;

                var endPart = dashParts[1].Trim();
                int endHost;
                if (endPart.Contains('.'))
                    endHost = int.TryParse(endPart.Split('.').ElementAtOrDefault(3), out int eh) ? eh : 254;
                else
                    endHost = int.TryParse(endPart, out int eh2) ? eh2 : 254;

                return (prefix, startHost, Math.Max(startHost, endHost));
            }

            // Single IP: 192.168.1.55
            var octs = input.Split('.');
            if (octs.Length == 4 && int.TryParse(octs[3], out int h))
                return (string.Join(".", octs.Take(3)), h, h);

            // Bare prefix: 192.168.1  → full subnet
            return (input.TrimEnd('.'), 1, 254);
        }

        private async Task ScanSingleIP(string ip, int timeout)
        {
            var device = await ScanDevice(ip, timeout);
            if (device != null)
            {
                UpdateProgress(1, 1);
                await AddDeviceToResults(device);
            }
        }

        private async Task ScanIPRange(string prefix, int startHost, int endHost, int timeout)
        {
            var ct    = _cancellationTokenSource.Token;
            var tasks = new List<Task>();
            int total = endHost - startHost + 1;
            int done  = 0;

            for (int i = startHost; i <= endHost; i++)
            {
                ct.ThrowIfCancellationRequested();
                await _throttler.WaitAsync(ct);

                int hostNum = i;
                string ip   = $"{prefix}.{hostNum}";

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var device = await ScanDevice(ip, timeout);
                        if (device != null)
                            await AddDeviceToResults(device);
                    }
                    finally
                    {
                        _throttler.Release();
                        int current = System.Threading.Interlocked.Increment(ref done);
                        await Dispatcher.InvokeAsync(() => UpdateProgress(current, total));
                    }
                }, ct));
            }

            await Task.WhenAll(tasks.Where(t => !t.IsCanceled && !t.IsFaulted));
        }

        private void StartContinuousMonitoring()
        {
            _continuousMonitoringTimer = new Timer(async _ =>
            {
                if (!_isScanningInProgress)
                {
                    await StartNetworkScan();
                }
            }, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }

        private void StopScanButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            _continuousMonitoringTimer?.Dispose();
            _continuousMonitoringTimer = null;
            UpdateStatus("Stopping scan...");
        }

        private void UpdateUIForScanStart()
        {
            Dispatcher.Invoke(() =>
            {
                StartScanButton.IsEnabled = false;
                StopScanButton.IsEnabled = true;
                ScanProgress.Value = 0;
                ScanProgress.Visibility = Visibility.Visible;
                ScanCompleteBorder.Visibility = Visibility.Collapsed;
                UpdateStatus("Scanning network...");
            });
        }

        private void UpdateUIForScanComplete(bool cancelled = false)
        {
            Dispatcher.Invoke(() =>
            {
                StartScanButton.IsEnabled = true;
                StopScanButton.IsEnabled  = false;
                ScanProgress.Value        = cancelled ? ScanProgress.Value : 100;
                ScanProgress.Visibility   = Visibility.Collapsed;

                ActiveDeviceCount = _stateService.NetworkScanResults.Count;

                if (cancelled)
                {
                    ScanCompleteBorder.Visibility = Visibility.Collapsed;
                    UpdateStatus($"Stopped — {ActiveDeviceCount} device{(ActiveDeviceCount == 1 ? "" : "s")} found");
                }
                else
                {
                    ScanCompleteBorder.Visibility = Visibility.Visible;
                    ScanSummary.Text = $"Found {ActiveDeviceCount} device{(ActiveDeviceCount == 1 ? "" : "s")}";
                    UpdateStatus("Scan complete");

                    // Save scan result and asset inventory only on clean completion
                    UpdateDeviceCounts();
                    var changeSummary = AssetInventoryService.Instance
                        .UpdateFromScan(_stateService.NetworkScanResults.ToList());
                    if (changeSummary.HasChanges)
                        NotificationUtils.ShowChangeDetected(changeSummary);
                }
            });
        }

        private void UpdateProgress(int current, int total)
        {
            Dispatcher.Invoke(() =>
            {
                ScanProgress.Value = (current * 100.0) / total;
                UpdateStatus($"Scanning: {current}/{total}");
            });
        }

        private void UpdateStatus(string status)
        {
            Dispatcher.Invoke(() => ScanStatus.Text = status);
        }

        private bool ValidateInput()
        {
            var ipRange = ScanRangeInput?.Text?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(ipRange))
            {
                AppDialog.Show("Please enter a valid IP address or range.", "Invalid Input",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!ValidationUtils.IsValidIpRangeOrCidr(ipRange))
            {
                AppDialog.Show(
                    "Invalid IP range format. Use a single IP (192.168.1.1), CIDR (192.168.1.0/24), or range (192.168.1.1-254).",
                    "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!int.TryParse(TimeoutInput?.Text, out int timeout) || timeout <= 0)
            {
                AppDialog.Show("Please enter a valid timeout value (positive integer).", "Invalid Input",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            return true;
        }

        private void UpdateDashboardCount()
        {
            _stateService.UpdateHostsScanned(ActiveDeviceCount);

            var deviceTypes = _stateService.NetworkScanResults
                .GroupBy(d => d.DeviceType)
                .ToDictionary(g => g.Key, g => g.Count());

            _stateService.UpdateNetworkStats(
                deviceTypes.GetValueOrDefault("Windows", 0),
                deviceTypes.GetValueOrDefault("Linux", 0),
                deviceTypes.GetValueOrDefault("Router", 0)
            );

            var scanResult = new ScanResult
            {
                Timestamp = DateTime.Now,
                Type = "Network Scan",
                Description = $"Found {ActiveDeviceCount} devices on network",
                Status = ActiveDeviceCount > 0 ? "Good" : "Warning",
                Details = new List<string>
                {
                    $"Windows Devices: {deviceTypes.GetValueOrDefault("Windows", 0)}",
                    $"Linux Devices: {deviceTypes.GetValueOrDefault("Linux", 0)}",
                    $"Network Devices: {deviceTypes.GetValueOrDefault("Router", 0)}",
                    $"Unknown Devices: {deviceTypes.GetValueOrDefault("Unknown", 0)}",
                    $"Scan Range: {ScanRangeInput.Text}",
                    $"Scan Time: {DateTime.Now:HH:mm:ss}"
                }
            };

            _stateService.AddScanResult(scanResult);
        }

        private void UpdateDeviceCounts()
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(UpdateDeviceCounts);
                return;
            }

            ActiveDeviceCount = _stateService.NetworkScanResults.Count;

            var deviceTypes = _stateService.NetworkScanResults
                .GroupBy(d => d.DeviceType)
                .ToDictionary(g => g.Key, g => g.Count());

            _stateService.UpdateNetworkStats(
                deviceTypes.GetValueOrDefault("Windows", 0),
                deviceTypes.GetValueOrDefault("Linux", 0),
                deviceTypes.GetValueOrDefault("Router", 0)
            );

            _stateService.UpdateHostsScanned(ActiveDeviceCount);

            // Get reference to MainWindow to access current page for screenshot
            var mainWindow = Application.Current.MainWindow as MainWindow;
            var currentPage = mainWindow?.GetCurrentPage();

            // CRITICAL FIX: Create a SNAPSHOT of the current state, not a reference
            var stateSnapshot = new Dictionary<string, object>
            {
                // Snapshot the CURRENT UI values (not StateService properties)
                ["LastScanRange"] = ScanRangeInput?.Text ?? "",
                ["LastTimeout"] = int.TryParse(TimeoutInput?.Text, out int timeout) ? timeout : 1000,
                ["LastScanType"] = (ScanTypeComboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "",
                ["WasSingleIpScan"] = false,

                // Snapshot the scan results at this moment
                ["NetworkScanResults"] = _stateService.NetworkScanResults.ToList(), // Create a copy
                ["HostsScanned"] = ActiveDeviceCount,
                ["WindowsDevices"] = deviceTypes.GetValueOrDefault("Windows", 0),
                ["LinuxDevices"] = deviceTypes.GetValueOrDefault("Linux", 0),
                ["NetworkDevicesCount"] = deviceTypes.GetValueOrDefault("Router", 0)
            };

            // Create scan result with the snapshot
            var scanResult = new ScanResult
            {
                Timestamp = DateTime.Now,
                Type = "Network Discovery Scan",
                Description = $"Discovered {ActiveDeviceCount} devices in network {ScanRangeInput?.Text ?? "Unknown"}",
                Status = ActiveDeviceCount > 0 ? "Good" : "Warning",
                Details = new List<string>
        {
            $"Windows Devices: {deviceTypes.GetValueOrDefault("Windows", 0)}",
            $"Linux Devices: {deviceTypes.GetValueOrDefault("Linux", 0)}",
            $"Network Devices: {deviceTypes.GetValueOrDefault("Router", 0)}",
            $"Unknown Devices: {deviceTypes.GetValueOrDefault("Unknown", 0)}",
            $"Scan Range: {ScanRangeInput?.Text ?? "Unknown"}",
            $"Scan Type: {(ScanTypeComboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Unknown"}",
            $"Timeout: {TimeoutInput?.Text ?? "1000"}ms",
            $"Scan Time: {DateTime.Now:HH:mm:ss}"
        },
                PageType = PageTypes.NetworkDiscovery,
                PageState = stateSnapshot, // Use the snapshot, not CapturePageState
                ScanId = Guid.NewGuid().ToString()
            };

            // Capture screenshot
            if (currentPage != null)
            {
                try
                {
                    currentPage.UpdateLayout();
                    var screenshot = ScreenshotUtility.CapturePage(currentPage);
                    if (screenshot != null)
                    {
                        scanResult.PageSnapshot = screenshot;
                        scanResult.SnapshotData = ScreenshotUtility.BitmapToBase64(screenshot);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error capturing screenshot: {ex.Message}");
                }
            }

            _stateService.AddScanResult(scanResult);

            Debug.WriteLine($"UpdateDeviceCounts: Created scan result with snapshot - Range: '{stateSnapshot["LastScanRange"]}', Results: {ActiveDeviceCount}");
        }

        private void FilterDevices()
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(FilterDevices);
                return;
            }

            if (string.IsNullOrWhiteSpace(SearchFilter))
            {
                ScanResultsGrid.ItemsSource = _stateService.NetworkScanResults;
                return;
            }

            var filteredDevices = _stateService.NetworkScanResults
                .Where(d => d.IPAddress.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ||
                           (d.Hostname?.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ?? false) ||
                           (d.MACAddress?.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ?? false) ||
                           (d.OS?.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ?? false));

            ScanResultsGrid.ItemsSource = new ObservableCollection<NetworkDevice>(filteredDevices);
        }
        public void RestoreUIState()
        {
            try
            {
                Debug.WriteLine("=== RESTORE UI STATE DEBUG ===");
                Debug.WriteLine($"RestoreUIState: Starting UI state restoration for NetworkDiscoveryPage");

                // Check StateService values first
                Debug.WriteLine($"StateService.LastScanRange: '{_stateService.LastScanRange}'");
                Debug.WriteLine($"StateService.LastTimeout: {_stateService.LastTimeout}");
                Debug.WriteLine($"StateService.LastScanType: '{_stateService.LastScanType}'");
                Debug.WriteLine($"StateService.WasSingleIpScan: {_stateService.WasSingleIpScan}");
                Debug.WriteLine($"StateService.NetworkScanResults.Count: {_stateService.NetworkScanResults.Count}");

                // Check current UI values BEFORE restoration
                Debug.WriteLine($"BEFORE - ScanRangeInput.Text: '{ScanRangeInput?.Text}'");
                Debug.WriteLine($"BEFORE - TimeoutInput.Text: '{TimeoutInput?.Text}'");
                Debug.WriteLine($"BEFORE - SingleIPCheckbox.IsChecked: {false}");
                Debug.WriteLine($"BEFORE - ScanTypeComboBox.SelectedIndex: {ScanTypeComboBox?.SelectedIndex}");

                // Restore form controls from StateService
                if (!string.IsNullOrEmpty(_stateService.LastScanRange))
                {
                    ScanRangeInput.Text = _stateService.LastScanRange;
                    Debug.WriteLine($"✓ Set scan range to: {_stateService.LastScanRange}");
                }
                else
                {
                    Debug.WriteLine("✗ LastScanRange is null or empty");
                }

                if (_stateService.LastTimeout > 0)
                {
                    TimeoutInput.Text = _stateService.LastTimeout.ToString();
                    Debug.WriteLine($"✓ Set timeout to: {_stateService.LastTimeout}");
                }
                else
                {
                    Debug.WriteLine("✗ LastTimeout is 0 or negative");
                }

                if (!string.IsNullOrEmpty(_stateService.LastScanType))
                {
                    Debug.WriteLine($"Attempting to find scan type: '{_stateService.LastScanType}'");
                    bool foundScanType = false;

                    for (int i = 0; i < ScanTypeComboBox.Items.Count; i++)
                    {
                        if (ScanTypeComboBox.Items[i] is ComboBoxItem item)
                        {
                            Debug.WriteLine($"  Checking item {i}: '{item.Content}'");
                            if (item.Content.ToString() == _stateService.LastScanType)
                            {
                                ScanTypeComboBox.SelectedIndex = i;
                                foundScanType = true;
                                Debug.WriteLine($"✓ Set scan type to index {i}: {_stateService.LastScanType}");
                                break;
                            }
                        }
                    }

                    if (!foundScanType)
                    {
                        Debug.WriteLine($"✗ Could not find scan type '{_stateService.LastScanType}' in ComboBox");
                    }
                }
                else
                {
                    Debug.WriteLine("✗ LastScanType is null or empty");
                }

                // SingleIPCheckbox removed — single IP is now auto-detected from input

                // Check UI values AFTER restoration
                Debug.WriteLine($"AFTER - ScanRangeInput.Text: '{ScanRangeInput?.Text}'");
                Debug.WriteLine($"AFTER - TimeoutInput.Text: '{TimeoutInput?.Text}'");
                Debug.WriteLine($"AFTER - SingleIPCheckbox.IsChecked: {false}");
                Debug.WriteLine($"AFTER - ScanTypeComboBox.SelectedIndex: {ScanTypeComboBox?.SelectedIndex}");

                // Update device counts and UI
                ActiveDeviceCount = _stateService.NetworkScanResults.Count;
                Debug.WriteLine($"✓ Set ActiveDeviceCount to: {ActiveDeviceCount}");

                // Force grid refresh
                var currentItems = _stateService.NetworkScanResults.ToList();
                Debug.WriteLine($"Network scan results to restore: {currentItems.Count}");

                foreach (var device in currentItems.Take(5)) // Show first 5 for debugging
                {
                    Debug.WriteLine($"  Device: {device.IPAddress} - {device.Hostname} - {device.OS}");
                }

                ScanResultsGrid.ItemsSource = null;
                ScanResultsGrid.ItemsSource = _stateService.NetworkScanResults;
                ScanResultsGrid.Items.Refresh();
                Debug.WriteLine($"✓ Refreshed grid with {_stateService.NetworkScanResults.Count} items");

                // Force UI update
                this.UpdateLayout();
                Debug.WriteLine("✓ Forced layout update");

                Debug.WriteLine("=== RESTORE UI STATE COMPLETE ===");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"RestoreUIState: ERROR - {ex.Message}");
                Debug.WriteLine($"RestoreUIState: Stack trace - {ex.StackTrace}");
            }
        }


        private void RestoreScanState()
        {
            if (!_isScanningInProgress) return;
            StartScanButton.IsEnabled = false;
            StopScanButton.IsEnabled  = true;
            ScanProgress.Visibility   = Visibility.Visible;
            ScanCompleteBorder.Visibility = Visibility.Collapsed;
            UpdateStatus("Scan in progress...");
        }

        public void DebugControlAccess()
        {
            Debug.WriteLine("=== CONTROL ACCESS DEBUG ===");
            Debug.WriteLine($"ScanRangeInput: {(ScanRangeInput != null ? "ACCESSIBLE" : "NULL")}");
            Debug.WriteLine($"TimeoutInput: {(TimeoutInput != null ? "ACCESSIBLE" : "NULL")}");
            Debug.WriteLine($"SingleIPCheckbox: {("REMOVED")}");
            Debug.WriteLine($"ScanTypeComboBox: {(ScanTypeComboBox != null ? "ACCESSIBLE" : "NULL")}");
            Debug.WriteLine($"ScanResultsGrid: {(ScanResultsGrid != null ? "ACCESSIBLE" : "NULL")}");

            if (ScanTypeComboBox != null)
            {
                Debug.WriteLine($"ScanTypeComboBox.Items.Count: {ScanTypeComboBox.Items.Count}");
                for (int i = 0; i < ScanTypeComboBox.Items.Count; i++)
                {
                    if (ScanTypeComboBox.Items[i] is ComboBoxItem item)
                    {
                        Debug.WriteLine($"  Item {i}: {item.Content}");
                    }
                }
            }
            Debug.WriteLine("=== CONTROL ACCESS COMPLETE ===");
        }


        private void ExportResults()
        {
            try
            {
                var devices = _stateService.NetworkScanResults;
                var csv = new StringBuilder();

                csv.AppendLine("IP Address,Hostname,MAC Address,OS,Status");

                foreach (var device in devices)
                {
                    csv.AppendLine($"{device.IPAddress},{device.Hostname},{device.MACAddress}," +
                                 $"{device.OS},{(device.IsOnline ? "Online" : "Offline")}");
                }

                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var fileName = $"network_scan_{timestamp}.csv";
                File.WriteAllText(fileName, csv.ToString());

                AppDialog.Show($"Results exported to {fileName}", "Export Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error exporting results: {ex.Message}", "Export Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void Page_Unloaded(object sender, RoutedEventArgs e)
        {
            // Do NOT cancel the scan on navigation — it should keep running.
            // Only dispose the continuous-monitoring timer (it will restart when page reloads).
            _continuousMonitoringTimer?.Dispose();
            _continuousMonitoringTimer = null;
        }
        private void ClearScanResultsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = AppDialog.Show(
                    "Clear the displayed scan results?",
                    "Clear Display",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    // Stop ongoing scans
                    if (_isScanningInProgress)
                    {
                        _cancellationTokenSource?.Cancel();
                        _continuousMonitoringTimer?.Dispose();
                        _continuousMonitoringTimer = null;
                    }

                    // Clear through the actual collection so the binding stays intact
                    _stateService.NetworkScanResults.Clear();
                    ScanResultsGrid.ItemsSource = _stateService.NetworkScanResults;

                    // Set the display count directly without triggering saves
                    _activeDeviceCount = 0;  // Direct field assignment
                    OnPropertyChanged(nameof(ActiveDeviceCount));

                    // Reset UI state
                    ScanProgress.Value = 0;
                    ScanProgress.Visibility = Visibility.Collapsed;
                    ScanStatus.Text = "Ready to scan";
                    ScanCompleteBorder.Visibility = Visibility.Collapsed;
                    ScanSummary.Text = "";
                    StartScanButton.IsEnabled = true;
                    StopScanButton.IsEnabled = false;
                    _isScanningInProgress = false;

                    // DO NOT call any StateService update methods here!
                    // DO NOT call UpdateDeviceCounts()!
                    // DO NOT modify _stateService.NetworkScanResults!

                    AppDialog.Show("Display cleared. Saved data preserved.", "Cleared",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private async Task AddDeviceToResults(NetworkDevice device)
        {
            if (device == null) return;

            await Dispatcher.InvokeAsync(() =>
            {
                var existing = _stateService.NetworkScanResults
                    .FirstOrDefault(d => d.IPAddress == device.IPAddress);

                if (existing == null)
                {
                    _stateService.NetworkScanResults.Add(device);
                }
                else
                {
                    existing.IsOnline       = device.IsOnline;
                    existing.Hostname       = device.Hostname;
                    existing.MACAddress     = device.MACAddress;
                    existing.OS             = device.OS;
                    existing.DeviceType     = device.DeviceType;
                    existing.ResponseTimeMs = device.ResponseTimeMs;
                    existing.OpenPorts      = device.OpenPorts;
                }

                // Live count update (cheap — no screenshot or scan result write)
                ActiveDeviceCount = _stateService.NetworkScanResults.Count;
            });
        }

        private void ExportNetworkCsv_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ExportUtils.ExportNetworkDevicesToCsv(_stateService.NetworkScanResults.ToList());
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ExportNetworkCsv] {ex.Message}");
                AppDialog.Show($"Error exporting CSV: {ex.Message}", "Export Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportNetworkJson_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ExportUtils.ExportNetworkDevicesToJson(_stateService.NetworkScanResults.ToList());
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ExportNetworkJson] {ex.Message}");
                AppDialog.Show($"Error exporting JSON: {ex.Message}", "Export Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}

