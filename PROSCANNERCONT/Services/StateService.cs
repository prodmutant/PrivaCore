using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.IO;
using PROSCANNERCONT.Models;
using System.Linq;
using System.Windows;
using System.Diagnostics;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using System.Windows.Media;
using System.Globalization;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public partial class StateService : INotifyPropertyChanged
    {
        private static readonly Lazy<StateService> _instance = new Lazy<StateService>(() => new StateService());
        public static StateService Instance => _instance.Value;

        private int _hostsScanned;
        private int _windowsDevices;
        private int _linuxDevices;
        private int _networkDevices;
        private string _lastScanRange;
        private int _lastTimeout;
        private string _lastScanType;
        private bool _wasSingleIpScan;
        private bool _isScanInProgress;

        public ObservableCollection<NetworkDevice> NetworkScanResults { get; private set; }
        public ObservableCollection<ScanResult> ScanHistory { get; private set; }
        public ObservableCollection<ScanResult> RecentScanResults { get; private set; }
        public ObservableCollection<PortScanResult> VulnerabilityScanResults { get; private set; }
        public ObservableCollection<PacketInfo> TrafficAnalysisPackets { get; private set; }
        public ObservableCollection<PortScanResult> MiscPageScanResults { get; private set; }

        public int HostsScanned
        {
            get => _hostsScanned;
            private set
            {
                if (_hostsScanned != value)
                {
                    _hostsScanned = value;
                    OnPropertyChanged();
                }
            }
        }

        public int WindowsDevices
        {
            get => _windowsDevices;
            private set
            {
                if (_windowsDevices != value)
                {
                    _windowsDevices = value;
                    OnPropertyChanged();
                }
            }
        }

        public int LinuxDevices
        {
            get => _linuxDevices;
            private set
            {
                if (_linuxDevices != value)
                {
                    _linuxDevices = value;
                    OnPropertyChanged();
                }
            }
        }

        public int NetworkDevices
        {
            get => _networkDevices;
            private set
            {
                if (_networkDevices != value)
                {
                    _networkDevices = value;
                    OnPropertyChanged();
                }
            }
        }

        public string LastScanRange
        {
            get => _lastScanRange;
            set
            {
                if (_lastScanRange != value)
                {
                    _lastScanRange = value;
                    OnPropertyChanged();
                }
            }
        }

        public int LastTimeout
        {
            get => _lastTimeout;
            set
            {
                if (_lastTimeout != value)
                {
                    _lastTimeout = value;
                    OnPropertyChanged();
                }
            }
        }

        public string LastScanType
        {
            get => _lastScanType;
            set
            {
                if (_lastScanType != value)
                {
                    _lastScanType = value;
                    OnPropertyChanged();
                }
            }
        }
        private BitmapSource CreateMockThumbnail(string scanType, string status)
        {
            var width = 120;
            var height = 80;
            var dpi = 96;

            var renderTarget = new RenderTargetBitmap(width, height, dpi, dpi, PixelFormats.Pbgra32);

            var visual = new DrawingVisual();
            using (var context = visual.RenderOpen())
            {
                // Background gradient based on status
                var startColor = status switch
                {
                    "Good" => Color.FromRgb(76, 175, 80),    // Green
                    "Warning" => Color.FromRgb(255, 193, 7), // Yellow  
                    "Error" => Color.FromRgb(244, 67, 54),   // Red
                    _ => Color.FromRgb(158, 158, 158)        // Gray
                };

                var endColor = Color.FromRgb(
                    (byte)(startColor.R * 0.8),
                    (byte)(startColor.G * 0.8),
                    (byte)(startColor.B * 0.8)
                );

                var gradientBrush = new LinearGradientBrush(startColor, endColor, 45);
                context.DrawRectangle(gradientBrush, null, new Rect(0, 0, width, height));

                // Add border
                var borderPen = new Pen(Brushes.White, 1);
                context.DrawRectangle(null, borderPen, new Rect(0.5, 0.5, width - 1, height - 1));

                // Add scan type text - FIX: Use FontFamily properly
                var mainText = new FormattedText(
                    TruncateText(scanType, 16),
                    CultureInfo.CurrentCulture,
                    FlowDirection.LeftToRight,
                    new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal),
                    11,
                    Brushes.White,
                    dpi
                );

                // Center the text
                var textX = (width - mainText.Width) / 2;
                var textY = (height - mainText.Height) / 2;
                context.DrawText(mainText, new Point(Math.Max(4, textX), Math.Max(4, textY)));

                // Add status indicator in corner
                var statusBrush = new SolidColorBrush(Colors.White);
                context.DrawEllipse(statusBrush, null, new Point(width - 10, 10), 4, 4);
            }

            renderTarget.Render(visual);
            renderTarget.Freeze();
            return renderTarget;
        }
        private string TruncateText(string text, int maxLength)
        {
            if (string.IsNullOrEmpty(text) || text.Length <= maxLength)
                return text;

            return text.Substring(0, maxLength - 3) + "...";
        }


        public bool WasSingleIpScan
        {
            get => _wasSingleIpScan;
            set
            {
                if (_wasSingleIpScan != value)
                {
                    _wasSingleIpScan = value;
                    OnPropertyChanged();
                }
            }
        }

        public bool IsScanInProgress
        {
            get => _isScanInProgress;
            set
            {
                if (_isScanInProgress != value)
                {
                    _isScanInProgress = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? LastVulnScanIpRange { get; set; }
        public string? LastVulnScanPortRange { get; set; }
        public string? LastVulnScanType { get; set; }
        public bool IsVulnScanInProgress { get; set; }
        public bool VulnScanServiceDetectionEnabled { get; set; }
        public string VulnScanConcurrentScans { get; set; } = "100";

        public string? MiscPageLastIp { get; set; }
        public string? MiscPageLastStartPort { get; set; }
        public string? MiscPageLastEndPort { get; set; }
        public string? MiscPageLastScanType { get; set; }
        public int MiscPageTimeout { get; set; }

        public Dictionary<int, string>? ServiceMap { get; set; }

        public string? Time { get; set; }
        public string? SourceIP { get; set; }
        public string? DestinationIP { get; set; }
        public string? Protocol { get; set; }
        public string? Length { get; set; }
        public string? Info { get; set; }

        private string _currentIP;
        public string CurrentIP
        {
            get => _currentIP;
            set
            {
                if (_currentIP != value)
                {
                    _currentIP = value;
                    OnPropertyChanged(nameof(CurrentIP));
                }
            }
        }

        private class HostCountState
        {
            public int HostsScanned { get; set; }
            public int WindowsDevices { get; set; }
            public int LinuxDevices { get; set; }
            public int NetworkDevices { get; set; }
        }

        private class VulnerabilityPageState
        {
            public string LastVulnScanIpRange { get; set; }
            public string LastVulnScanPortRange { get; set; }
            public string LastVulnScanType { get; set; }
            public bool IsVulnScanInProgress { get; set; }
            public bool VulnScanServiceDetectionEnabled { get; set; }
            public string VulnScanConcurrentScans { get; set; }
        }

        private class MiscellaneousPageState
        {
            public string LastIp { get; set; }
            public string LastStartPort { get; set; }
            public string LastEndPort { get; set; }
            public string LastScanType { get; set; }
            public int Timeout { get; set; }
            public List<PortScanResult> ScanResults { get; set; }
        }

        private class TrafficAnalysisState
        {
            public List<PacketInfo> Packets { get; set; }
            public string Time { get; set; }
            public string SourceIP { get; set; }
            public string DestinationIP { get; set; }
            public string Protocol { get; set; }
            public string Length { get; set; }
            public string Info { get; set; }
        }
        public ScanResult CreateScanResultWithContext(string type, string description, string status,
            List<string> details, string pageType, Page? currentPage = null)
        {
            var scanResult = new ScanResult
            {
                Timestamp = DateTime.Now,
                Type = type,
                Description = description,
                Status = status,
                Details = details ?? new List<string>(),
                PageType = pageType,
                // Use the new UI capture method instead of the old one
                PageState = currentPage != null ? CaptureUIStateFromPage(currentPage, pageType) : CapturePageState(pageType)
            };

            Debug.WriteLine($"Creating scan result: {type} for page: {pageType}");

            // Try to capture page screenshot if page is provided
            if (currentPage != null)
            {
                try
                {
                    Debug.WriteLine($"Attempting to capture screenshot for page: {currentPage.GetType().Name}");

                    // Ensure the page is loaded and rendered
                    currentPage.UpdateLayout();

                    var screenshot = ScreenshotUtility.CapturePage(currentPage);
                    if (screenshot != null)
                    {
                        scanResult.PageSnapshot = screenshot;

                        // CRITICAL FIX: Convert to Base64 for serialization
                        scanResult.SnapshotData = ScreenshotUtility.BitmapToBase64(screenshot);

                        Debug.WriteLine($"Successfully captured screenshot and converted to Base64: {scanResult.SnapshotData?.Length ?? 0} characters");
                    }
                    else
                    {
                        Debug.WriteLine("ScreenshotUtility.CapturePage returned null");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error capturing page screenshot: {ex.Message}");
                    Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                }
            }
            else
            {
                Debug.WriteLine("No current page provided for screenshot capture");
            }

            // Create mock thumbnail if no real screenshot
            if (scanResult.PageSnapshot == null)
            {
                try
                {
                    Debug.WriteLine($"Creating mock thumbnail for: {type} with status: {status}");
                    var mockThumbnail = CreateMockThumbnail(type, status);
                    if (mockThumbnail != null)
                    {
                        scanResult.PageSnapshot = mockThumbnail;

                        // CRITICAL FIX: Convert mock thumbnail to Base64 too
                        scanResult.SnapshotData = ScreenshotUtility.BitmapToBase64(mockThumbnail);

                        Debug.WriteLine($"Mock thumbnail created and converted to Base64: {scanResult.SnapshotData?.Length ?? 0} characters");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error creating mock thumbnail: {ex.Message}");
                }
            }

            // Final validation
            if (scanResult.PageSnapshot != null && string.IsNullOrEmpty(scanResult.SnapshotData))
            {
                Debug.WriteLine("WARNING: PageSnapshot exists but SnapshotData is empty - attempting conversion");
                try
                {
                    scanResult.SnapshotData = ScreenshotUtility.BitmapToBase64(scanResult.PageSnapshot);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Failed to convert existing PageSnapshot to Base64: {ex.Message}");
                }
            }

            Debug.WriteLine($"Final scan result - HasSnapshot: {scanResult.PageSnapshot != null}, SnapshotDataLength: {scanResult.SnapshotData?.Length ?? 0}");
            Debug.WriteLine($"PageState captured with {scanResult.PageState.Count} properties");

            return scanResult;
        }
        private StateService()
        {
            NetworkScanResults = new ObservableCollection<NetworkDevice>();
            ScanHistory = new ObservableCollection<ScanResult>();
            RecentScanResults = new ObservableCollection<ScanResult>();
            VulnerabilityScanResults = new ObservableCollection<PortScanResult>();
            TrafficAnalysisPackets = new ObservableCollection<PacketInfo>();
            MiscPageScanResults = new ObservableCollection<PortScanResult>();
            ServiceMap = new Dictionary<int, string>();
            LastTimeout = AppConstants.State.DefaultRequestTimeoutMs;
            VulnScanConcurrentScans = AppConstants.State.DefaultVulnConcurrentScans;
            VulnScanServiceDetectionEnabled = false;
            MiscPageTimeout = AppConstants.State.DefaultMiscPageTimeoutMs;

            try
            {
                LoadHostCount();
                LoadScanResults();
                LoadVulnerabilityScanResults();
                LoadVulnerabilityPageState();
                LoadMiscellaneousPageState();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading state: {ex.Message}");
            }
        }

        public void SaveMiscellaneousPageState()
        {
            try
            {
                var pageState = new MiscellaneousPageState
                {
                    LastIp = MiscPageLastIp ?? "",
                    LastStartPort = MiscPageLastStartPort ?? "",
                    LastEndPort = MiscPageLastEndPort ?? "",
                    LastScanType = MiscPageLastScanType ?? "",
                    Timeout = MiscPageTimeout,
                    ScanResults = new List<PortScanResult>(MiscPageScanResults)
                };

                string json = JsonSerializer.Serialize(pageState, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText("miscellaneousPageState.json", json);
                Debug.WriteLine("Miscellaneous page state saved successfully");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving miscellaneous page state: {ex.Message}");
            }
        }

        public void LoadMiscellaneousPageState()
        {
            try
            {
                if (File.Exists("miscellaneousPageState.json"))
                {
                    string json = File.ReadAllText("miscellaneousPageState.json");
                    var pageState = JsonSerializer.Deserialize<MiscellaneousPageState>(json);

                    if (pageState != null)
                    {
                        MiscPageLastIp = pageState.LastIp;
                        MiscPageLastStartPort = pageState.LastStartPort;
                        MiscPageLastEndPort = pageState.LastEndPort;
                        MiscPageLastScanType = pageState.LastScanType;
                        MiscPageTimeout = pageState.Timeout > 0 ? pageState.Timeout : AppConstants.State.DefaultMiscPageTimeoutMs;

                        MiscPageScanResults.Clear();
                        if (pageState.ScanResults != null)
                        {
                            foreach (var result in pageState.ScanResults)
                            {
                                MiscPageScanResults.Add(result);
                            }
                        }
                    }
                    Debug.WriteLine("Miscellaneous page state loaded successfully");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading miscellaneous page state: {ex.Message}");
            }
        }

        public void ClearMiscellaneousPageState()
        {
            try
            {
                if (Application.Current != null)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        MiscPageScanResults.Clear();
                    });
                }
                else
                {
                    MiscPageScanResults.Clear();
                }

                MiscPageLastIp = "";
                MiscPageLastStartPort = "";
                MiscPageLastEndPort = "";
                MiscPageLastScanType = "";
                MiscPageTimeout = AppConstants.State.DefaultMiscPageTimeoutMs;

                SaveMiscellaneousPageState();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error clearing miscellaneous page state: {ex.Message}");
            }
        }

        public void SaveNetworkScanResults()
        {
            try
            {
                string json = JsonSerializer.Serialize(NetworkScanResults);
                File.WriteAllText("networkScanResults.json", json);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to save network scan results", ex);
            }
        }

        public void LoadNetworkScanResults()
        {
            try
            {
                if (File.Exists("networkScanResults.json"))
                {
                    string json = File.ReadAllText("networkScanResults.json");
                    var devices = JsonSerializer.Deserialize<ObservableCollection<NetworkDevice>>(json);
                    if (devices != null)
                    {
                        NetworkScanResults = devices;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to load network scan results", ex);
            }
        }

        public void SaveHostCount()
        {
            try
            {
                var hostCountState = new HostCountState
                {
                    HostsScanned = HostsScanned,
                    WindowsDevices = WindowsDevices,
                    LinuxDevices = LinuxDevices,
                    NetworkDevices = NetworkDevices
                };

                string json = JsonSerializer.Serialize(hostCountState);
                File.WriteAllText("hostCountState.json", json);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to save host count state", ex);
            }
        }

        public void LoadHostCount()
        {
            try
            {
                if (File.Exists("hostCountState.json"))
                {
                    string json = File.ReadAllText("hostCountState.json");
                    var hostCountState = JsonSerializer.Deserialize<HostCountState>(json);

                    if (hostCountState != null)
                    {
                        HostsScanned = hostCountState.HostsScanned;
                        WindowsDevices = hostCountState.WindowsDevices;
                        LinuxDevices = hostCountState.LinuxDevices;
                        NetworkDevices = hostCountState.NetworkDevices;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to load host count state", ex);
            }
        }

        public void SaveVulnerabilityPageState()
        {
            try
            {
                var pageState = new VulnerabilityPageState
                {
                    LastVulnScanIpRange = LastVulnScanIpRange,
                    LastVulnScanPortRange = LastVulnScanPortRange,
                    LastVulnScanType = LastVulnScanType,
                    IsVulnScanInProgress = IsVulnScanInProgress,
                    VulnScanServiceDetectionEnabled = VulnScanServiceDetectionEnabled,
                    VulnScanConcurrentScans = VulnScanConcurrentScans
                };

                string json = JsonSerializer.Serialize(pageState, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText("vulnerabilityPageState.json", json);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving vulnerability page state: {ex.Message}");
            }
        }

        public void LoadVulnerabilityPageState()
        {
            try
            {
                if (File.Exists("vulnerabilityPageState.json"))
                {
                    string json = File.ReadAllText("vulnerabilityPageState.json");
                    var pageState = JsonSerializer.Deserialize<VulnerabilityPageState>(json);

                    if (pageState != null)
                    {
                        LastVulnScanIpRange = pageState.LastVulnScanIpRange;
                        LastVulnScanPortRange = pageState.LastVulnScanPortRange;
                        LastVulnScanType = pageState.LastVulnScanType;
                        IsVulnScanInProgress = pageState.IsVulnScanInProgress;
                        VulnScanServiceDetectionEnabled = pageState.VulnScanServiceDetectionEnabled;
                        VulnScanConcurrentScans = pageState.VulnScanConcurrentScans ?? AppConstants.State.DefaultVulnConcurrentScans;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading vulnerability page state: {ex.Message}");
            }
        }

        public void UpdateHostsScanned(int count)
        {
            HostsScanned = count;
            SaveHostCount();
            SaveNetworkScanResults();
        }

        public void UpdateNetworkStats(int windowsCount, int linuxCount, int networkDeviceCount)
        {
            WindowsDevices = windowsCount;
            LinuxDevices = linuxCount;
            NetworkDevices = networkDeviceCount;
        }

        public void AddScanResult(ScanResult result)
        {
            ScanHistory.Insert(0, result);
            while (ScanHistory.Count > AppConstants.State.MaxScanHistory)
            {
                ScanHistory.RemoveAt(ScanHistory.Count - 1);
            }

            try
            {
                if (Application.Current != null)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        RecentScanResults.Insert(0, result);
                        while (RecentScanResults.Count > AppConstants.State.MaxRecentScanResults)
                        {
                            RecentScanResults.RemoveAt(RecentScanResults.Count - 1);
                        }
                    });
                }
                else
                {
                    RecentScanResults.Insert(0, result);
                    while (RecentScanResults.Count > AppConstants.State.MaxRecentScanResults)
                    {
                        RecentScanResults.RemoveAt(RecentScanResults.Count - 1);
                    }
                }

                SaveScanResults();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error adding scan result: {ex.Message}");
            }
        }

        public void SaveScanResults()
        {
            try
            {
                var resultsToSave = RecentScanResults.Select(result => new
                {
                    result.Timestamp,
                    result.Type,
                    result.Description,
                    result.Details,
                    result.Status,
                    result.PageType,
                    result.PageState,
                    result.ScanId,
                    result.SnapshotData // Only save the Base64 string, NOT the BitmapSource
                                        // PageSnapshot is excluded because it can't be serialized
                }).ToList();

                string json = JsonSerializer.Serialize(resultsToSave, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText("recentScanResults.json", json);
                Debug.WriteLine($"Successfully saved {resultsToSave.Count} scan results");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving scan results: {ex.Message}");
            }
        }


        public void LoadScanResults()
        {
            try
            {
                if (File.Exists("recentScanResults.json"))
                {
                    string json = File.ReadAllText("recentScanResults.json");
                    using var document = JsonDocument.Parse(json);
                    var results = document.RootElement.EnumerateArray();

                    RecentScanResults.Clear();
                    int loadedCount = 0;
                    int screenshotSuccessCount = 0;
                    int screenshotFailCount = 0;

                    foreach (var item in results.Take(AppConstants.State.MaxRecentScanResults))
                    {
                        var result = new ScanResult
                        {
                            Timestamp = item.GetProperty("Timestamp").GetDateTime(),
                            Type = item.GetProperty("Type").GetString() ?? "",
                            Description = item.GetProperty("Description").GetString() ?? "",
                            Status = item.GetProperty("Status").GetString() ?? "Good",
                            PageType = item.TryGetProperty("PageType", out var pageType) ? pageType.GetString() : "",
                            ScanId = item.TryGetProperty("ScanId", out var scanId) ? scanId.GetString() : Guid.NewGuid().ToString()
                        };

                        // Load details
                        if (item.TryGetProperty("Details", out var detailsProperty))
                        {
                            result.Details = detailsProperty.EnumerateArray()
                                .Select(d => d.GetString() ?? "")
                                .ToList();
                        }

                        // Load page state
                        if (item.TryGetProperty("PageState", out var pageStateProperty))
                        {
                            try
                            {
                                // Create a separate JsonDocument for PageState to avoid disposal issues
                                var pageStateJson = pageStateProperty.GetRawText();
                                using var pageStateDoc = JsonDocument.Parse(pageStateJson);

                                // Convert to a proper Dictionary with concrete values (not JsonElements)
                                result.PageState = new Dictionary<string, object>();

                                foreach (var property in pageStateDoc.RootElement.EnumerateObject())
                                {
                                    object value = property.Value.ValueKind switch
                                    {
                                        JsonValueKind.String => property.Value.GetString() ?? "",
                                        JsonValueKind.Number => property.Value.TryGetInt32(out var intVal) ? (object)intVal : property.Value.GetDouble(),
                                        JsonValueKind.True => true,
                                        JsonValueKind.False => false,
                                        JsonValueKind.Null => null,
                                        _ => property.Value.ToString() // Convert other types to string immediately
                                    };

                                    result.PageState[property.Name] = value;
                                    Debug.WriteLine($"LoadScanResults: Loaded PageState - {property.Name} = '{value}' (Type: {value?.GetType().Name})");
                                }

                                Debug.WriteLine($"Successfully loaded PageState for {result.Type} with {result.PageState.Count} properties");
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"Error deserializing page state for {result.Type}: {ex.Message}");
                                result.PageState = new Dictionary<string, object>();
                            }
                        }
                        else
                        {
                            result.PageState = new Dictionary<string, object>();
                        }

                        // Load screenshot data - CRITICAL FIX
                        if (item.TryGetProperty("SnapshotData", out var snapshotProperty))
                        {
                            var snapshotData = snapshotProperty.GetString();
                            if (!string.IsNullOrEmpty(snapshotData))
                            {
                                Debug.WriteLine($"Loading screenshot for {result.Type}: {snapshotData.Length} characters");

                                result.SnapshotData = snapshotData;

                                // Convert Base64 back to BitmapSource
                                try
                                {
                                    result.PageSnapshot = ScreenshotUtility.Base64ToBitmap(snapshotData);
                                    if (result.PageSnapshot != null)
                                    {
                                        screenshotSuccessCount++;
                                        Debug.WriteLine($"Successfully restored screenshot for {result.Type}");
                                    }
                                    else
                                    {
                                        screenshotFailCount++;
                                        Debug.WriteLine($"Failed to convert Base64 to bitmap for {result.Type}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    screenshotFailCount++;
                                    Debug.WriteLine($"Error converting Base64 to bitmap for {result.Type}: {ex.Message}");
                                }
                            }
                            else
                            {
                                Debug.WriteLine($"Empty SnapshotData for {result.Type}");
                            }
                        }
                        else
                        {
                            Debug.WriteLine($"No SnapshotData property found for {result.Type}");
                        }

                        RecentScanResults.Add(result);
                        loadedCount++;
                    }

                    Debug.WriteLine($"LoadScanResults Summary:");
                    Debug.WriteLine($"  - Total results loaded: {loadedCount}");
                    Debug.WriteLine($"  - Screenshots successfully restored: {screenshotSuccessCount}");
                    Debug.WriteLine($"  - Screenshots failed to restore: {screenshotFailCount}");
                }
                else
                {
                    Debug.WriteLine("recentScanResults.json file not found");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading scan results: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        public Dictionary<string, object> CaptureUIStateFromPage(Page currentPage, string pageType)
        {
            var state = new Dictionary<string, object>();

            try
            {
                Debug.WriteLine($"CaptureUIStateFromPage: Capturing UI state for {pageType}");

                switch (pageType)
                {
                    case PageTypes.NetworkDiscovery:
                        if (currentPage is Views.NetworkDiscoveryPage networkPage)
                        {
                            // Get actual values from UI controls
                            var scanRange = networkPage.ScanRangeInput?.Text ?? "";
                            var timeout = int.TryParse(networkPage.TimeoutInput?.Text, out int timeoutVal) ? timeoutVal : 1000;
                            var scanType = (networkPage.ScanTypeComboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "";
                            state["LastScanRange"] = scanRange;
                            state["LastTimeout"] = timeout;
                            state["LastScanType"] = scanType;
                            state["WasSingleIpScan"] = false;
                            state["NetworkScanResults"] = NetworkScanResults.ToList();
                            state["HostsScanned"] = NetworkScanResults.Count;
                            state["WindowsDevices"] = NetworkScanResults.Count(d => d.DeviceType == "Windows");
                            state["LinuxDevices"] = NetworkScanResults.Count(d => d.DeviceType == "Linux");
                            state["NetworkDevicesCount"] = NetworkScanResults.Count(d => d.DeviceType == "Router");

                            Debug.WriteLine($"Captured NetworkDiscovery state:");
                            Debug.WriteLine($"  LastScanRange: '{scanRange}'");
                            Debug.WriteLine($"  LastTimeout: {timeout}");
                            Debug.WriteLine($"  LastScanType: '{scanType}'");
                            Debug.WriteLine($"  WasSingleIpScan: false");
                            Debug.WriteLine($"  NetworkScanResults count: {NetworkScanResults.Count}");
                        }
                        break;

                    case PageTypes.PortScanner:
                        // Add similar logic for other pages
                        state["LastVulnScanIpRange"] = LastVulnScanIpRange ?? "";
                        state["LastVulnScanPortRange"] = LastVulnScanPortRange ?? "";
                        state["LastVulnScanType"] = LastVulnScanType ?? "";
                        state["VulnScanServiceDetectionEnabled"] = VulnScanServiceDetectionEnabled;
                        state["VulnScanConcurrentScans"] = VulnScanConcurrentScans ?? "100";
                        state["VulnerabilityScanResults"] = VulnerabilityScanResults.ToList();
                        break;

                    case PageTypes.Miscellaneous:
                        state["MiscPageLastIp"] = MiscPageLastIp ?? "";
                        state["MiscPageLastStartPort"] = MiscPageLastStartPort ?? "";
                        state["MiscPageLastEndPort"] = MiscPageLastEndPort ?? "";
                        state["MiscPageLastScanType"] = MiscPageLastScanType ?? "";
                        state["MiscPageTimeout"] = MiscPageTimeout;
                        state["MiscPageScanResults"] = MiscPageScanResults.ToList();
                        break;

                    case PageTypes.TrafficAnalysis:
                        state["TrafficAnalysisPackets"] = TrafficAnalysisPackets.ToList();
                        state["Time"] = Time ?? "";
                        state["SourceIP"] = SourceIP ?? "";
                        state["DestinationIP"] = DestinationIP ?? "";
                        state["Protocol"] = Protocol ?? "";
                        state["Length"] = Length ?? "";
                        state["Info"] = Info ?? "";
                        break;
                }

                Debug.WriteLine($"CaptureUIStateFromPage: Captured {state.Count} state properties");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"CaptureUIStateFromPage: Error capturing UI state: {ex.Message}");
            }

            return state;
        }

        public void ClearScanResults()
        {
            try
            {
                if (Application.Current != null)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        RecentScanResults.Clear();
                    });
                }
                else
                {
                    RecentScanResults.Clear();
                }
                SaveScanResults();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error clearing scan results: {ex.Message}");
            }
        }
        private Dictionary<string, object> CapturePageState(string pageType)
        {
            // Try to get the current page from MainWindow
            try
            {
                var mainWindow = Application.Current.MainWindow as MainWindow;
                var currentPage = mainWindow?.GetCurrentPage();

                if (currentPage != null)
                {
                    Debug.WriteLine($"CapturePageState: Found current page {currentPage.GetType().Name}, capturing UI state");
                    return CaptureUIStateFromPage(currentPage, pageType);
                }
                else
                {
                    Debug.WriteLine($"CapturePageState: No current page found, using StateService values");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"CapturePageState: Error getting current page: {ex.Message}");
            }

            // Fallback to StateService properties if UI capture fails
            var state = new Dictionary<string, object>();

            // Complete fallback section for CapturePageState method in StateService
            switch (pageType)
            {
                case PageTypes.NetworkDiscovery:
                    state["LastScanRange"] = LastScanRange ?? "";
                    state["LastTimeout"] = LastTimeout;
                    state["LastScanType"] = LastScanType ?? "";
                    state["WasSingleIpScan"] = WasSingleIpScan;
                    state["NetworkScanResults"] = NetworkScanResults.ToList();
                    state["HostsScanned"] = HostsScanned;
                    state["WindowsDevices"] = WindowsDevices;
                    state["LinuxDevices"] = LinuxDevices;
                    state["NetworkDevicesCount"] = NetworkDevices;
                    break;

                case PageTypes.PortScanner:
                    state["LastVulnScanIpRange"] = LastVulnScanIpRange ?? "";
                    state["LastVulnScanPortRange"] = LastVulnScanPortRange ?? "";
                    state["LastVulnScanType"] = LastVulnScanType ?? "";
                    state["VulnScanServiceDetectionEnabled"] = VulnScanServiceDetectionEnabled;
                    state["VulnScanConcurrentScans"] = VulnScanConcurrentScans ?? "100";
                    state["VulnerabilityScanResults"] = VulnerabilityScanResults.ToList();
                    break;

                case PageTypes.Miscellaneous:
                    state["MiscPageLastIp"] = MiscPageLastIp ?? "";
                    state["MiscPageLastStartPort"] = MiscPageLastStartPort ?? "";
                    state["MiscPageLastEndPort"] = MiscPageLastEndPort ?? "";
                    state["MiscPageLastScanType"] = MiscPageLastScanType ?? "";
                    state["MiscPageTimeout"] = MiscPageTimeout;
                    state["MiscPageScanResults"] = MiscPageScanResults.ToList();
                    break;

                case PageTypes.TrafficAnalysis:
                    state["TrafficAnalysisPackets"] = TrafficAnalysisPackets.ToList();
                    state["Time"] = Time ?? "";
                    state["SourceIP"] = SourceIP ?? "";
                    state["DestinationIP"] = DestinationIP ?? "";
                    state["Protocol"] = Protocol ?? "";
                    state["Length"] = Length ?? "";
                    state["Info"] = Info ?? "";
                    break;

                case PageTypes.Dashboard:
                    // Dashboard doesn't have specific state to capture
                    state["LastRefreshTime"] = DateTime.Now;
                    break;

                case PageTypes.NetworkTopology:
                    // Add topology-specific state if needed
                    state["TopologyLastRefresh"] = DateTime.Now;
                    break;

                case PageTypes.Achievements:
                    // Add achievements-specific state if needed
                    state["AchievementsLastViewed"] = DateTime.Now;
                    break;

                case PageTypes.Settings:
                    // Add settings-specific state if needed
                    state["SettingsLastModified"] = DateTime.Now;
                    break;

                case PageTypes.Profile:
                    // Add profile-specific state if needed
                    state["ProfileLastViewed"] = DateTime.Now;
                    break;

                default:
                    Debug.WriteLine($"CapturePageState: Unknown page type {pageType}");
                    break;
            }

            return state;
        }
        public void RestorePageState(string pageType, Dictionary<string, object> state)
        {
            if (state == null || state.Count == 0)
            {
                Debug.WriteLine($"RestorePageState: No state to restore for {pageType}");
                return;
            }

            Debug.WriteLine($"=== RESTORE PAGE STATE DEBUG ===");
            Debug.WriteLine($"RestorePageState: Restoring state for {pageType} with {state.Count} properties");

            // Debug what's in the state dictionary
            foreach (var kvp in state)
            {
                Debug.WriteLine($"State Key: '{kvp.Key}' = '{kvp.Value}' (Type: {kvp.Value?.GetType().Name})");
            }

            try
            {
                switch (pageType)
                {
                    case PageTypes.NetworkDiscovery:
                        Debug.WriteLine("Processing NetworkDiscovery state restoration...");

                        if (state.ContainsKey("LastScanRange"))
                        {
                            var oldValue = LastScanRange;
                            LastScanRange = SafeGetString(state["LastScanRange"]);
                            Debug.WriteLine($"LastScanRange: '{oldValue}' → '{LastScanRange}'");
                        }
                        else
                        {
                            Debug.WriteLine("LastScanRange key not found in state");
                        }

                        if (state.ContainsKey("LastTimeout"))
                        {
                            var oldValue = LastTimeout;
                            LastTimeout = SafeGetInt(state["LastTimeout"], 1000);
                            Debug.WriteLine($"LastTimeout: {oldValue} → {LastTimeout}");
                        }
                        else
                        {
                            Debug.WriteLine("LastTimeout key not found in state");
                        }

                        if (state.ContainsKey("LastScanType"))
                        {
                            var oldValue = LastScanType;
                            LastScanType = SafeGetString(state["LastScanType"]);
                            Debug.WriteLine($"LastScanType: '{oldValue}' → '{LastScanType}'");
                        }
                        else
                        {
                            Debug.WriteLine("LastScanType key not found in state");
                        }

                        if (state.ContainsKey("WasSingleIpScan"))
                        {
                            var oldValue = WasSingleIpScan;
                            WasSingleIpScan = SafeGetBool(state["WasSingleIpScan"], false);
                            Debug.WriteLine($"WasSingleIpScan: {oldValue} → {WasSingleIpScan}");
                        }
                        else
                        {
                            Debug.WriteLine("WasSingleIpScan key not found in state");
                        }

                        // Check if NetworkScanResults should be restored
                        if (state.ContainsKey("NetworkScanResults"))
                        {
                            Debug.WriteLine("NetworkScanResults found in state - attempting to restore...");
                            try
                            {
                                var networkResults = state["NetworkScanResults"];
                                Debug.WriteLine($"NetworkScanResults type: {networkResults?.GetType().Name}");
                                // Add more restoration logic here if needed
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"Error restoring NetworkScanResults: {ex.Message}");
                            }
                        }
                        else
                        {
                            Debug.WriteLine("NetworkScanResults key not found in state");
                        }
                        break;

                        // ... other cases remain the same
                }

                Debug.WriteLine($"RestorePageState: Successfully restored state for {pageType}");
                Debug.WriteLine("=== RESTORE PAGE STATE COMPLETE ===");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"RestorePageState: Error restoring state for {pageType}: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                throw new Exception($"Failed to restore page state for {pageType}: {ex.Message}", ex);
            }
        }

        private string? SafeGetString(object? value)
        {
            try
            {
                if (value == null) return null;

                if (value is JsonElement jsonElement)
                {
                    return jsonElement.ValueKind == JsonValueKind.String ? jsonElement.GetString() : jsonElement.ToString();
                }

                return value.ToString();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SafeGetString error: {ex.Message} for value: {value}");
                return null;
            }
        }
        private int SafeGetInt(object value, int defaultValue)
        {
            try
            {
                if (value == null) return defaultValue;

                if (value is JsonElement jsonElement)
                {
                    if (jsonElement.ValueKind == JsonValueKind.Number && jsonElement.TryGetInt32(out int intValue))
                        return intValue;

                    // Try to parse the string representation
                    if (int.TryParse(jsonElement.ToString(), out int parsedValue))
                        return parsedValue;
                }
                else if (value is int directInt)
                {
                    return directInt;
                }
                else if (int.TryParse(value.ToString(), out int stringParsedValue))
                {
                    return stringParsedValue;
                }

                Debug.WriteLine($"SafeGetInt: Could not convert {value} to int, using default {defaultValue}");
                return defaultValue;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SafeGetInt error: {ex.Message} for value: {value}, using default {defaultValue}");
                return defaultValue;
            }
        }

        private bool SafeGetBool(object value, bool defaultValue)
        {
            try
            {
                if (value == null) return defaultValue;

                if (value is JsonElement jsonElement)
                {
                    if (jsonElement.ValueKind == JsonValueKind.True) return true;
                    if (jsonElement.ValueKind == JsonValueKind.False) return false;

                    // Try to parse the string representation
                    if (bool.TryParse(jsonElement.ToString(), out bool parsedValue))
                        return parsedValue;
                }
                else if (value is bool directBool)
                {
                    return directBool;
                }
                else if (bool.TryParse(value.ToString(), out bool stringParsedValue))
                {
                    return stringParsedValue;
                }

                Debug.WriteLine($"SafeGetBool: Could not convert {value} to bool, using default {defaultValue}");
                return defaultValue;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SafeGetBool error: {ex.Message} for value: {value}, using default {defaultValue}");
                return defaultValue;
            }
        }

        public void ClearNetworkScanResults()
        {
            // Only clear the current results collection for fresh scans
            NetworkScanResults.Clear();

            // Reset the scan-in-progress flag
            IsScanInProgress = false;

            // IMPORTANT: Do NOT clear these - they're needed for state restoration:
            // - LastScanRange (preserve)
            // - LastTimeout (preserve)  
            // - LastScanType (preserve)
            // - WasSingleIpScan (preserve)
            // - RecentScanResults (preserve - this contains the navigation history)
            // - Host counts (preserve for dashboard)

            Debug.WriteLine("ClearNetworkScanResults: Cleared current results only - preserved saved state");

            // Save only the cleared current state, not the historical state
            SaveNetworkScanResults();
        }

        // Alternative: Create a new method for UI clearing vs full clearing
        public void ClearCurrentDisplayOnly()
        {
            // This method only clears what's currently displayed
            NetworkScanResults.Clear();
            IsScanInProgress = false;

            Debug.WriteLine("ClearCurrentDisplayOnly: Cleared display data only");

            // Don't save anything - this is just a display operation
        }

        public void ClearVulnerabilityScanResults()
        {
            try
            {
                if (Application.Current != null)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        VulnerabilityScanResults.Clear();
                    });
                }
                else
                {
                    VulnerabilityScanResults.Clear();
                }

                SaveVulnerabilityScanResults();

                LastVulnScanIpRange = null;
                LastVulnScanPortRange = null;
                LastVulnScanType = null;
                IsVulnScanInProgress = false;
                VulnScanServiceDetectionEnabled = false;
                VulnScanConcurrentScans = "100";

                SaveVulnerabilityPageState();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error clearing vulnerability scan results: {ex.Message}");
            }
        }

        public void ClearTrafficAnalysisState()
        {
            TrafficAnalysisPackets.Clear();
            Time = null;
            SourceIP = null;
            DestinationIP = null;
            Protocol = null;
            Length = null;
            Info = null;
        }

        public void SaveTrafficAnalysisState()
        {
            var state = new TrafficAnalysisState
            {
                Packets = new List<PacketInfo>(TrafficAnalysisPackets),
                Time = Time,
                SourceIP = SourceIP,
                DestinationIP = DestinationIP,
                Protocol = Protocol,
                Length = Length,
                Info = Info
            };

            try
            {
                string json = JsonSerializer.Serialize(state);
                File.WriteAllText("trafficAnalysisState.json", json);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to save traffic analysis state", ex);
            }
        }

        public void LoadTrafficAnalysisState()
        {
            try
            {
                if (File.Exists("trafficAnalysisState.json"))
                {
                    string json = File.ReadAllText("trafficAnalysisState.json");
                    var state = JsonSerializer.Deserialize<TrafficAnalysisState>(json);

                    TrafficAnalysisPackets.Clear();
                    if (state != null)
                    {
                        foreach (var packet in state.Packets)
                        {
                            TrafficAnalysisPackets.Add(packet);
                        }
                        Time = state.Time;
                        SourceIP = state.SourceIP;
                        DestinationIP = state.DestinationIP;
                        Protocol = state.Protocol;
                        Length = state.Length;
                        Info = state.Info;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to load traffic analysis state", ex);
            }
        }

        public void AddVulnerabilityScanResults(IEnumerable<PortScanResult> results)
        {
            if (results != null)
            {
                try
                {
                    if (Application.Current != null)
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            foreach (var result in results)
                            {
                                VulnerabilityScanResults.Add(result);
                            }
                        });
                    }
                    else
                    {
                        foreach (var result in results)
                        {
                            VulnerabilityScanResults.Add(result);
                        }
                    }

                    SaveVulnerabilityScanResults();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error adding vulnerability scan results: {ex.Message}");
                }
            }
        }

        public bool RemoveVulnerabilityScanResult(PortScanResult result)
        {
            if (result != null)
            {
                try
                {
                    bool removed = false;
                    if (Application.Current != null)
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            removed = VulnerabilityScanResults.Remove(result);
                        });
                    }
                    else
                    {
                        removed = VulnerabilityScanResults.Remove(result);
                    }

                    if (removed)
                    {
                        SaveVulnerabilityScanResults();
                    }
                    return removed;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error removing vulnerability scan result: {ex.Message}");
                    return false;
                }
            }
            return false;
        }

        public int GetVulnerabilityScanResultsCount()
        {
            return VulnerabilityScanResults.Count;
        }

        public void SaveVulnerabilityScanResults()
        {
            try
            {
                string json = JsonSerializer.Serialize(VulnerabilityScanResults.ToList(), new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText("vulnerabilityScanResults.json", json);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving vulnerability scan results: {ex.Message}");
            }
        }

        public void LoadVulnerabilityScanResults()
        {
            try
            {
                if (File.Exists("vulnerabilityScanResults.json"))
                {
                    string json = File.ReadAllText("vulnerabilityScanResults.json");
                    var results = JsonSerializer.Deserialize<List<PortScanResult>>(json);
                    if (results != null)
                    {
                        VulnerabilityScanResults.Clear();
                        foreach (var result in results)
                        {
                            VulnerabilityScanResults.Add(result);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading vulnerability scan results: {ex.Message}");
            }
        }

        public void SaveVulnerabilityState()
        {
            try
            {
                var stateData = new Dictionary<string, object>
                {
                    ["LastVulnScanIpRange"] = LastVulnScanIpRange ?? "",
                    ["LastVulnScanPortRange"] = LastVulnScanPortRange ?? "",
                    ["LastVulnScanType"] = LastVulnScanType ?? "",
                    ["VulnScanServiceDetectionEnabled"] = VulnScanServiceDetectionEnabled,
                    ["VulnScanConcurrentScans"] = VulnScanConcurrentScans ?? "100"
                };

                string json = JsonSerializer.Serialize(stateData, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText("vulnerabilityState.json", json);

                Debug.WriteLine("Vulnerability state saved successfully");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving vulnerability state: {ex.Message}");
            }
        }

        public void LoadVulnerabilityState()
        {
            try
            {
                if (File.Exists("vulnerabilityState.json"))
                {
                    string json = File.ReadAllText("vulnerabilityState.json");
                    var stateData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

                    if (stateData != null)
                    {
                        LastVulnScanIpRange = stateData.ContainsKey("LastVulnScanIpRange") ?
                            stateData["LastVulnScanIpRange"].GetString() : "";
                        LastVulnScanPortRange = stateData.ContainsKey("LastVulnScanPortRange") ?
                            stateData["LastVulnScanPortRange"].GetString() : "";
                        LastVulnScanType = stateData.ContainsKey("LastVulnScanType") ?
                            stateData["LastVulnScanType"].GetString() : "";
                        VulnScanServiceDetectionEnabled = stateData.ContainsKey("VulnScanServiceDetectionEnabled") ?
                            stateData["VulnScanServiceDetectionEnabled"].GetBoolean() : false;
                        VulnScanConcurrentScans = stateData.ContainsKey("VulnScanConcurrentScans") ?
                            stateData["VulnScanConcurrentScans"].GetString() : AppConstants.State.DefaultVulnConcurrentScans;
                    }

                    Debug.WriteLine("Vulnerability state loaded successfully");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading vulnerability state: {ex.Message}");
            }
        }

        public void ClearAllResults()
        {
            ClearNetworkScanResults();
            ClearVulnerabilityScanResults();
            ClearTrafficAnalysisState();
            ClearScanResults();
            ClearMiscellaneousPageState();
        }

        public List<PortScanResult> GetVulnerabilityScanResults()
        {
            return new List<PortScanResult>(VulnerabilityScanResults);
        }

        public void AddVulnerabilityScanResult(PortScanResult result)
        {
            if (result != null)
            {
                try
                {
                    if (Application.Current != null)
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            VulnerabilityScanResults.Add(result);
                        });
                    }
                    else
                    {
                        VulnerabilityScanResults.Add(result);
                    }

                    SaveVulnerabilityScanResults();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error adding vulnerability scan result: {ex.Message}");
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

    }
}
