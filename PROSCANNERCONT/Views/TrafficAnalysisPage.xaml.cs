using FontAwesome.Sharp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    #region Converters

    /// <summary>
    /// Converts protocol name to a semi-transparent background color for row highlighting.
    /// Uses theme-compatible colors with transparency.
    /// </summary>
    public class ProtocolToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var protocol = value as string;
            return protocol?.ToUpperInvariant() switch
            {
                // Blue tint for TCP
                "TCP" => new SolidColorBrush(Color.FromArgb(25, 0, 122, 204)),
                // Purple tint for UDP
                "UDP" => new SolidColorBrush(Color.FromArgb(25, 147, 112, 219)),
                // Yellow tint for ICMP
                "ICMP" => new SolidColorBrush(Color.FromArgb(25, 255, 193, 7)),
                "ICMPV6" => new SolidColorBrush(Color.FromArgb(25, 255, 193, 7)),
                // Green tint for HTTP/HTTPS
                "HTTP" => new SolidColorBrush(Color.FromArgb(25, 76, 175, 80)),
                "HTTPS" => new SolidColorBrush(Color.FromArgb(25, 76, 175, 80)),
                // Cyan tint for DNS
                "DNS" => new SolidColorBrush(Color.FromArgb(25, 0, 188, 212)),
                // Orange tint for SSH
                "SSH" => new SolidColorBrush(Color.FromArgb(25, 255, 152, 0)),
                _ => Brushes.Transparent
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }

    /// <summary>
    /// Converts ThreatLevel enum to a semi-transparent background color for row highlighting.
    /// Uses theme-compatible warning/error colors with transparency.
    /// </summary>
    public class ThreatLevelToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ThreatLevel level)
            {
                return level switch
                {
                    // Yellow-orange tint for Low
                    ThreatLevel.Low => new SolidColorBrush(Color.FromArgb(40, 255, 193, 7)),
                    // Orange tint for Medium
                    ThreatLevel.Medium => new SolidColorBrush(Color.FromArgb(50, 255, 152, 0)),
                    // Red-orange tint for High
                    ThreatLevel.High => new SolidColorBrush(Color.FromArgb(60, 255, 87, 34)),
                    // Red tint for Critical
                    ThreatLevel.Critical => new SolidColorBrush(Color.FromArgb(70, 244, 67, 54)),
                    _ => Brushes.Transparent
                };
            }
            return Brushes.Transparent;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }

    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool b && b ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }

    public class BytesToStringConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long bytes)
            {
                return FormatBytes(bytes);
            }
            if (value is int intBytes)
            {
                return FormatBytes(intBytes);
            }
            if (value is double doubleBytes)
            {
                return FormatBytes((long)doubleBytes);
            }
            return "0 B";
        }

        private string FormatBytes(long bytes)
        {
            if (bytes < 0) return "0 B";
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < suffixes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:F2} {suffixes[order]}";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }

    #endregion

    public partial class TrafficAnalysisPage : Page
    {
        #region Fields

        private readonly TrafficCaptureService _captureService;
        private readonly DispatcherTimer _uiUpdateTimer;
        private EnhancedPacketInfo _selectedPacket;
        private string _currentSidePanel = null;
        private bool _autoScroll = true;

        #endregion

        #region Constructor

        public TrafficAnalysisPage()
        {
            InitializeComponent();

            _captureService = TrafficCaptureService.Instance;

            // Setup UI update timer
            _uiUpdateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
            _uiUpdateTimer.Tick += UpdateUI;
            _uiUpdateTimer.Start();

            // Initialize interface selector
            LoadNetworkInterfaces();

            // Bind packet grid
            PacketGrid.ItemsSource = _captureService.FilteredPackets;

            // Subscribe to property changes
            _captureService.PropertyChanged += CaptureService_PropertyChanged;

            // Restore button state in case capture was already running before navigation
            UpdateCaptureButton();
            UpdateCaptureStatus();
        }

        #endregion

        #region Initialization

        private void LoadNetworkInterfaces()
        {
            InterfaceComboBox.Items.Clear();

            foreach (var device in _captureService.AvailableDevices)
            {
                var item = new ComboBoxItem
                {
                    Content = device.Description ?? device.Name,
                    Tag = device
                };
                InterfaceComboBox.Items.Add(item);
            }

            if (_captureService.SelectedDevice != null)
            {
                for (int i = 0; i < InterfaceComboBox.Items.Count; i++)
                {
                    var item = InterfaceComboBox.Items[i] as ComboBoxItem;
                    if (item?.Tag == _captureService.SelectedDevice)
                    {
                        InterfaceComboBox.SelectedIndex = i;
                        break;
                    }
                }
            }
            else if (InterfaceComboBox.Items.Count > 0)
            {
                InterfaceComboBox.SelectedIndex = 0;
            }
        }

        private void CaptureService_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                switch (e.PropertyName)
                {
                    case nameof(TrafficCaptureService.IsCapturing):
                        UpdateCaptureButton();
                        break;
                    case nameof(TrafficCaptureService.CaptureStatus):
                        UpdateCaptureStatus();
                        break;
                }
            }));
        }

        #endregion

        #region UI Updates

        private int _lastAutoScrollCount = 0;

        private void UpdateUI(object sender, EventArgs e)
        {
            UpdateStatisticsDisplay();

            // Auto-scroll: only when new packets actually arrived, and via
            // ScrollViewer.ScrollToBottom (not ScrollIntoView which triggers
            // a full layout recalc that resets star-column widths).
            int count = PacketGrid.Items.Count;
            if (_autoScroll && _captureService.IsCapturing && count > _lastAutoScrollCount)
            {
                _lastAutoScrollCount = count;
                var sv = FindVisualChild<ScrollViewer>(PacketGrid);
                sv?.ScrollToBottom();
            }
        }

        private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
        {
            for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);
                if (child is T match) return match;
                var result = FindVisualChild<T>(child);
                if (result != null) return result;
            }
            return null;
        }

        private void UpdateStatisticsDisplay()
        {
            var stats = _captureService.Statistics;

            TotalPacketsText.Text = stats.TotalPackets.ToString("N0");
            TotalBytesText.Text = stats.FormattedTotalBytes;
            PacketsPerSecText.Text = $"{stats.PacketsPerSecond:F0}/s";
            AlertsCountText.Text = _captureService.Alerts.Count.ToString();
        }

        private void UpdateCaptureStatus()
        {
            CaptureStatusText.Text = _captureService.CaptureStatus;
        }

        private void UpdateCaptureButton()
        {
            if (_captureService.IsCapturing)
            {
                StartStopIcon.Icon = IconChar.Stop;
                StartStopText.Text = "Stop Capture";
                // Use CriticalBrush from theme for stop button
                StartStopButton.Background = (Brush)FindResource("CriticalBrush");
            }
            else
            {
                StartStopIcon.Icon = IconChar.Play;
                StartStopText.Text = "Start Capture";
                // Use AccentBrush from theme for start button
                StartStopButton.Background = (Brush)FindResource("AccentBrush");
            }
        }

        #endregion

        #region Capture Control

        private async void StartStopCapture_Click(object sender, RoutedEventArgs e)
        {
            if (_captureService.IsCapturing)
            {
                StopCapture();
            }
            else
            {
                await StartCaptureAsync();
            }
        }

        private async Task StartCaptureAsync()
        {
            try
            {
                await _captureService.StartCaptureAsync();
                CreateTrafficAnalysisScanResult("Capture Started");
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error starting capture: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void StopCapture()
        {
            _captureService.StopCapture();
            CreateTrafficAnalysisScanResult("Capture Stopped");
        }

        private void InterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (InterfaceComboBox.SelectedItem is ComboBoxItem item && item.Tag is SharpPcap.ILiveDevice device)
            {
                _captureService.SelectDevice(device);
            }
        }

        #endregion

        #region Packet Grid

        private void PacketGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PacketGrid.SelectedItem is EnhancedPacketInfo packet)
            {
                _selectedPacket = packet;
                UpdatePacketDetails(packet);
            }
        }

        private void PacketGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (_selectedPacket != null)
            {
                ShowPacketDetailsWindow(_selectedPacket);
            }
        }

        private void UpdatePacketDetails(EnhancedPacketInfo packet)
        {
            // Update protocol tree
            UpdateProtocolTree(packet);

            // Update hex dump
            if (packet.RawPacket != null)
            {
                HexDumpText.Text = _captureService.GenerateHexDump(packet.RawPacket);
            }
            else
            {
                HexDumpText.Text = "No raw packet data available";
            }
        }

        private void UpdateProtocolTree(EnhancedPacketInfo packet)
        {
            ProtocolTree.Items.Clear();

            // Create frame info node
            var frameNode = new TreeViewItem
            {
                Header = $"Frame {packet.PacketNumber}: {packet.Length} bytes",
                IsExpanded = true,
                Foreground = (Brush)FindResource("TextBrush")
            };
            frameNode.Items.Add(CreateTreeItem($"Capture Time: {packet.FormattedTimestamp}"));
            frameNode.Items.Add(CreateTreeItem($"Frame Length: {packet.Length} bytes"));
            ProtocolTree.Items.Add(frameNode);

            // Add protocol layers
            foreach (var layer in packet.Layers)
            {
                var layerNode = new TreeViewItem
                {
                    Header = layer.Name,
                    IsExpanded = true,
                    Foreground = (Brush)FindResource("TextBrush")
                };

                foreach (var field in layer.DisplayFields)
                {
                    var fieldHeader = field.IsImportant
                        ? $"► {field.Name}: {field.Value}"
                        : $"  {field.Name}: {field.Value}";

                    var fieldItem = CreateTreeItem(fieldHeader);
                    if (field.IsImportant)
                    {
                        fieldItem.FontWeight = FontWeights.SemiBold;
                    }
                    layerNode.Items.Add(fieldItem);
                }

                ProtocolTree.Items.Add(layerNode);
            }

            // Add threat info if present
            if (packet.ThreatLevel > ThreatLevel.None)
            {
                var threatNode = new TreeViewItem
                {
                    Header = "⚠️ Threat Detection",
                    IsExpanded = true,
                    Foreground = (Brush)FindResource("WarningBrush")
                };
                threatNode.Items.Add(new TreeViewItem
                {
                    Header = $"Level: {packet.ThreatLevel}",
                    Foreground = GetThreatBrush(packet.ThreatLevel)
                });
                threatNode.Items.Add(CreateTreeItem($"Description: {packet.ThreatDescription}"));
                ProtocolTree.Items.Add(threatNode);
            }
        }

        private TreeViewItem CreateTreeItem(string header)
        {
            return new TreeViewItem
            {
                Header = header,
                Foreground = (Brush)FindResource("TextBrush")
            };
        }

        /// <summary>
        /// Gets the appropriate brush for threat level using theme resources.
        /// </summary>
        private Brush GetThreatBrush(ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.Low => (Brush)FindResource("WarningBrush"),
                ThreatLevel.Medium => (Brush)FindResource("WarningBrush"),
                ThreatLevel.High => (Brush)FindResource("CriticalBrush"),
                ThreatLevel.Critical => (Brush)FindResource("CriticalBrush"),
                _ => (Brush)FindResource("TextBrush")
            };
        }

        private void ShowPacketDetailsWindow(EnhancedPacketInfo packet)
        {
            var details = _captureService.GeneratePacketDetails(packet);

            var window = new Window
            {
                Title = $"Packet #{packet.PacketNumber} Details",
                Width = 800,
                Height = 600,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Application.Current.MainWindow,
                Background = (Brush)FindResource("BackgroundBrush")
            };

            var textBox = new TextBox
            {
                Text = details,
                IsReadOnly = true,
                TextWrapping = TextWrapping.NoWrap,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                Background = Brushes.Transparent,
                Foreground = (Brush)FindResource("TextBrush"),
                BorderThickness = new Thickness(0),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(16)
            };

            window.Content = textBox;
            window.ShowDialog();
        }

        private void ClearPacketDetails()
        {
            ProtocolTree.Items.Clear();
            HexDumpText.Text = "Select a packet to view hex dump";
            StreamContentText.Text = "Select a packet and click Follow TCP/UDP Stream.";
            _selectedPacket = null;
            _lastAutoScrollCount = 0;
        }

        #endregion

        #region Filtering

        private void ApplyFilter_Click(object sender, RoutedEventArgs e)
        {
            ApplyFilters();
        }

        private void ClearFilter_Click(object sender, RoutedEventArgs e)
        {
            DisplayFilterInput.Text = string.Empty;
            AutocompletePopup.IsOpen = false;
            _captureService.ClearFilter();
        }

        private void DisplayFilter_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                AutocompletePopup.IsOpen = false;
                ApplyFilters();
            }
            else if (e.Key == Key.Escape)
            {
                AutocompletePopup.IsOpen = false;
            }
            else if (e.Key == Key.Down && AutocompletePopup.IsOpen && AutocompleteList.Items.Count > 0)
            {
                AutocompleteList.Focus();
                AutocompleteList.SelectedIndex = 0;
                (AutocompleteList.ItemContainerGenerator.ContainerFromIndex(0) as ListBoxItem)?.Focus();
                e.Handled = true;
            }
        }

        private void FilterInput_LostFocus(object sender, RoutedEventArgs e)
        {
            // Slight delay so click on popup item registers first
            Dispatcher.BeginInvoke(new Action(() => AutocompletePopup.IsOpen = false),
                System.Windows.Threading.DispatcherPriority.Background);
        }

        // ── Autocomplete ──────────────────────────────────────────────────────
        private static readonly string[] _filterSuggestions = new[]
        {
            "tcp", "udp", "icmp", "icmpv6",
            "http", "https", "dns", "ssh", "ftp", "smtp",
            "src:", "dst:", "port:", "proto:", "host:",
            "tcp and port:80", "udp and port:53",
            "not arp", "broadcast",
            "tcp.flags == SYN", "tcp.flags == RST",
        };

        private void FilterInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            var text = DisplayFilterInput.Text?.Trim() ?? string.Empty;
            if (text.Length < 1) { AutocompletePopup.IsOpen = false; return; }

            // Find the current token being typed (after last space or operator)
            var lastToken = text.Split(new[] { ' ', '&', '|', '!' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? text;

            var matches = _filterSuggestions
                .Where(s => s.StartsWith(lastToken, StringComparison.OrdinalIgnoreCase) && s != lastToken)
                .Take(8)
                .ToList();

            AutocompleteList.Items.Clear();
            if (matches.Count == 0) { AutocompletePopup.IsOpen = false; return; }

            foreach (var m in matches)
                AutocompleteList.Items.Add(m);

            AutocompletePopup.IsOpen = true;
        }

        private void Autocomplete_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (AutocompleteList.SelectedItem is not string selected) return;
            AutocompletePopup.IsOpen = false;

            // Replace the last typed token with the selected suggestion
            var current = DisplayFilterInput.Text ?? string.Empty;
            var parts   = current.Split(new[] { ' ' }, StringSplitOptions.None);
            if (parts.Length > 0)
                parts[^1] = selected;
            DisplayFilterInput.Text = string.Join(" ", parts);
            DisplayFilterInput.CaretIndex = DisplayFilterInput.Text.Length;
            DisplayFilterInput.Focus();
        }

        private void Filter_Changed(object sender, RoutedEventArgs e)
        {
            // Delayed filter application to avoid excessive updates
        }

        private void ResetFilters_Click(object sender, RoutedEventArgs e)
        {
            // Reset all filter controls
            FilterTCP.IsChecked = false;
            FilterUDP.IsChecked = false;
            FilterICMP.IsChecked = false;
            FilterHTTP.IsChecked = false;
            FilterHTTPS.IsChecked = false;
            FilterDNS.IsChecked = false;
            FilterSSH.IsChecked = false;
            FilterIP.Text = string.Empty;
            FilterPort.Text = string.Empty;
            FilterThreatsOnly.IsChecked = false;
            DisplayFilterInput.Text = string.Empty;

            _captureService.ClearFilter();
        }

        private void ApplyFilters()
        {
            var filter = _captureService.CurrentFilter;

            // Apply protocol filters
            filter.TcpEnabled = FilterTCP.IsChecked == true;
            filter.UdpEnabled = FilterUDP.IsChecked == true;
            filter.IcmpEnabled = FilterICMP.IsChecked == true;
            filter.HttpEnabled = FilterHTTP.IsChecked == true;
            filter.HttpsEnabled = FilterHTTPS.IsChecked == true;
            filter.DnsEnabled = FilterDNS.IsChecked == true;
            filter.SshEnabled = FilterSSH.IsChecked == true;

            // Apply IP filter
            filter.IpFilter = string.IsNullOrWhiteSpace(FilterIP.Text) ? null : FilterIP.Text.Trim();

            // Apply port filter
            if (int.TryParse(FilterPort.Text, out int port))
            {
                filter.PortFilter = port;
            }
            else
            {
                filter.PortFilter = null;
            }

            // Apply threat filter
            filter.ShowOnlyThreats = FilterThreatsOnly.IsChecked == true;

            // Apply custom display filter from text box
            filter.CustomDisplayFilter = DisplayFilterInput.Text;

            _captureService.ApplyFilter();
        }

        #endregion

        #region Stream Analysis

        private void FollowTcpStream_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedPacket == null)
            {
                StreamContentText.Text = "Please select a TCP packet first.";
                return;
            }

            if (_selectedPacket.Protocol != "TCP")
            {
                StreamContentText.Text = "Selected packet is not TCP.";
                return;
            }

            var streamContent = _captureService.ReconstructTcpStream(_selectedPacket.ConversationId);

            if (string.IsNullOrEmpty(streamContent))
            {
                StreamContentText.Text = "No stream data available for this conversation.";
            }
            else
            {
                StreamContentText.Text = streamContent;
                _captureService.FilterByConversation(_selectedPacket.ConversationId);
            }
        }

        private void FollowUdpStream_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedPacket == null)
            {
                StreamContentText.Text = "Please select a UDP packet first.";
                return;
            }

            if (_selectedPacket.Protocol != "UDP")
            {
                StreamContentText.Text = "Selected packet is not UDP.";
                return;
            }

            _captureService.FilterByConversation(_selectedPacket.ConversationId);
            StreamContentText.Text = $"Filtering to show UDP stream: {_selectedPacket.ConversationId}\n" +
                $"Endpoints: {_selectedPacket.SourceEndpoint} ↔ {_selectedPacket.DestinationEndpoint}";
        }

        #endregion

        #region Toolbar Actions

        private void ClearCapture_Click(object sender, RoutedEventArgs e)
        {
            var result = AppDialog.Show("Are you sure you want to clear the capture?",
                "Clear Capture", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                _captureService.ClearCapture();
                ClearPacketDetails();
            }
        }

        private async void ExportCapture_Click(object sender, RoutedEventArgs e)
        {
            if (_captureService.CapturedPackets.Count == 0)
            {
                AppDialog.Show("No packets to export.", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "PCAP Files (*.pcap)|*.pcap|CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json",
                DefaultExt = ".pcap",
                FileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var extension = System.IO.Path.GetExtension(dialog.FileName).ToLowerInvariant();

                    switch (extension)
                    {
                        case ".pcap":
                            await _captureService.ExportToPcapAsync(dialog.FileName);
                            break;
                        case ".csv":
                            await _captureService.ExportToCsvAsync(dialog.FileName);
                            break;
                        case ".json":
                            await _captureService.ExportToJsonAsync(dialog.FileName);
                            break;
                    }

                    AppDialog.Show($"Exported {_captureService.CapturedPackets.Count} packets successfully.",
                        "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Export failed: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void ImportCapture_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "PCAP Files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All Files (*.*)|*.*",
                Title = "Import Capture File"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    await _captureService.ImportFromPcapAsync(dialog.FileName);
                    AppDialog.Show($"Imported {_captureService.CapturedPackets.Count} packets successfully.",
                        "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Import failed: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ScrollToTop_Click(object sender, RoutedEventArgs e)
        {
            if (PacketGrid.Items.Count > 0)
            {
                PacketGrid.ScrollIntoView(PacketGrid.Items[0]);
                PacketGrid.SelectedIndex = 0;
            }
        }

        private void ScrollToBottom_Click(object sender, RoutedEventArgs e)
        {
            if (PacketGrid.Items.Count > 0)
            {
                var lastIndex = PacketGrid.Items.Count - 1;
                PacketGrid.ScrollIntoView(PacketGrid.Items[lastIndex]);
                PacketGrid.SelectedIndex = lastIndex;
            }
        }

        #endregion

        #region Side Panel

        private void ToggleStatistics_Click(object sender, RoutedEventArgs e)
        {
            ToggleSidePanel("Statistics");
        }

        private void ToggleConversations_Click(object sender, RoutedEventArgs e)
        {
            ToggleSidePanel("Conversations");
        }

        private void ToggleAlerts_Click(object sender, RoutedEventArgs e)
        {
            ToggleSidePanel("Alerts");
        }

        private void CloseSidePanel_Click(object sender, RoutedEventArgs e)
        {
            CloseSidePanel();
        }

        private void ToggleSidePanel(string panelType)
        {
            if (_currentSidePanel == panelType)
            {
                CloseSidePanel();
                return;
            }

            _currentSidePanel = panelType;
            SidePanelTitle.Text = panelType;
            SidePanel.Visibility = Visibility.Visible;
            SidePanelColumn.Width = new GridLength(320);

            // Update content based on panel type
            UpdateSidePanelContent(panelType);
        }

        private void CloseSidePanel()
        {
            _currentSidePanel = null;
            SidePanel.Visibility = Visibility.Collapsed;
            SidePanelColumn.Width = new GridLength(0);
        }

        private void UpdateSidePanelContent(string panelType)
        {
            SidePanelContent.Children.Clear();

            switch (panelType)
            {
                case "Statistics":
                    BuildStatisticsPanel();
                    break;
                case "Conversations":
                    BuildConversationsPanel();
                    break;
                case "Alerts":
                    BuildAlertsPanel();
                    break;
            }
        }

        private void BuildStatisticsPanel()
        {
            var stats = _captureService.Statistics;
            var panel = new StackPanel { Margin = new Thickness(12) };

            // General Statistics
            panel.Children.Add(CreateStatSection("General", new[]
            {
                ($"Total Packets", stats.TotalPackets.ToString("N0")),
                ($"Total Data", stats.FormattedTotalBytes),
                ($"Duration", stats.FormattedDuration),
                ($"Avg Packet Size", $"{stats.AveragePacketSize:F1} bytes")
            }));

            // Protocol Distribution
            if (stats.ProtocolPacketCounts.Count > 0)
            {
                var protoItems = stats.ProtocolPacketCounts
                    .OrderByDescending(p => p.Value)
                    .Take(10)
                    .Select(p => ($"{p.Key}", $"{p.Value:N0} packets"))
                    .ToArray();

                panel.Children.Add(CreateStatSection("Protocols", protoItems));
            }

            // Top Talkers
            if (stats.TopSourceIPs.Count > 0)
            {
                var topSources = stats.TopSourceIPs
                    .OrderByDescending(p => p.Value)
                    .Take(5)
                    .Select(p => (p.Key, $"{p.Value:N0} packets"))
                    .ToArray();

                panel.Children.Add(CreateStatSection("Top Sources", topSources));
            }

            SidePanelContent.Children.Add(panel);
        }

        private StackPanel CreateStatSection(string title, (string Label, string Value)[] items)
        {
            var section = new StackPanel { Margin = new Thickness(0, 0, 0, 16) };

            section.Children.Add(new TextBlock
            {
                Text = title,
                FontWeight = FontWeights.SemiBold,
                FontSize = 13,
                Foreground = (Brush)FindResource("TextBrush"),
                Margin = new Thickness(0, 0, 0, 8)
            });

            foreach (var (label, value) in items)
            {
                var row = new Grid();
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                row.Children.Add(new TextBlock
                {
                    Text = label,
                    Foreground = (Brush)FindResource("TextBrush"),
                    Opacity = 0.8,
                    FontSize = 12
                });

                var valueText = new TextBlock
                {
                    Text = value,
                    Foreground = (Brush)FindResource("AccentBrush"),
                    FontSize = 12,
                    FontWeight = FontWeights.Medium
                };
                Grid.SetColumn(valueText, 1);
                row.Children.Add(valueText);

                section.Children.Add(row);
            }

            return section;
        }

        private void BuildConversationsPanel()
        {
            var panel = new StackPanel { Margin = new Thickness(12) };

            panel.Children.Add(new TextBlock
            {
                Text = $"{_captureService.Conversations.Count} Conversations",
                FontWeight = FontWeights.SemiBold,
                FontSize = 13,
                Foreground = (Brush)FindResource("TextBrush"),
                Margin = new Thickness(0, 0, 0, 12)
            });

            var listView = new ListView
            {
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                ItemsSource = _captureService.Conversations.Take(50),
                MaxHeight = 400
            };

            listView.ItemTemplate = CreateConversationItemTemplate();
            listView.SelectionChanged += ConversationListView_SelectionChanged;

            panel.Children.Add(listView);
            SidePanelContent.Children.Add(panel);
        }

        private DataTemplate CreateConversationItemTemplate()
        {
            var template = new DataTemplate();
            var factory = new FrameworkElementFactory(typeof(Border));
            factory.SetValue(Border.BackgroundProperty, Brushes.Transparent);
            factory.SetValue(Border.PaddingProperty, new Thickness(8, 6, 8, 6));
            factory.SetValue(Border.MarginProperty, new Thickness(0, 2, 0, 2));

            var stackFactory = new FrameworkElementFactory(typeof(StackPanel));

            // Endpoints
            var endpointsFactory = new FrameworkElementFactory(typeof(TextBlock));
            endpointsFactory.SetBinding(TextBlock.TextProperty, new Binding("EndpointA") { StringFormat = "{0}" });
            endpointsFactory.SetValue(TextBlock.ForegroundProperty, FindResource("TextBrush"));
            endpointsFactory.SetValue(TextBlock.FontSizeProperty, 11.0);
            stackFactory.AppendChild(endpointsFactory);

            var arrowFactory = new FrameworkElementFactory(typeof(TextBlock));
            arrowFactory.SetValue(TextBlock.TextProperty, "↔");
            arrowFactory.SetValue(TextBlock.ForegroundProperty, FindResource("AccentBrush"));
            arrowFactory.SetValue(TextBlock.FontSizeProperty, 11.0);
            stackFactory.AppendChild(arrowFactory);

            var endpoint2Factory = new FrameworkElementFactory(typeof(TextBlock));
            endpoint2Factory.SetBinding(TextBlock.TextProperty, new Binding("EndpointB"));
            endpoint2Factory.SetValue(TextBlock.ForegroundProperty, FindResource("TextBrush"));
            endpoint2Factory.SetValue(TextBlock.FontSizeProperty, 11.0);
            stackFactory.AppendChild(endpoint2Factory);

            factory.AppendChild(stackFactory);
            template.VisualTree = factory;
            return template;
        }

        private void ConversationListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender is ListView listView && listView.SelectedItem is Conversation conversation)
            {
                _captureService.FilterByConversation(conversation.Id);
            }
        }

        private void BuildAlertsPanel()
        {
            var panel = new StackPanel { Margin = new Thickness(12) };

            panel.Children.Add(new TextBlock
            {
                Text = $"{_captureService.Alerts.Count} Alerts",
                FontWeight = FontWeights.SemiBold,
                FontSize = 13,
                Foreground = (Brush)FindResource("TextBrush"),
                Margin = new Thickness(0, 0, 0, 12)
            });

            foreach (var alert in _captureService.Alerts.Take(20))
            {
                var alertBorder = new Border
                {
                    Background = GetAlertBackground(alert.Severity),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(8),
                    Margin = new Thickness(0, 0, 0, 8)
                };

                var alertStack = new StackPanel();

                alertStack.Children.Add(new TextBlock
                {
                    Text = $"{alert.SeverityIcon} {alert.Title}",
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 12,
                    Foreground = (Brush)FindResource("TextBrush")
                });

                alertStack.Children.Add(new TextBlock
                {
                    Text = alert.Description,
                    FontSize = 11,
                    Foreground = (Brush)FindResource("TextBrush"),
                    Opacity = 0.8,
                    TextWrapping = TextWrapping.Wrap
                });

                alertStack.Children.Add(new TextBlock
                {
                    Text = $"Packet #{alert.RelatedPacketNumber} • {alert.Timestamp:HH:mm:ss}",
                    FontSize = 10,
                    Foreground = (Brush)FindResource("TextBrush"),
                    Opacity = 0.6,
                    Margin = new Thickness(0, 4, 0, 0)
                });

                alertBorder.Child = alertStack;
                panel.Children.Add(alertBorder);
            }

            SidePanelContent.Children.Add(panel);
        }

        /// <summary>
        /// Gets alert background color with transparency based on threat level.
        /// Uses semi-transparent versions of theme-compatible colors.
        /// </summary>
        private Brush GetAlertBackground(ThreatLevel level)
        {
            return level switch
            {
                // Yellow-ish for Low
                ThreatLevel.Low => new SolidColorBrush(Color.FromArgb(40, 255, 193, 7)),
                // Orange for Medium
                ThreatLevel.Medium => new SolidColorBrush(Color.FromArgb(50, 255, 152, 0)),
                // Red-orange for High
                ThreatLevel.High => new SolidColorBrush(Color.FromArgb(60, 255, 87, 34)),
                // Red for Critical
                ThreatLevel.Critical => new SolidColorBrush(Color.FromArgb(70, 244, 67, 54)),
                // Gray for None/Unknown
                _ => new SolidColorBrush(Color.FromArgb(30, 158, 158, 158))
            };
        }

        #endregion

        #region Scan Result Creation

        private void CreateTrafficAnalysisScanResult(string action)
        {
            try
            {
                var stats = _captureService.Statistics;
                var alertCount = _captureService.Alerts.Count;

                string status = alertCount == 0 ? "Good" : alertCount < 10 ? "Warning" : "Error";

                var mainWindow = Application.Current.MainWindow as MainWindow;
                var currentPage = mainWindow?.GetCurrentPage();

                var stateService = StateService.Instance;
                var scanResult = stateService.CreateScanResultWithContext(
                    type: "Traffic Analysis",
                    description: $"{action} - {stats.TotalPackets} packets, {alertCount} alerts",
                    status: status,
                    details: new List<string>
                    {
                        $"Total Packets: {stats.TotalPackets:N0}",
                        $"Total Data: {stats.FormattedTotalBytes}",
                        $"Duration: {stats.FormattedDuration}",
                        $"Alerts: {alertCount}",
                        $"Interface: {_captureService.SelectedDevice?.Description ?? "Unknown"}",
                        $"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}"
                    },
                    pageType: PageTypes.TrafficAnalysis,
                    currentPage: currentPage
                );

                stateService.AddScanResult(scanResult);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error creating scan result: {ex.Message}");
            }
        }

        #endregion
    }
}



