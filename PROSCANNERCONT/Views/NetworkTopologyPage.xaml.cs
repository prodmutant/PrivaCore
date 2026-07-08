using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class NetworkTopologyPage : Page
    {
        // Constants
        private const double MIN_ZOOM = 0.1;
        private const double MAX_ZOOM = 5.0;
        private const double ZOOM_STEP = 0.1;
        private const int NODE_WIDTH = 180;
        private const int NODE_HEIGHT = 100;
        private const int LAYER_VERTICAL_SPACING = 150;
        private const int LAYER_HORIZONTAL_SPACING = 200;

        // Static: survive page navigation so topology and scan state persist
        private static List<TopologyNetworkDevice> _devices = new();
        private static bool _isScanning = false;

        // Instance: UI interaction state (reset each page creation is fine)
        private bool _isPanning = false;
        private Point _panStartPoint;
        private Point _panStartTranslate;
        private double _currentZoom = 1.0;
        private TopologyNetworkDevice _selectedDevice;

        // Services
        private readonly TopologyNetworkDiscoveryService _discoveryService;

        public NetworkTopologyPage()
        {
            InitializeComponent();

            _discoveryService = new TopologyNetworkDiscoveryService();
            _discoveryService.OnProgressUpdate += UpdateProgress;

            ResetView();

            // Re-render any topology captured before navigation
            Loaded += (_, __) =>
            {
                if (_isScanning)
                {
                    ScanButton.IsEnabled               = false;
                    LoadingOverlay.Visibility           = Visibility.Visible;
                    LoadingProgressBar.IsIndeterminate  = true;
                    LoadingText.Text                   = "Scan in progress...";
                    LoadingDetailText.Text             = "Please wait";
                }
                else if (_devices.Any())
                {
                    RenderTopology();
                    UpdateStatistics();
                    Dispatcher.BeginInvoke(async () =>
                    {
                        await Task.Delay(400);
                        CenterOnDevices();
                    });
                }
            };

            Debug.WriteLine("✅ NetworkTopologyPage initialized");
        }

        #region Scanning

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning)
            {
                Debug.WriteLine("⚠️ Scan already in progress");
                return;
            }

            await PerformScanAsync();
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            // Refresh is same as scan
            await PerformScanAsync();
        }

        private void AutoDetectCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            bool autoDetect = AutoDetectCheckBox.IsChecked ?? true;

            // Enable/disable manual inputs based on auto-detect
            StartIPTextBox.IsEnabled = !autoDetect;
            EndIPTextBox.IsEnabled = !autoDetect;
            SubnetMaskTextBox.IsEnabled = !autoDetect;

            Debug.WriteLine($"🔧 Auto-detect: {autoDetect}");
        }

        private async Task PerformScanAsync()
        {
            _isScanning = true;

            try
            {
                Debug.WriteLine("🔍 Starting network scan...");

                // UI feedback
                ScanButton.IsEnabled = false;
                LoadingOverlay.Visibility = Visibility.Visible;
                LoadingProgressBar.IsIndeterminate = true;
                LoadingText.Text = "Scanning network...";
                LoadingDetailText.Text = "Discovering devices...";

                _devices.Clear();
                TopologyCanvas?.Children.Clear();

                // Perform discovery
                _devices = await _discoveryService.DiscoverNetworkAsync();

                Debug.WriteLine($"✅ Scan complete! Found {_devices.Count} devices");

                // Render topology
                if (_devices.Any())
                {
                    LoadingText.Text = "Rendering topology...";
                    LoadingDetailText.Text = "Creating visual layout...";
                    await Task.Delay(100); // Let UI update

                    RenderTopology();
                    UpdateStatistics();

                    // Force layout update to get correct canvas dimensions
                    UpdateLayout();

                    // Auto-center after render with longer delay
                    await Task.Delay(800); // Increased delay for animation completion
                    CenterOnDevices();

                    LoadingText.Text = "Scan Complete!";
                    LoadingDetailText.Text = $"Found {_devices.Count} devices";
                    Debug.WriteLine("✅ Topology rendered and centered");
                }
                else
                {
                    LoadingText.Text = "No Devices Found";
                    LoadingDetailText.Text = "No active devices detected on the network";
                    Debug.WriteLine("⚠️ No devices found");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Scan error: {ex.Message}");
                LoadingText.Text = "Scan Error";
                LoadingDetailText.Text = ex.Message;
                AppDialog.Show($"Scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isScanning = false;
                ScanButton.IsEnabled = true;

                // Hide loading overlay after a brief delay
                await Task.Delay(500);
                LoadingOverlay.Visibility = Visibility.Collapsed;
                LoadingProgressBar.IsIndeterminate = false;
            }
        }

        private void UpdateProgress(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LoadingDetailText.Text = message;
                Debug.WriteLine($"📊 {message}");
            });
        }

        #endregion

        #region Rendering

        private void RenderTopology()
        {
            TopologyCanvas.Children.Clear();

            if (!_devices.Any())
            {
                Debug.WriteLine("⚠️ No devices to render");
                return;
            }

            Debug.WriteLine($"🎨 Rendering {_devices.Count} devices...");

            // Calculate positions for all devices
            CalculateDevicePositions();

            // Draw connections first (so they appear behind nodes)
            DrawConnections();

            // Draw device nodes
            DrawDeviceNodes();

            Debug.WriteLine("✅ Rendering complete");
        }

        private void CalculateDevicePositions()
        {
            // Use hierarchical tree layout instead of rigid grid
            var layers = _devices.GroupBy(d => d.NetworkLayer).OrderBy(g => g.Key).ToList();

            Debug.WriteLine($"📐 Calculating tree positions for {layers.Count} layers");

            // Calculate tree layout with proper spacing
            double currentY = 150; // Start further down

            foreach (var layer in layers)
            {
                int layerIndex = layer.Key;
                var devicesInLayer = layer.ToList();
                int deviceCount = devicesInLayer.Count;

                Debug.WriteLine($"  Layer {layerIndex}: {deviceCount} devices");

                if (layerIndex == 0)
                {
                    // Gateway: center at top
                    foreach (var device in devicesInLayer)
                    {
                        device.X = 1500; // Center in 3000px canvas
                        device.Y = currentY;
                        Debug.WriteLine($"    Gateway {device.IPAddress} at ({device.X:F0}, {device.Y:F0})");
                    }
                }
                else
                {
                    // Get parent devices from previous layer
                    var parents = devicesInLayer
                        .Select(d => _devices.FirstOrDefault(p => p.IPAddress == d.ParentDeviceId))
                        .Where(p => p != null)
                        .Distinct()
                        .ToList();

                    if (parents.Any())
                    {
                        // Position children around their parents in a tree structure
                        foreach (var parent in parents)
                        {
                            var children = devicesInLayer
                                .Where(d => d.ParentDeviceId == parent.IPAddress)
                                .ToList();

                            if (children.Any())
                            {
                                PositionChildrenAroundParent(parent, children);
                            }
                        }
                    }
                    else
                    {
                        // No parent found, spread horizontally
                        double totalWidth = deviceCount * (NODE_WIDTH + 100);
                        double startX = 1500 - (totalWidth / 2);

                        for (int i = 0; i < deviceCount; i++)
                        {
                            var device = devicesInLayer[i];
                            device.X = startX + (i * (NODE_WIDTH + 100));
                            device.Y = currentY;
                        }
                    }
                }

                // Move to next layer
                currentY += LAYER_VERTICAL_SPACING + 50; // More vertical space
            }
        }

        private void PositionChildrenAroundParent(TopologyNetworkDevice parent, List<TopologyNetworkDevice> children)
        {
            int childCount = children.Count;

            // Calculate spread based on number of children
            double spreadWidth = Math.Max(childCount * (NODE_WIDTH + 80), 400);
            double parentY = parent.Y + LAYER_VERTICAL_SPACING;

            if (childCount == 1)
            {
                // Single child: directly below parent
                children[0].X = parent.X;
                children[0].Y = parentY;
            }
            else if (childCount == 2)
            {
                // Two children: on either side
                children[0].X = parent.X - 150;
                children[0].Y = parentY;
                children[1].X = parent.X + 150;
                children[1].Y = parentY;
            }
            else
            {
                // Multiple children: spread evenly
                double startX = parent.X - (spreadWidth / 2);
                double spacing = spreadWidth / (childCount - 1);

                for (int i = 0; i < childCount; i++)
                {
                    children[i].X = startX + (i * spacing);
                    children[i].Y = parentY + (Math.Abs(i - (childCount / 2.0)) * 20); // Slight arc
                }
            }

            Debug.WriteLine($"    Positioned {childCount} children around parent {parent.IPAddress}");
        }

        private void DrawConnections()
        {
            foreach (var device in _devices.Where(d => !string.IsNullOrEmpty(d.ParentDeviceId)))
            {
                // Find parent device by IP
                var parent = _devices.FirstOrDefault(d => d.IPAddress == device.ParentDeviceId);

                if (parent == null)
                    continue;

                // Calculate connection points (bottom of parent to top of child)
                double x1 = parent.X + NODE_WIDTH / 2;
                double y1 = parent.Y + NODE_HEIGHT;
                double x2 = device.X + NODE_WIDTH / 2;
                double y2 = device.Y;

                // Determine line color and style based on connection type and device type
                Color lineColor;
                double thickness = 2;
                DoubleCollection dashArray = null;

                // Infrastructure connections (router/AP to gateway) - solid, thicker
                if (device.DeviceType == TopologyDeviceType.Router ||
                    device.DeviceType == TopologyDeviceType.AccessPoint)
                {
                    lineColor = Color.FromRgb(0, 188, 212); // Cyan for infrastructure
                    thickness = 3;
                }
                // Wireless connections - dashed
                else if (device.ConnectionType == TopologyConnectionType.Wireless)
                {
                    lineColor = Color.FromRgb(156, 39, 176); // Purple for wireless
                    dashArray = new DoubleCollection { 8, 4 };  // Longer dashes for wireless
                }
                // Wired connections - solid
                else if (device.ConnectionType == TopologyConnectionType.Wired)
                {
                    lineColor = Color.FromRgb(76, 175, 80); // Green for wired
                }
                // Unknown - lighter dashed
                else
                {
                    lineColor = Color.FromRgb(150, 150, 150); // Gray for unknown
                    dashArray = new DoubleCollection { 4, 4 };
                }

                // Create curved path using bezier curve for organic look
                var path = new Path
                {
                    Stroke = new SolidColorBrush(Color.FromArgb(180, lineColor.R, lineColor.G, lineColor.B)),
                    StrokeThickness = thickness,
                    StrokeDashArray = dashArray
                };

                // Calculate control points for bezier curve
                double controlOffset = Math.Abs(y2 - y1) / 2;
                Point controlPoint1 = new Point(x1, y1 + controlOffset);
                Point controlPoint2 = new Point(x2, y2 - controlOffset);

                var pathGeometry = new PathGeometry();
                var pathFigure = new PathFigure { StartPoint = new Point(x1, y1) };

                // Use bezier curve for smooth, organic connection
                var bezierSegment = new BezierSegment
                {
                    Point1 = controlPoint1,
                    Point2 = controlPoint2,
                    Point3 = new Point(x2, y2)
                };

                pathFigure.Segments.Add(bezierSegment);
                pathGeometry.Figures.Add(pathFigure);
                path.Data = pathGeometry;

                TopologyCanvas.Children.Add(path);

                // Add subtle glow effect for infrastructure connections
                if (thickness >= 3)
                {
                    var glowPath = new Path
                    {
                        Stroke = new SolidColorBrush(Color.FromArgb(40, lineColor.R, lineColor.G, lineColor.B)),
                        StrokeThickness = thickness + 6,
                        Data = pathGeometry
                    };
                    TopologyCanvas.Children.Insert(0, glowPath); // Behind main line
                }

                // Add arrowhead to show direction
                AddArrowhead(x2, y2, controlPoint2, lineColor);
            }
        }

        private void AddArrowhead(double x, double y, Point fromPoint, Color color)
        {
            // Calculate angle from control point to endpoint
            double angle = Math.Atan2(y - fromPoint.Y, x - fromPoint.X);

            // Arrowhead size
            double arrowSize = 10;

            // Calculate arrowhead points
            double angle1 = angle + Math.PI * 0.85;
            double angle2 = angle - Math.PI * 0.85;

            Point arrowPoint1 = new Point(x - arrowSize * Math.Cos(angle1), y - arrowSize * Math.Sin(angle1));
            Point arrowPoint2 = new Point(x - arrowSize * Math.Cos(angle2), y - arrowSize * Math.Sin(angle2));

            // Create arrowhead polygon
            var arrow = new Polygon
            {
                Points = new PointCollection { new Point(x, y), arrowPoint1, arrowPoint2 },
                Fill = new SolidColorBrush(Color.FromArgb(180, color.R, color.G, color.B))
            };

            TopologyCanvas.Children.Add(arrow);
        }

        private void DrawDeviceNodes()
        {
            foreach (var device in _devices)
            {
                // Create device node
                var node = CreateDeviceNode(device);

                // Position it
                Canvas.SetLeft(node, device.X);
                Canvas.SetTop(node, device.Y);

                // Add to canvas
                TopologyCanvas.Children.Add(node);

                // Animate appearance
                node.Opacity = 0;
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300));
                node.BeginAnimation(UIElement.OpacityProperty, fadeIn);
            }
        }

        private Border CreateDeviceNode(TopologyNetworkDevice device)
        {
            // Determine color based on device type
            var color = GetDeviceColor(device);

            // Create node UI
            var border = new Border
            {
                Width = NODE_WIDTH,
                Height = NODE_HEIGHT,
                Background = new SolidColorBrush(Color.FromArgb(230, color.R, color.G, color.B)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(255, color.R, color.G, color.B)),
                BorderThickness = new Thickness(2),
                CornerRadius = new CornerRadius(8),
                Cursor = Cursors.Hand,
                Tag = device
            };

            // Create content
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Device icon/type
            var typeText = new TextBlock
            {
                Text = GetDeviceIcon(device),
                FontSize = 24,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = Brushes.White
            };
            Grid.SetRow(typeText, 0);
            grid.Children.Add(typeText);

            // Device name/IP
            var nameText = new TextBlock
            {
                Text = string.IsNullOrEmpty(device.Hostname) ? device.IPAddress : device.Hostname,
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                Foreground = Brushes.White,
                Margin = new Thickness(5, 0, 5, 2),
                TextTrimming = TextTrimming.CharacterEllipsis,
                TextWrapping = TextWrapping.Wrap, // Allow wrapping
                MaxWidth = NODE_WIDTH - 10, // Ensure it fits
                TextAlignment = TextAlignment.Center
            };
            Grid.SetRow(nameText, 1);
            grid.Children.Add(nameText);

            // Device IP
            var ipText = new TextBlock
            {
                Text = device.IPAddress,
                FontSize = 9,
                HorizontalAlignment = HorizontalAlignment.Center,
                Foreground = new SolidColorBrush(Color.FromArgb(200, 255, 255, 255)),
                Margin = new Thickness(5, 0, 5, 5),
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = NODE_WIDTH - 10
            };
            Grid.SetRow(ipText, 2);
            grid.Children.Add(ipText);

            border.Child = grid;

            // Add hover effect
            border.MouseEnter += (s, e) =>
            {
                border.BorderThickness = new Thickness(3);
                var scaleTransform = new ScaleTransform(1.05, 1.05);
                border.RenderTransform = scaleTransform;
                border.RenderTransformOrigin = new Point(0.5, 0.5);
            };

            border.MouseLeave += (s, e) =>
            {
                border.BorderThickness = new Thickness(2);
                border.RenderTransform = null;
            };

            // Add click handler
            border.MouseLeftButtonDown += DeviceNode_Click;

            return border;
        }

        private Color GetDeviceColor(TopologyNetworkDevice device)
        {
            if (device.IsGateway)
                return Color.FromRgb(46, 125, 50); // Green

            switch (device.DeviceType)
            {
                case TopologyDeviceType.Router:
                    return Color.FromRgb(56, 142, 60);
                case TopologyDeviceType.AccessPoint:
                    return Color.FromRgb(67, 160, 71);
                case TopologyDeviceType.Server:
                    return Color.FromRgb(211, 47, 47);
                case TopologyDeviceType.Desktop:
                    return Color.FromRgb(25, 118, 210);
                case TopologyDeviceType.Mobile:
                    return Color.FromRgb(156, 39, 176);
                case TopologyDeviceType.Laptop:
                    return Color.FromRgb(48, 63, 159);
                default:
                    return Color.FromRgb(97, 97, 97);
            }
        }

        private string GetDeviceIcon(TopologyNetworkDevice device)
        {
            if (device.IsGateway) return "🌐";

            switch (device.DeviceType)
            {
                case TopologyDeviceType.Router: return "📡";
                case TopologyDeviceType.AccessPoint: return "📶";
                case TopologyDeviceType.Server: return "🖥️";
                case TopologyDeviceType.Desktop: return "💻";
                case TopologyDeviceType.Laptop: return "💻";
                case TopologyDeviceType.Mobile: return "📱";
                default: return "❓";
            }
        }

        private void DeviceNode_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border && border.Tag is TopologyNetworkDevice device)
            {
                ShowDeviceDetails(device);
            }
        }

        private void ShowDeviceDetails(TopologyNetworkDevice device)
        {
            _selectedDevice = device;
            DetailsPanelBorder.Visibility = Visibility.Visible;

            DeviceIconText.Text = GetDeviceIcon(device);
            DeviceNameText.Text = string.IsNullOrEmpty(device.Hostname) ? "Unknown Device" : device.Hostname;
            DeviceIPText.Text = device.IPAddress ?? "Unknown";
            DeviceMACText.Text = device.MACAddress ?? "Unknown";
            DeviceVendorText.Text = device.Vendor ?? "Unknown";
            DeviceTypeText.Text = device.DeviceType.ToString();
            DeviceHostnameText.Text = string.IsNullOrEmpty(device.Hostname) ? "N/A" : device.Hostname;
            DeviceConnectionText.Text = device.ConnectionType.ToString();
            DeviceLayerText.Text = device.NetworkLayer.ToString();

            // Set parent device
            if (!string.IsNullOrEmpty(device.ParentDeviceId))
            {
                var parent = _devices.FirstOrDefault(d => d.IPAddress == device.ParentDeviceId);
                DeviceParentText.Text = parent != null
                    ? (string.IsNullOrEmpty(parent.Hostname) ? parent.IPAddress : parent.Hostname)
                    : device.ParentDeviceId;
            }
            else
            {
                DeviceParentText.Text = "None (Root)";
            }

            // Show access button for routers/APs
            bool isInfrastructure = device.DeviceType == TopologyDeviceType.Router ||
                                   device.DeviceType == TopologyDeviceType.AccessPoint ||
                                   device.IsGateway;

            AccessRouterButton.Visibility = isInfrastructure ? Visibility.Visible : Visibility.Collapsed;
            AccessRouterButton.Tag = device;

            if (isInfrastructure)
            {
                AccessRouterButton.Content = device.DeviceType == TopologyDeviceType.AccessPoint
                    ? "🌐 Access AP Admin"
                    : "🌐 Access Router Admin";
            }
        }

        private void CloseDetailsPanel_Click(object sender, RoutedEventArgs e)
        {
            DetailsPanelBorder.Visibility = Visibility.Collapsed;
        }

        private void AccessRouterButton_Click(object sender, RoutedEventArgs e)
        {
            if (AccessRouterButton.Tag is TopologyNetworkDevice device)
            {
                try
                {
                    var url = $"http://{device.IPAddress}";
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Could not open browser: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void ScanPortsButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedDevice == null)
            {
                AppDialog.Show("No device selected. Click a device node first.", "No Selection",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string ip = _selectedDevice.IPAddress;
            if (string.IsNullOrEmpty(ip))
            {
                AppDialog.Show("Selected device has no IP address.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            ScanPortsButton.IsEnabled = false;
            ScanPortsButton.Content = "Scanning...";

            try
            {
                var results = new System.Text.StringBuilder();
                results.AppendLine($"Port scan results for {ip}:\n");

                int[] commonPorts = { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443 };
                var openPorts = new List<int>();

                await System.Threading.Tasks.Task.Run(() =>
                {
                    foreach (int port in commonPorts)
                    {
                        try
                        {
                            using var tcp = new System.Net.Sockets.TcpClient();
                            var connect = tcp.BeginConnect(ip, port, null, null);
                            bool connected = connect.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(300));
                            if (connected && tcp.Connected)
                            {
                                tcp.EndConnect(connect);
                                openPorts.Add(port);
                            }
                        }
                        catch { }
                    }
                });

                if (openPorts.Count == 0)
                {
                    results.AppendLine("No common ports open.");
                }
                else
                {
                    foreach (var p in openPorts)
                        results.AppendLine($"  Port {p}: OPEN");
                }

                AppDialog.Show(results.ToString(), $"Port Scan - {ip}",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Port scan failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ScanPortsButton.IsEnabled = true;
                ScanPortsButton.Content = "Scan Ports";
            }
        }


        private async void PingDeviceButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedDevice == null)
            {
                AppDialog.Show("No device selected. Click a device node first.", "No Selection",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string ip = _selectedDevice.IPAddress;
            if (string.IsNullOrEmpty(ip))
            {
                AppDialog.Show("Selected device has no IP address.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            PingDeviceButton.IsEnabled = false;
            PingDeviceButton.Content = "Pinging...";

            try
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"Ping results for {ip}:\n");

                await System.Threading.Tasks.Task.Run(() =>
                {
                    using var ping = new System.Net.NetworkInformation.Ping();
                    for (int i = 0; i < 4; i++)
                    {
                        try
                        {
                            var reply = ping.Send(ip, 2000);
                            if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                                sb.AppendLine($"  Reply from {ip}: time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}");
                            else
                                sb.AppendLine($"  Request timed out.");
                        }
                        catch (Exception ex) { sb.AppendLine($"  Error: {ex.Message}"); }
                        System.Threading.Thread.Sleep(500);
                    }
                });

                AppDialog.Show(sb.ToString(), $"Ping - {ip}", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Ping failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                PingDeviceButton.IsEnabled = true;
                PingDeviceButton.Content = "Ping Device";
            }
        }

        private void UpdateStatistics()
        {
            TotalDevicesText.Text = _devices.Count.ToString();
            RoutersCountText.Text = _devices.Count(d => d.DeviceType == TopologyDeviceType.Router || d.IsGateway).ToString();
            AccessPointsCountText.Text = _devices.Count(d => d.DeviceType == TopologyDeviceType.AccessPoint).ToString();
            EndpointsCountText.Text = _devices.Count(d => d.DeviceType != TopologyDeviceType.Router &&
                                                           d.DeviceType != TopologyDeviceType.AccessPoint &&
                                                           !d.IsGateway).ToString();
        }

        private void ApplyZoom(double delta, Point center)
        {
            double newZoom = Math.Max(MIN_ZOOM, Math.Min(MAX_ZOOM, _currentZoom + delta));
            if (Math.Abs(newZoom - _currentZoom) < 0.001) return;

            double zoomFactor = newZoom / _currentZoom;
            _currentZoom = newZoom;

            CanvasScaleTransform.ScaleX = _currentZoom;
            CanvasScaleTransform.ScaleY = _currentZoom;

            if (CanvasTranslateTransform != null)
            {
                CanvasTranslateTransform.X = center.X - zoomFactor * (center.X - CanvasTranslateTransform.X);
                CanvasTranslateTransform.Y = center.Y - zoomFactor * (center.Y - CanvasTranslateTransform.Y);
            }

            Debug.WriteLine($"Zoom: {_currentZoom:F2}");
        }

        private void TopologyCanvas_MouseWheel(object sender, MouseWheelEventArgs e)
        {
            double delta = e.Delta > 0 ? ZOOM_STEP : -ZOOM_STEP;
            Point mousePos = e.GetPosition(TopologyCanvas);
            ApplyZoom(delta, mousePos);
            e.Handled = true;
        }

        private void TopologyCanvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 1)
            {
                _isPanning = true;
                _panStartPoint = e.GetPosition(TopologyCanvas.Parent as System.Windows.UIElement ?? TopologyCanvas);
                if (CanvasTranslateTransform != null)
                    _panStartTranslate = new Point(CanvasTranslateTransform.X, CanvasTranslateTransform.Y);
                TopologyCanvas.CaptureMouse();
            }
        }

        private void TopologyCanvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            _isPanning = false;
            TopologyCanvas.ReleaseMouseCapture();
        }

        private void TopologyCanvas_MouseMove(object sender, MouseEventArgs e)
        {
            if (!_isPanning || CanvasTranslateTransform == null) return;
            Point current = e.GetPosition(TopologyCanvas.Parent as System.Windows.UIElement ?? TopologyCanvas);
            CanvasTranslateTransform.X = _panStartTranslate.X + (current.X - _panStartPoint.X);
            CanvasTranslateTransform.Y = _panStartTranslate.Y + (current.Y - _panStartPoint.Y);
        }
        private void ZoomIn_Click(object sender, RoutedEventArgs e)
        {
            Point center = new Point(TopologyCanvas.ActualWidth / 2, TopologyCanvas.ActualHeight / 2);
            ApplyZoom(ZOOM_STEP, center);
        }

        private void ZoomOut_Click(object sender, RoutedEventArgs e)
        {
            Point center = new Point(TopologyCanvas.ActualWidth / 2, TopologyCanvas.ActualHeight / 2);
            ApplyZoom(-ZOOM_STEP, center);
        }

        private void ResetViewButton_Click(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("🔄 Resetting view...");

            if (_devices.Any())
            {
                CenterOnDevices();
            }
            else
            {
                ResetView();
            }
        }

        private void CenterOnDevices()
        {
            if (!_devices.Any())
            {
                Debug.WriteLine("⚠️ No devices to center on");
                return;
            }

            try
            {
                // Calculate bounding box (all coordinates are now positive)
                double minX = _devices.Min(d => d.X);
                double maxX = _devices.Max(d => d.X + NODE_WIDTH);
                double minY = _devices.Min(d => d.Y);
                double maxY = _devices.Max(d => d.Y + NODE_HEIGHT);

                double contentWidth = maxX - minX;
                double contentHeight = maxY - minY;
                double centerX = (minX + maxX) / 2;
                double centerY = (minY + maxY) / 2;

                Debug.WriteLine($"📐 Bounding box: ({minX:F0},{minY:F0}) to ({maxX:F0},{maxY:F0})");
                Debug.WriteLine($"📐 Content: {contentWidth:F0}x{contentHeight:F0}, Center: ({centerX:F0}, {centerY:F0})");

                // Get viewport size
                double viewWidth = TopologyCanvas.ActualWidth;
                double viewHeight = TopologyCanvas.ActualHeight;

                if (viewWidth <= 0 || viewHeight <= 0)
                {
                    Debug.WriteLine("⚠️ View not ready, using defaults");
                    viewWidth = 1200;
                    viewHeight = 800;
                }

                Debug.WriteLine($"📐 Viewport: {viewWidth:F0}x{viewHeight:F0}");

                // Calculate zoom to fit content with padding (use 80% of viewport)
                double zoomX = (viewWidth * 0.8) / Math.Max(contentWidth, 1);
                double zoomY = (viewHeight * 0.8) / Math.Max(contentHeight, 1);
                double fitZoom = Math.Min(zoomX, zoomY);

                // Clamp zoom between min and max
                fitZoom = Math.Max(MIN_ZOOM, Math.Min(MAX_ZOOM, Math.Min(fitZoom, 1.5)));

                Debug.WriteLine($"🔍 Calculated zoom: {fitZoom:F2} (zoomX={zoomX:F2}, zoomY={zoomY:F2})");

                // Apply zoom
                _currentZoom = fitZoom;
                CanvasScaleTransform.ScaleX = _currentZoom;
                CanvasScaleTransform.ScaleY = _currentZoom;
                BackgroundScaleTransform.ScaleX = _currentZoom;
                BackgroundScaleTransform.ScaleY = _currentZoom;

                // Center the content in viewport
                // Translate so content center appears at viewport center
                double offsetX = (viewWidth / 2) - (centerX * _currentZoom);
                double offsetY = (viewHeight / 2) - (centerY * _currentZoom);

                CanvasTranslateTransform.X = offsetX;
                CanvasTranslateTransform.Y = offsetY;
                BackgroundTranslateTransform.X = offsetX;
                BackgroundTranslateTransform.Y = offsetY;

                ZoomLevelText.Text = $"{(int)(_currentZoom * 100)}%";

                Debug.WriteLine($"✅ View centered: Zoom={_currentZoom:F2}, Offset=({offsetX:F0}, {offsetY:F0})");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Error centering view: {ex.Message}");
                Debug.WriteLine($"   Stack trace: {ex.StackTrace}");
                ResetView();
            }
        }

        private void ResetView()
        {
            _currentZoom = 1.0;

            CanvasScaleTransform.ScaleX = 1.0;
            CanvasScaleTransform.ScaleY = 1.0;
            BackgroundScaleTransform.ScaleX = 1.0;
            BackgroundScaleTransform.ScaleY = 1.0;

            CanvasTranslateTransform.X = 0;
            CanvasTranslateTransform.Y = 0;
            BackgroundTranslateTransform.X = 0;
            BackgroundTranslateTransform.Y = 0;

            ZoomLevelText.Text = "100%";

            Debug.WriteLine("✅ View reset to defaults");
        }

        #endregion

        #region Export

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_devices.Any())
            {
                AppDialog.Show("No devices to export. Please scan the network first.", "No Data",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                var saveDialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                    FileName = $"NetworkTopology_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    var report = GenerateReport();
                    System.IO.File.WriteAllText(saveDialog.FileName, report);

                    AppDialog.Show($"Topology exported successfully to:\n{saveDialog.FileName}", "Success",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Export failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateReport()
        {
            var report = new System.Text.StringBuilder();

            report.AppendLine("Network Topology Report");
            report.AppendLine($"Generated: {DateTime.Now:dd/MM/yyyy hh:mm:ss tt}");
            report.AppendLine($"Total Devices: {_devices.Count}");
            report.AppendLine();
            report.AppendLine("Devices:");
            report.AppendLine("========");
            report.AppendLine();

            foreach (var device in _devices.OrderBy(d => d.NetworkLayer).ThenBy(d => d.IPAddress))
            {
                report.AppendLine($"Device: {device.Hostname ?? device.IPAddress}");
                report.AppendLine($"  Type: {device.DeviceType}");
                report.AppendLine($"  IP: {device.IPAddress}");
                report.AppendLine($"  MAC: {device.MACAddress ?? "Unknown"}");
                report.AppendLine($"  Vendor: {device.Vendor ?? "Unknown"}");
                report.AppendLine($"  Layer: {device.NetworkLayer}");
                report.AppendLine();
            }

            return report.ToString();
        }

        #endregion
    }
}


