using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Advanced traffic capture and analysis service
    /// </summary>
    public class TrafficCaptureService : INotifyPropertyChanged, IDisposable
    {
        #region Singleton

        private static readonly Lazy<TrafficCaptureService> _instance =
            new Lazy<TrafficCaptureService>(() => new TrafficCaptureService());

        public static TrafficCaptureService Instance => _instance.Value;

        #endregion

        #region Fields

        private ILiveDevice? _selectedDevice;
        private bool _isCapturing;
        private CancellationTokenSource? _cancellationTokenSource;
        private DateTime _captureStartTime;
        private int _packetCounter;
        private readonly object _lockObject = new object();
        private readonly ProtocolAnalyzerService _protocolAnalyzer;

        // Statistics update timer
        private System.Timers.Timer? _statsUpdateTimer;
        private long _bytesLastSecond;
        private int _packetsLastSecond;
        private DateTime _lastStatsUpdate;

        // Packet queue for async processing
        private readonly ConcurrentQueue<RawCapture> _packetQueue = new ConcurrentQueue<RawCapture>();
        private Task? _packetProcessingTask;

        // UI batch dispatch — collect packets and flush every 250 ms instead of one BeginInvoke per packet
        private readonly List<EnhancedPacketInfo> _uiPendingPackets = new List<EnhancedPacketInfo>();
        private readonly object _uiPendingLock = new object();
        private System.Timers.Timer? _uiBatchTimer;

        // Conversation tracking
        private readonly Dictionary<string, Conversation> _conversationLookup = new Dictionary<string, Conversation>();
        private int _streamCounter;

        // I/O graph tracking
        private readonly List<(DateTime Time, int Packets, long Bytes)> _ioDataBuffer = new List<(DateTime, int, long)>();
        private DateTime _lastIOGraphUpdate;

        #endregion

        #region Properties

        public ObservableCollection<EnhancedPacketInfo> CapturedPackets { get; } = new ObservableCollection<EnhancedPacketInfo>();
        public ObservableCollection<Conversation> Conversations { get; } = new ObservableCollection<Conversation>();
        public ObservableCollection<TrafficAlert> Alerts { get; } = new ObservableCollection<TrafficAlert>();
        public ObservableCollection<IOGraphDataPoint> IOGraphData { get; } = new ObservableCollection<IOGraphDataPoint>();

        public TrafficStatistics Statistics { get; } = new TrafficStatistics();
        public TrafficPacketFilter CurrentFilter { get; } = new TrafficPacketFilter();

        private ObservableCollection<EnhancedPacketInfo> _filteredPackets = new ObservableCollection<EnhancedPacketInfo>();
        public ObservableCollection<EnhancedPacketInfo> FilteredPackets
        {
            get => _filteredPackets;
            private set { _filteredPackets = value; OnPropertyChanged(); }
        }

        public bool IsCapturing
        {
            get => _isCapturing;
            private set { _isCapturing = value; OnPropertyChanged(); }
        }

        public ILiveDevice SelectedDevice
        {
            get => _selectedDevice;
            set { _selectedDevice = value; OnPropertyChanged(); }
        }

        public List<ILiveDevice> AvailableDevices { get; private set; } = new List<ILiveDevice>();

        private string _captureStatus = "Ready";
        public string CaptureStatus
        {
            get => _captureStatus;
            private set { _captureStatus = value; OnPropertyChanged(); }
        }

        #endregion

        #region Constructor

        private TrafficCaptureService()
        {
            _protocolAnalyzer = ProtocolAnalyzerService.Instance;
            LoadAvailableDevices();
            InitializeStatsTimer();
        }

        #endregion

        #region Initialization

        private void InitializeStatsTimer()
        {
            _statsUpdateTimer = new System.Timers.Timer(1000); // Update every second
            _statsUpdateTimer.Elapsed += (s, e) => UpdateStatistics();
            _statsUpdateTimer.AutoReset = true;
        }

        private void StartUIBatchTimer()
        {
            _uiBatchTimer = new System.Timers.Timer(250);
            _uiBatchTimer.Elapsed += (s, e) => FlushPendingPacketsToUI();
            _uiBatchTimer.AutoReset = true;
            _uiBatchTimer.Start();
        }

        private void StopUIBatchTimer()
        {
            _uiBatchTimer?.Stop();
            _uiBatchTimer?.Dispose();
            _uiBatchTimer = null;
            // Final flush
            FlushPendingPacketsToUI();
        }

        private void FlushPendingPacketsToUI()
        {
            EnhancedPacketInfo[] batch;
            lock (_uiPendingLock)
            {
                if (_uiPendingPackets.Count == 0) return;
                batch = _uiPendingPackets.ToArray();
                _uiPendingPackets.Clear();
            }

            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                foreach (var p in batch)
                {
                    CapturedPackets.Add(p);
                    if (CurrentFilter.ShouldDisplayPacket(p))
                        FilteredPackets.Add(p);
                }
                while (CapturedPackets.Count > 100000) CapturedPackets.RemoveAt(0);
                while (FilteredPackets.Count > 50000) FilteredPackets.RemoveAt(0);
            }));
        }

        #endregion

        #region Device Management

        public void LoadAvailableDevices()
        {
            try
            {
                AvailableDevices.Clear();
                var devices = CaptureDeviceList.Instance;

                foreach (var device in devices)
                {
                    AvailableDevices.Add(device);
                }

                if (AvailableDevices.Count > 0)
                {
                    SelectedDevice = AvailableDevices.FirstOrDefault(d =>
                        !d.Description?.Contains("Loopback", StringComparison.OrdinalIgnoreCase) == true)
                        ?? AvailableDevices.First();
                }

                CaptureStatus = $"Found {AvailableDevices.Count} network interfaces";
            }
            catch (Exception ex)
            {
                CaptureStatus = $"Error loading devices: {ex.Message}";
            }
        }

        public void SelectDevice(int index)
        {
            if (index >= 0 && index < AvailableDevices.Count)
            {
                SelectedDevice = AvailableDevices[index];
            }
        }

        public void SelectDevice(ILiveDevice device)
        {
            if (device != null && AvailableDevices.Contains(device))
            {
                SelectedDevice = device;
            }
        }

        #endregion

        #region Capture Control

        public async Task StartCaptureAsync(string? captureFilter = null)
        {
            if (IsCapturing) return;
            if (SelectedDevice == null)
            {
                CaptureStatus = "No device selected";
                return;
            }

            try
            {
                _cancellationTokenSource = new CancellationTokenSource();
                _packetCounter = 0;
                _captureStartTime = DateTime.Now;
                _lastStatsUpdate = DateTime.Now;
                _lastIOGraphUpdate = DateTime.Now;
                _bytesLastSecond = 0;
                _packetsLastSecond = 0;

                // Reset statistics
                Statistics.CaptureStartTime = _captureStartTime;
                Statistics.TotalPackets = 0;
                Statistics.TotalBytes = 0;
                Statistics.ProtocolPacketCounts.Clear();
                Statistics.ProtocolByteCounts.Clear();
                Statistics.TopSourceIPs.Clear();
                Statistics.TopDestinationIPs.Clear();
                Statistics.TopPorts.Clear();

                // Open device
                SelectedDevice.OnPacketArrival += OnPacketArrival;
                SelectedDevice.Open(DeviceModes.Promiscuous, 1000);

                // Apply capture filter if provided
                if (!string.IsNullOrEmpty(captureFilter))
                {
                    try
                    {
                        SelectedDevice.Filter = captureFilter;
                    }
                    catch (Exception ex)
                    {
                        CaptureStatus = $"Invalid filter: {ex.Message}";
                        return;
                    }
                }

                // Start packet processing task
                _packetProcessingTask = Task.Run(() => ProcessPacketQueueAsync(_cancellationTokenSource.Token));

                // Start capture
                SelectedDevice.StartCapture();
                IsCapturing = true;
                _statsUpdateTimer.Start();
                StartUIBatchTimer();

                CaptureStatus = $"Capturing on {SelectedDevice.Description}";
            }
            catch (Exception ex)
            {
                CaptureStatus = $"Capture failed: {ex.Message}";
                StopCapture();
            }
        }

        public void StopCapture()
        {
            if (!IsCapturing && SelectedDevice == null) return;

            try
            {
                _statsUpdateTimer.Stop();
                StopUIBatchTimer();
                _cancellationTokenSource?.Cancel();

                if (SelectedDevice != null)
                {
                    try
                    {
                        SelectedDevice.StopCapture();
                    }
                    catch { }

                    try
                    {
                        SelectedDevice.OnPacketArrival -= OnPacketArrival;
                        SelectedDevice.Close();
                    }
                    catch { }
                }

                // Wait for packet processing to complete
                _packetProcessingTask?.Wait(TimeSpan.FromSeconds(2));

                IsCapturing = false;
                CaptureStatus = $"Capture stopped. {Statistics.TotalPackets} packets captured.";
            }
            catch (Exception ex)
            {
                CaptureStatus = $"Error stopping capture: {ex.Message}";
            }
        }

        public void ClearCapture()
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                CapturedPackets.Clear();
                FilteredPackets.Clear();
                Conversations.Clear();
                Alerts.Clear();
                IOGraphData.Clear();
            });

            _conversationLookup.Clear();
            _streamCounter = 0;
            _packetCounter = 0;

            // Reset statistics
            Statistics.TotalPackets = 0;
            Statistics.TotalBytes = 0;
            Statistics.PacketsPerSecond = 0;
            Statistics.BytesPerSecond = 0;
            Statistics.AveragePacketSize = 0;
            Statistics.CaptureDuration = TimeSpan.Zero;
            Statistics.ProtocolPacketCounts.Clear();
            Statistics.ProtocolByteCounts.Clear();
            Statistics.TopSourceIPs.Clear();
            Statistics.TopDestinationIPs.Clear();
            Statistics.TopPorts.Clear();
            Statistics.ThreatCount = 0;
            Statistics.ThreatsByLevel.Clear();

            CaptureStatus = "Capture cleared";
        }

        #endregion

        #region Packet Processing

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            // Queue packet for async processing
            _packetQueue.Enqueue(e.GetPacket());
        }

        private async Task ProcessPacketQueueAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (_packetQueue.TryDequeue(out var rawCapture))
                    {
                        ProcessRawPacket(rawCapture);
                    }
                    else
                    {
                        await Task.Delay(10, cancellationToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Packet processing error: {ex.Message}");
                }
            }

            // Process remaining packets
            while (_packetQueue.TryDequeue(out var rawCapture))
            {
                ProcessRawPacket(rawCapture);
            }
        }

        private void ProcessRawPacket(RawCapture rawCapture)
        {
            try
            {
                var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                var packetNumber = Interlocked.Increment(ref _packetCounter);

                // Analyze packet
                var enhancedPacket = _protocolAnalyzer.AnalyzePacket(
                    packet, rawCapture.Data, packetNumber, _captureStartTime);

                // Update statistics
                UpdatePacketStatistics(enhancedPacket);

                // Track conversation
                TrackConversation(enhancedPacket);

                // Check for threats and create alerts
                if (enhancedPacket.ThreatLevel > ThreatLevel.None)
                {
                    CreateAlert(enhancedPacket);
                }

                // Track I/O data
                lock (_ioDataBuffer)
                {
                    _ioDataBuffer.Add((DateTime.Now, 1, enhancedPacket.Length));
                }

                // Queue for batched UI dispatch (250ms flush interval)
                lock (_uiPendingLock)
                {
                    _uiPendingPackets.Add(enhancedPacket);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error processing packet: {ex.Message}");
            }
        }

        #endregion

        #region Statistics

        private void UpdatePacketStatistics(EnhancedPacketInfo packet)
        {
            lock (_lockObject)
            {
                Statistics.TotalPackets++;
                Statistics.TotalBytes += packet.Length;
                _bytesLastSecond += packet.Length;
                _packetsLastSecond++;

                // Protocol counts
                var proto = packet.Protocol ?? "Unknown";
                if (!Statistics.ProtocolPacketCounts.ContainsKey(proto))
                {
                    Statistics.ProtocolPacketCounts[proto] = 0;
                    Statistics.ProtocolByteCounts[proto] = 0;
                }
                Statistics.ProtocolPacketCounts[proto]++;
                Statistics.ProtocolByteCounts[proto] += packet.Length;

                // Top source IPs
                if (!string.IsNullOrEmpty(packet.SourceIP))
                {
                    if (!Statistics.TopSourceIPs.ContainsKey(packet.SourceIP))
                        Statistics.TopSourceIPs[packet.SourceIP] = 0;
                    Statistics.TopSourceIPs[packet.SourceIP]++;
                }

                // Top destination IPs
                if (!string.IsNullOrEmpty(packet.DestinationIP))
                {
                    if (!Statistics.TopDestinationIPs.ContainsKey(packet.DestinationIP))
                        Statistics.TopDestinationIPs[packet.DestinationIP] = 0;
                    Statistics.TopDestinationIPs[packet.DestinationIP]++;
                }

                // Top ports
                if (packet.DestinationPort > 0)
                {
                    if (!Statistics.TopPorts.ContainsKey(packet.DestinationPort))
                        Statistics.TopPorts[packet.DestinationPort] = 0;
                    Statistics.TopPorts[packet.DestinationPort]++;
                }

                // Threat statistics
                if (packet.ThreatLevel > ThreatLevel.None)
                {
                    Statistics.ThreatCount++;
                    if (!Statistics.ThreatsByLevel.ContainsKey(packet.ThreatLevel))
                        Statistics.ThreatsByLevel[packet.ThreatLevel] = 0;
                    Statistics.ThreatsByLevel[packet.ThreatLevel]++;
                }
            }
        }

        private void UpdateStatistics()
        {
            lock (_lockObject)
            {
                var now = DateTime.Now;
                var elapsed = (now - _lastStatsUpdate).TotalSeconds;

                if (elapsed > 0)
                {
                    Statistics.PacketsPerSecond = _packetsLastSecond / elapsed;
                    Statistics.BytesPerSecond = _bytesLastSecond / elapsed;
                    Statistics.CaptureDuration = now - _captureStartTime;

                    if (Statistics.TotalPackets > 0)
                    {
                        Statistics.AveragePacketSize = (double)Statistics.TotalBytes / Statistics.TotalPackets;
                    }

                    // Update I/O graph data
                    UpdateIOGraphData();

                    _bytesLastSecond = 0;
                    _packetsLastSecond = 0;
                    _lastStatsUpdate = now;
                }
            }
        }

        private void UpdateIOGraphData()
        {
            lock (_ioDataBuffer)
            {
                if (_ioDataBuffer.Count == 0) return;

                var now = DateTime.Now;
                var cutoff = now.AddSeconds(-60); // Keep last 60 seconds

                // Remove old data
                _ioDataBuffer.RemoveAll(d => d.Time < cutoff);

                // Group by second
                var groupedData = _ioDataBuffer
                    .GroupBy(d => new DateTime(d.Time.Year, d.Time.Month, d.Time.Day,
                        d.Time.Hour, d.Time.Minute, d.Time.Second))
                    .Select(g => new IOGraphDataPoint
                    {
                        Timestamp = g.Key,
                        PacketCount = g.Sum(x => x.Packets),
                        ByteCount = g.Sum(x => x.Bytes),
                        PacketsPerSecond = g.Sum(x => x.Packets),
                        BytesPerSecond = g.Sum(x => x.Bytes),
                        BitsPerSecond = g.Sum(x => x.Bytes) * 8
                    })
                    .OrderBy(d => d.Timestamp)
                    .ToList();

                Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                {
                    IOGraphData.Clear();
                    foreach (var point in groupedData)
                    {
                        IOGraphData.Add(point);
                    }
                }));
            }
        }

        #endregion

        #region Conversation Tracking

        private void TrackConversation(EnhancedPacketInfo packet)
        {
            if (string.IsNullOrEmpty(packet.ConversationId)) return;

            lock (_conversationLookup)
            {
                if (!_conversationLookup.TryGetValue(packet.ConversationId, out var conversation))
                {
                    conversation = new Conversation
                    {
                        Id = packet.ConversationId,
                        EndpointA = packet.SourceEndpoint,
                        EndpointB = packet.DestinationEndpoint,
                        Protocol = packet.Protocol,
                        AppProtocol = packet.AppProtocol,
                        StartTime = packet.Timestamp,
                        State = ConnectionState.New
                    };

                    _conversationLookup[packet.ConversationId] = conversation;
                    packet.StreamIndex = Interlocked.Increment(ref _streamCounter);

                    Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                    {
                        Conversations.Add(conversation);
                    }));
                }

                // Update conversation
                conversation.PacketCount++;
                conversation.LastActivity = packet.Timestamp;
                conversation.Packets.Add(packet);

                // Determine direction and update bytes
                if (packet.SourceEndpoint == conversation.EndpointA)
                {
                    conversation.BytesAtoB += packet.Length;
                    packet.Direction = PacketDirection.Outbound;
                }
                else
                {
                    conversation.BytesBtoA += packet.Length;
                    packet.Direction = PacketDirection.Inbound;
                }

                // Update connection state based on TCP flags
                if (packet.TcpFlags != null)
                {
                    UpdateConnectionState(conversation, packet);
                }

                packet.StreamIndex = conversation.Packets.IndexOf(packet) + 1;
            }
        }

        private void UpdateConnectionState(Conversation conversation, EnhancedPacketInfo packet)
        {
            if (packet.TcpFlags.SYN && !packet.TcpFlags.ACK)
            {
                conversation.State = ConnectionState.New;
            }
            else if (packet.TcpFlags.SYN && packet.TcpFlags.ACK)
            {
                conversation.State = ConnectionState.New;
            }
            else if (packet.TcpFlags.ACK && !packet.TcpFlags.SYN && !packet.TcpFlags.FIN && !packet.TcpFlags.RST)
            {
                if (conversation.State == ConnectionState.New)
                    conversation.State = ConnectionState.Established;
            }
            else if (packet.TcpFlags.FIN)
            {
                conversation.State = ConnectionState.Closing;
            }
            else if (packet.TcpFlags.RST)
            {
                conversation.State = ConnectionState.Reset;
            }
        }

        #endregion

        #region Alerts

        private void CreateAlert(EnhancedPacketInfo packet)
        {
            var alert = new TrafficAlert
            {
                Timestamp = packet.Timestamp,
                Severity = packet.ThreatLevel,
                Title = GetAlertTitle(packet),
                Description = packet.ThreatDescription ?? "Suspicious activity detected",
                SourceIP = packet.SourceIP,
                DestinationIP = packet.DestinationIP,
                RelatedPacketNumber = packet.PacketNumber,
                Category = GetAlertCategory(packet)
            };

            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                Alerts.Insert(0, alert);

                // Limit alerts
                while (Alerts.Count > 1000)
                {
                    Alerts.RemoveAt(Alerts.Count - 1);
                }
            }));
        }

        private string GetAlertTitle(EnhancedPacketInfo packet)
        {
            if (packet.ThreatDescription?.Contains("NULL scan") == true)
                return "NULL Scan Detected";
            if (packet.ThreatDescription?.Contains("XMAS scan") == true)
                return "XMAS Scan Detected";
            if (packet.ThreatDescription?.Contains("Suspicious port") == true)
                return "Suspicious Port Activity";
            if (packet.ThreatDescription?.Contains("Large ICMP") == true)
                return "Large ICMP Packet";
            if (packet.ThreatDescription?.Contains("DNS") == true)
                return "Suspicious DNS Activity";
            return "Network Anomaly Detected";
        }

        private string GetAlertCategory(EnhancedPacketInfo packet)
        {
            if (packet.ThreatDescription?.Contains("scan") == true)
                return "Reconnaissance";
            if (packet.ThreatDescription?.Contains("port") == true)
                return "Suspicious Port";
            if (packet.ThreatDescription?.Contains("ICMP") == true)
                return "ICMP Anomaly";
            if (packet.ThreatDescription?.Contains("DNS") == true)
                return "DNS Anomaly";
            return "General";
        }

        #endregion

        #region Filtering

        public void ApplyFilter()
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                FilteredPackets.Clear();

                foreach (var packet in CapturedPackets)
                {
                    if (CurrentFilter.ShouldDisplayPacket(packet))
                    {
                        FilteredPackets.Add(packet);
                    }
                }
            });

            CaptureStatus = $"Filter applied. Showing {FilteredPackets.Count} of {CapturedPackets.Count} packets.";
        }

        public void ClearFilter()
        {
            CurrentFilter.ResetFilter();
            ApplyFilter();
            CaptureStatus = $"Filter cleared. Showing all {CapturedPackets.Count} packets.";
        }

        public void FilterByConversation(string conversationId)
        {
            CurrentFilter.ConversationFilter = conversationId;
            ApplyFilter();
        }

        #endregion

        #region Stream Reconstruction

        public string ReconstructTcpStream(string conversationId)
        {
            if (!_conversationLookup.TryGetValue(conversationId, out var conversation))
                return null;

            var sb = new StringBuilder();

            foreach (var packet in conversation.Packets.OrderBy(p => p.Timestamp))
            {
                if (packet.HttpData != null)
                {
                    sb.AppendLine($"=== Packet #{packet.PacketNumber} ({packet.FormattedTimestamp}) ===");

                    if (packet.HttpData.IsRequest)
                    {
                        sb.AppendLine($"{packet.HttpData.Method} {packet.HttpData.Uri} HTTP/{packet.HttpData.HttpVersion}");
                        foreach (var header in packet.HttpData.Headers)
                        {
                            sb.AppendLine($"{header.Key}: {header.Value}");
                        }
                    }
                    else
                    {
                        sb.AppendLine($"HTTP/{packet.HttpData.HttpVersion} {packet.HttpData.StatusCode} {packet.HttpData.StatusText}");
                        foreach (var header in packet.HttpData.Headers)
                        {
                            sb.AppendLine($"{header.Key}: {header.Value}");
                        }
                    }

                    sb.AppendLine();
                }
            }

            return sb.ToString();
        }

        public byte[] GetStreamPayload(string conversationId, bool clientToServer = true)
        {
            if (!_conversationLookup.TryGetValue(conversationId, out var conversation))
                return null;

            var payloads = new List<byte>();

            foreach (var packet in conversation.Packets.OrderBy(p => p.Timestamp))
            {
                bool isClientToServer = packet.SourceEndpoint == conversation.EndpointA;

                if ((clientToServer && isClientToServer) || (!clientToServer && !isClientToServer))
                {
                    // Get payload from raw packet (simplified - would need proper reassembly)
                    if (packet.RawPacket != null && packet.PayloadLength > 0)
                    {
                        // This would need proper TCP reassembly for production use
                        // For now, just concatenate payloads
                    }
                }
            }

            return payloads.ToArray();
        }

        #endregion

        #region Export

        public async Task ExportToPcapAsync(string filePath)
        {
            await Task.Run(() =>
            {
                try
                {
                    using var writer = new CaptureFileWriterDevice(filePath);
                    writer.Open();

                    foreach (var packet in CapturedPackets)
                    {
                        if (packet.RawPacket != null)
                        {
                            // Write packet to file
                            var rawPacket = new RawCapture(
                                PacketDotNet.LinkLayers.Ethernet,
                                new PosixTimeval(packet.Timestamp),
                                packet.RawPacket);
                            writer.Write(rawPacket);
                        }
                    }

                    writer.Close();
                    CaptureStatus = $"Exported {CapturedPackets.Count} packets to {filePath}";
                }
                catch (Exception ex)
                {
                    CaptureStatus = $"Export failed: {ex.Message}";
                }
            });
        }

        public async Task ExportToCsvAsync(string filePath)
        {
            await Task.Run(() =>
            {
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("No,Time,Source,Destination,Protocol,Length,Info");

                    foreach (var packet in CapturedPackets)
                    {
                        sb.AppendLine($"{packet.PacketNumber}," +
                            $"\"{packet.FormattedTimestamp}\"," +
                            $"\"{packet.SourceEndpoint}\"," +
                            $"\"{packet.DestinationEndpoint}\"," +
                            $"\"{packet.Protocol}\"," +
                            $"{packet.Length}," +
                            $"\"{packet.Info?.Replace("\"", "\"\"")}\"");
                    }

                    File.WriteAllText(filePath, sb.ToString());
                    CaptureStatus = $"Exported {CapturedPackets.Count} packets to CSV";
                }
                catch (Exception ex)
                {
                    CaptureStatus = $"CSV export failed: {ex.Message}";
                }
            });
        }

        public async Task ExportToJsonAsync(string filePath)
        {
            await Task.Run(() =>
            {
                try
                {
                    var exportData = CapturedPackets.Select(p => new
                    {
                        p.PacketNumber,
                        Timestamp = p.FormattedTimestamp,
                        p.SourceIP,
                        p.SourcePort,
                        p.DestinationIP,
                        p.DestinationPort,
                        p.Protocol,
                        ApplicationProtocol = p.AppProtocol.ToString(),
                        p.Length,
                        p.Info,
                        ThreatLevel = p.ThreatLevel.ToString(),
                        p.ThreatDescription,
                        p.ConversationId
                    });

                    var json = System.Text.Json.JsonSerializer.Serialize(exportData,
                        new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

                    File.WriteAllText(filePath, json);
                    CaptureStatus = $"Exported {CapturedPackets.Count} packets to JSON";
                }
                catch (Exception ex)
                {
                    CaptureStatus = $"JSON export failed: {ex.Message}";
                }
            });
        }

        #endregion

        #region Import

        public async Task ImportFromPcapAsync(string filePath)
        {
            await Task.Run(() =>
            {
                try
                {
                    ClearCapture();
                    _captureStartTime = DateTime.Now;

                    using var reader = new CaptureFileReaderDevice(filePath);
                    reader.Open();

                    // Use the new SharpPcap API with out parameter
                    PacketCapture packetCapture;
                    GetPacketStatus status;
                    while ((status = reader.GetNextPacket(out packetCapture)) == GetPacketStatus.PacketRead)
                    {
                        var rawCapture = packetCapture.GetPacket();
                        if (rawCapture != null)
                        {
                            ProcessRawPacket(rawCapture);
                        }
                    }

                    reader.Close();

                    Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        CaptureStatus = $"Imported {CapturedPackets.Count} packets from {filePath}";
                    });
                }
                catch (Exception ex)
                {
                    Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        CaptureStatus = $"Import failed: {ex.Message}";
                    });
                }
            });
        }

        #endregion

        #region Utility Methods

        public EnhancedPacketInfo GetPacketByNumber(int packetNumber)
        {
            return CapturedPackets.FirstOrDefault(p => p.PacketNumber == packetNumber);
        }

        public IEnumerable<EnhancedPacketInfo> GetPacketsByIP(string ip)
        {
            return CapturedPackets.Where(p =>
                p.SourceIP == ip || p.DestinationIP == ip);
        }

        public IEnumerable<EnhancedPacketInfo> GetPacketsByPort(int port)
        {
            return CapturedPackets.Where(p =>
                p.SourcePort == port || p.DestinationPort == port);
        }

        public IEnumerable<EnhancedPacketInfo> GetPacketsByProtocol(string protocol)
        {
            return CapturedPackets.Where(p =>
                p.Protocol?.Equals(protocol, StringComparison.OrdinalIgnoreCase) == true);
        }

        public IEnumerable<EnhancedPacketInfo> GetPacketsByConversation(string conversationId)
        {
            return CapturedPackets.Where(p => p.ConversationId == conversationId);
        }

        public IEnumerable<EnhancedPacketInfo> GetPacketsByTimeRange(DateTime start, DateTime end)
        {
            return CapturedPackets.Where(p =>
                p.Timestamp >= start && p.Timestamp <= end);
        }

        public string GeneratePacketDetails(EnhancedPacketInfo packet)
        {
            if (packet == null) return "No packet selected";

            var sb = new StringBuilder();

            sb.AppendLine($"=== Packet #{packet.PacketNumber} ===");
            sb.AppendLine();
            sb.AppendLine($"Timestamp: {packet.FormattedTimestamp}");
            sb.AppendLine($"Relative Time: {packet.FormattedRelativeTime}s");
            sb.AppendLine($"Length: {packet.Length} bytes");
            sb.AppendLine();

            foreach (var layer in packet.Layers)
            {
                sb.AppendLine($"--- {layer.Name} ---");
                foreach (var field in layer.DisplayFields)
                {
                    var marker = field.IsImportant ? "* " : "  ";
                    sb.AppendLine($"{marker}{field.Name}: {field.Value}");
                }
                sb.AppendLine();
            }

            if (packet.ThreatLevel > ThreatLevel.None)
            {
                sb.AppendLine("--- Threat Information ---");
                sb.AppendLine($"Threat Level: {packet.ThreatLevel}");
                sb.AppendLine($"Description: {packet.ThreatDescription}");
                sb.AppendLine();
            }

            if (packet.RawPacket != null && packet.RawPacket.Length > 0)
            {
                sb.AppendLine("--- Hex Dump ---");
                sb.AppendLine(GenerateHexDump(packet.RawPacket));
            }

            return sb.ToString();
        }

        public string GenerateHexDump(byte[] data, int bytesPerLine = 16)
        {
            if (data == null || data.Length == 0)
                return string.Empty;

            var sb = new StringBuilder();

            for (int i = 0; i < data.Length; i += bytesPerLine)
            {
                // Offset
                sb.Append($"{i:X8}  ");

                // Hex bytes
                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (i + j < data.Length)
                    {
                        sb.Append($"{data[i + j]:X2} ");
                    }
                    else
                    {
                        sb.Append("   ");
                    }

                    if (j == 7) sb.Append(" ");
                }

                sb.Append(" ");

                // ASCII
                for (int j = 0; j < bytesPerLine && i + j < data.Length; j++)
                {
                    byte b = data[i + j];
                    char c = (b >= 32 && b < 127) ? (char)b : '.';
                    sb.Append(c);
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }

        #endregion

        #region INotifyPropertyChanged

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion

        #region IDisposable

        private bool _disposed;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                StopCapture();
                _statsUpdateTimer?.Dispose();
                _cancellationTokenSource?.Dispose();
            }

            _disposed = true;
        }

        ~TrafficCaptureService()
        {
            Dispose(false);
        }

        #endregion
    }
}
