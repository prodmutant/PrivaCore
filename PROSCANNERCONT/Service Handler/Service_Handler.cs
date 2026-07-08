using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.ServiceDetection;
using PROSCANNERCONT.ServiceDetection.Detectors;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Service_Handler
{
    // â”€â”€ Event argument classes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    public class ScanResultEventArgs : EventArgs
    {
        public int HostsScanned { get; set; }
        public int SecurityScore { get; set; }
        public string RiskLevel { get; set; } = string.Empty;
        public DateTime CompletionTime { get; set; }
        public List<DeviceInfo> FoundDevices { get; set; } = new List<DeviceInfo>();
        public Dictionary<string, string> SecurityDetails { get; set; } = new Dictionary<string, string>();
    }

    public class SpeedTestResultEventArgs : EventArgs
    {
        public double DownloadSpeed { get; set; }
        public double UploadSpeed { get; set; }
        public int Latency { get; set; }
        public DateTime CompletionTime { get; set; }
    }

    public class NetworkDiscoveryScanResultEventArgs : EventArgs
    {
        public DateTime CompletionTime { get; set; }
        public List<DeviceInfo> DiscoveredDevices { get; set; } = new List<DeviceInfo>();
    }

    public class PortScanResultEventArgs : EventArgs
    {
        public string TargetIP { get; set; } = string.Empty;
        public List<PortResult> PortResults { get; set; } = new List<PortResult>();
        public int StartPort { get; set; }
        public int EndPort { get; set; }
        public DateTime CompletionTime { get; set; }
        public int TotalScanned { get; set; }
        public int OpenPorts { get; set; }
    }

    public class PortFoundEventArgs : EventArgs
    {
        public string TargetIP { get; set; } = string.Empty;
        public PortResult PortResult { get; set; } = new PortResult();
        public int ProgressPercentage { get; set; }
    }

    public class DeviceInfo
    {
        public string IPAddress { get; set; } = string.Empty;
        public string DeviceName { get; set; } = string.Empty;
        public string DeviceType { get; set; } = string.Empty;
        public List<int> OpenPorts { get; set; } = new List<int>();
    }

    public class PortResult
    {
        public int Port { get; set; }
        public bool IsOpen { get; set; }
        public string ServiceName { get; set; } = string.Empty;
        public string ServiceVersion { get; set; } = string.Empty;
        public string Vulnerability { get; set; } = string.Empty;
    }

    // â”€â”€ Service_Handler facade â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// <summary>
    /// Thin orchestration facade for dashboard-level scans (quick scan, security check,
    /// speed test, network discovery, port scan).  All inline detector classes have been
    /// moved to <c>ServiceDetection/Detectors/</c>.
    /// </summary>
    public partial class Service_Handler
    {
        private static Service_Handler? _instance;
        private static readonly object _lock = new object();

        // â”€â”€ Events â”€â”€
        public delegate void ScanCompletedEventHandler(object sender, ScanResultEventArgs e);
        public delegate void SpeedTestCompletedEventHandler(object sender, SpeedTestResultEventArgs e);
        public delegate void NetworkDiscoveryScanCompletedEventHandler(object sender, NetworkDiscoveryScanResultEventArgs e);
        public delegate void PortScanCompletedEventHandler(object sender, PortScanResultEventArgs e);
        public delegate void PortFoundEventHandler(object sender, PortFoundEventArgs e);

        public event ScanCompletedEventHandler? QuickScanCompleted;
        public event ScanCompletedEventHandler? SecurityCheckCompleted;
        public event SpeedTestCompletedEventHandler? SpeedTestCompleted;
        public event NetworkDiscoveryScanCompletedEventHandler? NetworkDiscoveryScanCompleted;
        public event PortScanCompletedEventHandler? PortScanCompleted;
        public event PortFoundEventHandler? PortFound;

        private CancellationTokenSource _cancellationSource = new CancellationTokenSource();
        private bool _isPortScanRunning;

        private Service_Handler() { }

        public static Service_Handler Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        _instance ??= new Service_Handler();
                    }
                }
                return _instance;
            }
        }

        // â”€â”€ Dashboard Page Services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        public async Task StartQuickScanAsync()
        {
            try
            {
                await Task.Run(async () =>
                {
                    await Task.Delay(AppConstants.Scanning.DefaultConnectionTimeoutMs, _cancellationSource.Token);

                    var results = new ScanResultEventArgs
                    {
                        HostsScanned = 6,
                        SecurityScore = 75,
                        CompletionTime = DateTime.Now,
                        FoundDevices = new List<DeviceInfo>
                        {
                            new DeviceInfo { IPAddress = "192.168.0.106", DeviceName = "HUAWEI_P30_lite-8b05000c3", DeviceType = "Android Device" },
                            new DeviceInfo { IPAddress = "192.168.0.181", DeviceName = "HUAWEI_P30_lite-f16e8c17d", DeviceType = "Android Device" }
                        }
                    };

                    OnQuickScanCompleted(results);
                }, _cancellationSource.Token);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("[Service_Handler.StartQuickScanAsync] Quick scan cancelled.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Service_Handler.StartQuickScanAsync] {ex.Message}");
                throw;
            }
        }

        public async Task StartSecurityCheckAsync()
        {
            try
            {
                await Task.Run(async () =>
                {
                    await Task.Delay(3000, _cancellationSource.Token);

                    var results = new ScanResultEventArgs
                    {
                        SecurityScore = 40,
                        RiskLevel = "High Risk",
                        CompletionTime = DateTime.Now,
                        SecurityDetails = new Dictionary<string, string>
                        {
                            { "OpenPorts", "22, 80, 443" },
                            { "VulnerableServices", "SMB, FTP" },
                            { "UnsecuredDevices", "2" }
                        }
                    };

                    OnSecurityCheckCompleted(results);
                }, _cancellationSource.Token);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("[Service_Handler.StartSecurityCheckAsync] Security check cancelled.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Service_Handler.StartSecurityCheckAsync] {ex.Message}");
                throw;
            }
        }

        public async Task StartSpeedTestAsync()
        {
            try
            {
                await Task.Run(async () =>
                {
                    await Task.Delay(5000, _cancellationSource.Token);

                    var results = new SpeedTestResultEventArgs
                    {
                        DownloadSpeed = 256.2,
                        UploadSpeed = 124.5,
                        Latency = 15,
                        CompletionTime = DateTime.Now
                    };

                    OnSpeedTestCompleted(results);
                }, _cancellationSource.Token);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("[Service_Handler.StartSpeedTestAsync] Speed test cancelled.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Service_Handler.StartSpeedTestAsync] {ex.Message}");
                throw;
            }
        }

        public void CancelOperation()
        {
            _cancellationSource.Cancel();
            _cancellationSource = new CancellationTokenSource();
        }

        // â”€â”€ Network Discovery Services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        public async Task StartNetworkDiscoveryScanAsync()
        {
            try
            {
                await Task.Run(async () =>
                {
                    await Task.Delay(4000, _cancellationSource.Token);

                    var results = new NetworkDiscoveryScanResultEventArgs
                    {
                        CompletionTime = DateTime.Now,
                        DiscoveredDevices = new List<DeviceInfo>
                        {
                            new DeviceInfo { IPAddress = "192.168.0.1",   DeviceName = "Router-ASUS-RT-AX88U", DeviceType = "Router",     OpenPorts = new List<int> { 80, 443, 8080 } },
                            new DeviceInfo { IPAddress = "192.168.0.100", DeviceName = "DESKTOP-XYZ123",       DeviceType = "Windows PC", OpenPorts = new List<int> { 135, 139, 445 } },
                            new DeviceInfo { IPAddress = "192.168.0.105", DeviceName = "iPhone-John",          DeviceType = "iOS Device", OpenPorts = new List<int> { 62078 } },
                            new DeviceInfo { IPAddress = "192.168.0.110", DeviceName = "SmartTV-Samsung",      DeviceType = "Smart TV",   OpenPorts = new List<int> { 8001, 8002 } }
                        }
                    };

                    OnNetworkDiscoveryScanCompleted(results);
                }, _cancellationSource.Token);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("[Service_Handler.StartNetworkDiscoveryScanAsync] Network discovery cancelled.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Service_Handler.StartNetworkDiscoveryScanAsync] {ex.Message}");
                throw;
            }
        }

        public void StopNetworkDiscoveryScan() => CancelOperation();

        // â”€â”€ Port Scanner Services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        public async Task StartPortScanAsync(string targetIp, int startPort, int endPort)
        {
            if (!ValidationUtils.IsValidIpAddress(targetIp))
                throw new ArgumentException($"Invalid IP address: {targetIp}", nameof(targetIp));
            if (!ValidationUtils.IsValidPortRange(startPort, endPort))
                throw new ArgumentException($"Invalid port range: {startPort}-{endPort}");

            if (_isPortScanRunning)
                throw new InvalidOperationException("A port scan is already running.");

            _isPortScanRunning = true;
            try
            {
                await Task.Run(async () =>
                {
                    var portResults = new List<PortResult>();
                    int totalPorts = endPort - startPort + 1;
                    int scannedPorts = 0;

                    for (int port = startPort; port <= endPort; port++)
                    {
                        if (_cancellationSource.Token.IsCancellationRequested) break;

                        bool isOpen = await IsPortOpenAsync(targetIp, port, _cancellationSource.Token);
                        scannedPorts++;

                        if (isOpen)
                        {
                            string serviceName = KnownServices.GetServiceName(port);
                            string serviceVersion = await DetectServiceVersionAsync(targetIp, port, serviceName, _cancellationSource.Token);

                            var portResult = new PortResult
                            {
                                Port = port,
                                IsOpen = true,
                                ServiceName = serviceName,
                                ServiceVersion = serviceVersion,
                                Vulnerability = AssessVulnerability(serviceName, serviceVersion)
                            };

                            portResults.Add(portResult);

                            OnPortFound(new PortFoundEventArgs
                            {
                                TargetIP = targetIp,
                                PortResult = portResult,
                                ProgressPercentage = (int)((double)scannedPorts / totalPorts * 100)
                            });
                        }
                    }

                    OnPortScanCompleted(new PortScanResultEventArgs
                    {
                        TargetIP = targetIp,
                        PortResults = portResults,
                        StartPort = startPort,
                        EndPort = endPort,
                        CompletionTime = DateTime.Now,
                        TotalScanned = scannedPorts,
                        OpenPorts = portResults.Count
                    });

                }, _cancellationSource.Token);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("[Service_Handler.StartPortScanAsync] Port scan cancelled.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Service_Handler.StartPortScanAsync] {ex.Message}");
                throw;
            }
            finally
            {
                _isPortScanRunning = false;
            }
        }

        public void StopPortScan()
        {
            if (_isPortScanRunning)
            {
                CancelOperation();
                _isPortScanRunning = false;
            }
        }

        public void ClearPortScanResults() { /* reserved for future cache clearing */ }

        // â”€â”€ Private helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private static async Task<bool> IsPortOpenAsync(string ipAddress, int port, CancellationToken ct)
        {
            try
            {
                using var client = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(AppConstants.Scanning.DefaultConnectionTimeoutMs);

                await client.ConnectAsync(ipAddress, port).WaitAsync(cts.Token);
                return client.Connected;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Service_Handler.IsPortOpenAsync] port={port}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Delegates to the appropriate protocol detector in ServiceDetection/Detectors/.
        /// Uses <see cref="KnownServices"/> instead of a local switch statement.
        /// </summary>
        private static async Task<string> DetectServiceVersionAsync(
            string ipAddress, int port, string serviceName, CancellationToken ct)
        {
            try
            {
                return serviceName switch
                {
                    "FTP"        => await FtpDetector.DetectVersionAsync(ipAddress, port, ct),
                    "SSH"        => await SshDetector.DetectVersionAsync(ipAddress, port, ct),
                    "HTTP"       => await HttpDetector.DetectVersionAsync(ipAddress, port, ct),
                    "HTTP-Alt"   => await HttpDetector.DetectVersionAsync(ipAddress, port, ct),
                    "HTTPS"      => await HttpDetector.DetectVersionAsync(ipAddress, port, ct),
                    "HTTPS-Alt"  => await HttpDetector.DetectVersionAsync(ipAddress, port, ct),
                    "SMTP"       => await SmtpDetector.DetectVersionAsync(ipAddress, port, ct),
                    "MySQL"      => await MySqlDetector.DetectVersionAsync(ipAddress, port, ct),
                    "NetBIOS-SSN"=> await NetBIOSDetector.DetectVersionAsync(ipAddress, port, ct),
                    _            => "Unknown"
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Service_Handler.DetectServiceVersionAsync] {ex.Message}");
                return "Detection Failed";
            }
        }

        private static string AssessVulnerability(string serviceName, string serviceVersion)
        {
            if (serviceName == "FTP" && serviceVersion.Contains("vsftpd 2.3.4"))
                return "High (Backdoor vulnerability)";
            if (serviceName == "SMB" && serviceVersion.Contains("1.0"))
                return "High (EternalBlue vulnerability)";
            if (serviceName == "Telnet")
                return "Medium (Unencrypted protocol)";
            return "Low";
        }

        // â”€â”€ Event invokers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        protected virtual void OnQuickScanCompleted(ScanResultEventArgs e) =>
            QuickScanCompleted?.Invoke(this, e);

        protected virtual void OnSecurityCheckCompleted(ScanResultEventArgs e) =>
            SecurityCheckCompleted?.Invoke(this, e);

        protected virtual void OnSpeedTestCompleted(SpeedTestResultEventArgs e) =>
            SpeedTestCompleted?.Invoke(this, e);

        protected virtual void OnNetworkDiscoveryScanCompleted(NetworkDiscoveryScanResultEventArgs e) =>
            NetworkDiscoveryScanCompleted?.Invoke(this, e);

        protected virtual void OnPortScanCompleted(PortScanResultEventArgs e) =>
            PortScanCompleted?.Invoke(this, e);

        protected virtual void OnPortFound(PortFoundEventArgs e) =>
            PortFound?.Invoke(this, e);
    }
}
