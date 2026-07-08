using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Advanced Stealth Network Reconnaissance Service
    /// Uses fragmentation, multiple probe types, and timing analysis for accurate parent detection
    /// </summary>
    public class AdvancedStealthReconService
    {
        private Random _random = new Random();
        private const int MIN_DELAY_MS = 50;
        private const int MAX_DELAY_MS = 200;

        public event Action<string> OnProgressUpdate;

        public class DeviceProbeResult
        {
            public string IPAddress { get; set; }
            public int TTL { get; set; }
            public long ResponseTime { get; set; }  // in milliseconds
            public int HopCount { get; set; }
            public List<string> IntermediateHops { get; set; } = new List<string>();
            public bool IsAlive { get; set; }
            public string DetectionMethod { get; set; }
        }

        /// <summary>
        /// Perform advanced stealth probe on a device using multiple techniques
        /// </summary>
        public async Task<DeviceProbeResult> StealthProbeDeviceAsync(string targetIP)
        {
            var result = new DeviceProbeResult
            {
                IPAddress = targetIP,
                IsAlive = false
            };

            try
            {
                // Method 1: Fragmented ICMP Ping (Stealth)
                var fragmentedResult = await FragmentedPingAsync(targetIP);
                if (fragmentedResult != null)
                {
                    result = fragmentedResult;
                    result.DetectionMethod = "Fragmented ICMP";
                    result.IsAlive = true;

                    // Add random delay for stealth
                    await Task.Delay(_random.Next(MIN_DELAY_MS, MAX_DELAY_MS));
                }

                // Method 2: Multi-TTL Probing (Path Discovery)
                if (result.IsAlive)
                {
                    var traceroute = await StealthTracerouteAsync(targetIP);
                    if (traceroute.Any())
                    {
                        result.IntermediateHops = traceroute;
                        result.HopCount = traceroute.Count;
                    }
                }

                // Method 3: TCP Timestamp Analysis (if ICMP failed)
                if (!result.IsAlive)
                {
                    var tcpResult = await TCPTimestampProbeAsync(targetIP);
                    if (tcpResult != null)
                    {
                        result = tcpResult;
                        result.DetectionMethod = "TCP Timestamp";
                        result.IsAlive = true;
                    }
                }

                // Method 4: Timing-based hop estimation
                if (result.IsAlive && result.HopCount == 0)
                {
                    result.HopCount = EstimateHopsFromTiming(result.ResponseTime);
                }

            }
            catch (Exception ex)
            {
                Debug.WriteLine($"⚠️ Stealth probe failed for {targetIP}: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Fragmented ICMP ping - splits packet into fragments for stealth
        /// </summary>
        private async Task<DeviceProbeResult> FragmentedPingAsync(string targetIP)
        {
            try
            {
                using (var ping = new Ping())
                {
                    // Create fragmented payload (1500+ bytes forces fragmentation)
                    var fragmentedBuffer = new byte[1500];
                    _random.NextBytes(fragmentedBuffer);  // Random data for stealth

                    var options = new PingOptions
                    {
                        DontFragment = false,  // Allow fragmentation
                        Ttl = 128
                    };

                    var stopwatch = Stopwatch.StartNew();
                    var reply = await ping.SendPingAsync(targetIP, 1000, fragmentedBuffer, options);
                    stopwatch.Stop();

                    if (reply.Status == IPStatus.Success)
                    {
                        return new DeviceProbeResult
                        {
                            IPAddress = targetIP,
                            TTL = reply.Options?.Ttl ?? 0,
                            ResponseTime = stopwatch.ElapsedMilliseconds,
                            IsAlive = true,
                            HopCount = CalculateHopCount(reply.Options?.Ttl ?? 0)
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Fragmented ping failed for {targetIP}: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Stealth traceroute using incremental TTL probes
        /// </summary>
        private async Task<List<string>> StealthTracerouteAsync(string targetIP)
        {
            var hops = new List<string>();

            try
            {
                using (var ping = new Ping())
                {
                    // Probe with incrementing TTL to discover path
                    for (int ttl = 1; ttl <= 10; ttl++)  // Max 10 hops
                    {
                        var buffer = new byte[32];
                        _random.NextBytes(buffer);  // Random payload for stealth

                        var options = new PingOptions(ttl, true);

                        var reply = await ping.SendPingAsync(targetIP, 500, buffer, options);

                        if (reply.Status == IPStatus.Success)
                        {
                            // Reached destination
                            hops.Add(reply.Address.ToString());
                            break;
                        }
                        else if (reply.Status == IPStatus.TtlExpired)
                        {
                            // Found intermediate hop
                            if (reply.Address != null)
                            {
                                hops.Add(reply.Address.ToString());
                            }
                        }
                        else if (reply.Status == IPStatus.TimedOut)
                        {
                            // Router not responding, add placeholder
                            hops.Add($"*hop{ttl}*");
                        }

                        // Stealth delay between probes
                        await Task.Delay(_random.Next(MIN_DELAY_MS, MAX_DELAY_MS));
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Stealth traceroute failed for {targetIP}: {ex.Message}");
            }

            return hops;
        }

        /// <summary>
        /// TCP SYN probe with timestamp analysis - very stealthy
        /// </summary>
        private async Task<DeviceProbeResult> TCPTimestampProbeAsync(string targetIP)
        {
            try
            {
                // Try common ports in random order for stealth
                var ports = new[] { 80, 443, 22, 445, 139, 3389 };
                var randomPorts = ports.OrderBy(x => _random.Next()).ToArray();

                foreach (var port in randomPorts)
                {
                    try
                    {
                        var stopwatch = Stopwatch.StartNew();
                        using (var client = new TcpClient())
                        {
                            client.ReceiveTimeout = 500;
                            client.SendTimeout = 500;

                            var connectTask = client.ConnectAsync(targetIP, port);
                            var completedInTime = await Task.WhenAny(connectTask, Task.Delay(500)) == connectTask;

                            stopwatch.Stop();

                            if (completedInTime && client.Connected)
                            {
                                return new DeviceProbeResult
                                {
                                    IPAddress = targetIP,
                                    ResponseTime = stopwatch.ElapsedMilliseconds,
                                    IsAlive = true
                                };
                            }
                        }
                    }
                    catch
                    {
                        // Port closed/filtered, try next
                    }

                    // Stealth delay between port probes
                    await Task.Delay(_random.Next(MIN_DELAY_MS, MAX_DELAY_MS));
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"TCP timestamp probe failed for {targetIP}: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Estimate hop count based on response timing
        /// Higher latency generally means more hops
        /// </summary>
        private int EstimateHopsFromTiming(long responseTimeMs)
        {
            if (responseTimeMs < 5)
                return 0;  // Direct connection (same network)
            else if (responseTimeMs < 15)
                return 1;  // One hop (through AP/router)
            else if (responseTimeMs < 30)
                return 2;  // Two hops
            else if (responseTimeMs < 50)
                return 3;  // Three hops
            else
                return 4;  // Multiple hops
        }

        /// <summary>
        /// Calculate actual hop count from TTL value
        /// </summary>
        private int CalculateHopCount(int ttl)
        {
            if (ttl >= 128)
                return 128 - ttl;
            else if (ttl >= 64)
                return 64 - ttl;
            else if (ttl >= 32)
                return 64 - ttl;
            else
                return -1;
        }

        /// <summary>
        /// Determine parent device with advanced analysis
        /// </summary>
        public TopologyNetworkDevice DetermineParentAdvanced(
            string deviceIP,
            DeviceProbeResult probeResult,
            TopologyNetworkDevice gateway,
            List<TopologyNetworkDevice> infrastructure,
            List<TopologyNetworkDevice> allDevices)
        {
            Debug.WriteLine($"🔬 Advanced parent detection for {deviceIP}:");
            Debug.WriteLine($"   TTL: {probeResult.TTL}, Hops: {probeResult.HopCount}, Time: {probeResult.ResponseTime}ms");

            // Method 1: Use traceroute hops to find direct parent
            if (probeResult.IntermediateHops.Any())
            {
                // Last hop before destination is the parent
                var lastHop = probeResult.IntermediateHops.LastOrDefault(h => !h.StartsWith("*"));
                if (lastHop != null)
                {
                    var parent = infrastructure.FirstOrDefault(i => i.IPAddress == lastHop);
                    if (parent != null)
                    {
                        Debug.WriteLine($"   ✅ Traceroute parent: {parent.IPAddress}");
                        return parent;
                    }
                }
            }

            // Method 2: Hop count analysis
            if (probeResult.HopCount == 0)
            {
                // Direct to gateway
                Debug.WriteLine($"   ✅ Direct connection to gateway");
                return gateway;
            }
            else if (probeResult.HopCount == 1 && infrastructure.Any())
            {
                // One hop - find which infrastructure device
                // Use IP proximity to determine which AP/router
                var closest = infrastructure
                    .Select(i => new
                    {
                        Device = i,
                        Proximity = CalculateIPProximity(deviceIP, i.IPAddress)
                    })
                    .OrderByDescending(x => x.Proximity)
                    .FirstOrDefault();

                if (closest != null && closest.Proximity > 0.5)
                {
                    Debug.WriteLine($"   ✅ 1-hop via closest: {closest.Device.IPAddress}");
                    return closest.Device;
                }
            }

            // Method 3: Timing-based analysis
            // Devices with similar response times are likely behind same router
            var timingMatch = infrastructure
                .Select(i => new
                {
                    Device = i,
                    TimingDiff = Math.Abs(i.ResponseTime - probeResult.ResponseTime)
                })
                .OrderBy(x => x.TimingDiff)
                .FirstOrDefault();

            if (timingMatch != null && timingMatch.TimingDiff < 10)
            {
                Debug.WriteLine($"   ✅ Timing match: {timingMatch.Device.IPAddress}");
                return timingMatch.Device;
            }

            // Fallback to gateway
            Debug.WriteLine($"   ⚠️ Using gateway fallback");
            return gateway;
        }

        private double CalculateIPProximity(string ip1, string ip2)
        {
            if (string.IsNullOrEmpty(ip1) || string.IsNullOrEmpty(ip2))
                return 0;

            try
            {
                var parts1 = ip1.Split('.').Select(int.Parse).ToArray();
                var parts2 = ip2.Split('.').Select(int.Parse).ToArray();

                if (parts1.Length != 4 || parts2.Length != 4)
                    return 0;

                // Same /24 subnet
                if (parts1[0] == parts2[0] && parts1[1] == parts2[1] && parts1[2] == parts2[2])
                {
                    // Very close IPs (within 10)
                    if (Math.Abs(parts1[3] - parts2[3]) <= 10)
                        return 1.0;

                    return 0.6;
                }

                return 0;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Perform passive monitoring to detect MAC->IP relationships by capturing ARP replies.
        /// Returns a dictionary of MAC address (string) -> IP address (string).
        /// </summary>
        public async Task<Dictionary<string, string>> PassiveARPMonitoringAsync(TimeSpan duration)
        {
            var relationships = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            OnProgressUpdate?.Invoke("Starting passive ARP monitoring...");

            // Seed with current OS ARP cache for immediate results
            SeedFromArpCache(relationships);

            // Live capture using SharpPcap (captures actual ARP replies on the wire)
            ILiveDevice? device = null;
            try
            {
                var devices = CaptureDeviceList.Instance;
                if (devices.Count > 0)
                {
                    // Pick the first up-and-running non-loopback device
                    device = devices.FirstOrDefault(d =>
                        d is LibPcapLiveDevice live &&
                        live.Interface?.Addresses?.Any(a =>
                            a.Addr?.ipAddress?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) == true)
                        ?? devices[0];

                    device.Open(DeviceModes.Promiscuous, 100);
                    device.Filter = "arp";

                    device.OnPacketArrival += (_, e) =>
                    {
                        try
                        {
                            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
                            var arp = packet.Extract<ArpPacket>();
                            if (arp == null) return;

                            // Only process ARP replies (opcode 2)
                            if (arp.Operation != ArpOperation.Response) return;

                            string mac = arp.SenderHardwareAddress != null
                                ? string.Join(":", arp.SenderHardwareAddress.GetAddressBytes().Select(b => b.ToString("X2")))
                                : null;
                            string ip = arp.SenderProtocolAddress?.ToString();

                            if (!string.IsNullOrEmpty(mac) && !string.IsNullOrEmpty(ip))
                            {
                                lock (relationships)
                                    relationships[mac] = ip;
                            }
                        }
                        catch { /* ignore malformed packets */ }
                    };

                    device.StartCapture();
                    OnProgressUpdate?.Invoke($"Capturing ARP on {device.Description ?? device.Name} for {duration.TotalSeconds:F0}s...");
                }
                else
                {
                    OnProgressUpdate?.Invoke("No capture devices found — using ARP cache only.");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ARP capture setup failed: {ex.Message}");
                OnProgressUpdate?.Invoke("Live capture unavailable (run as Administrator). Using ARP cache.");
            }

            await Task.Delay(duration);

            try { device?.StopCapture(); device?.Close(); } catch { }

            OnProgressUpdate?.Invoke($"ARP monitoring complete — {relationships.Count} MAC/IP pairs found.");
            return relationships;
        }

        private static void SeedFromArpCache(Dictionary<string, string> map)
        {
            try
            {
                var psi = new ProcessStartInfo("arp", "-a")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                string output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(3000);

                // Parse lines like:  192.168.1.1   00-11-22-33-44-55   dynamic
                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;
                    string ip = parts[0].Trim();
                    string mac = parts[1].Replace('-', ':').Trim().ToUpperInvariant();
                    if (mac.Length == 17 && IPAddress.TryParse(ip, out _))
                        map[mac] = ip;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ARP cache seed failed: {ex.Message}");
            }
        }
    }
}