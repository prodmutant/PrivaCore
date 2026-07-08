using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Linq;

namespace PROSCANNERCONT.Services
{
    public class OSDetector
    {
        private const int PORT_TIMEOUT = 200;

 
        private static readonly HashSet<string> AndroidHostnamePatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "android",
        "samsung",
        "galaxy",
        "pixel",
        "oneplus",
        "redmi",
        "xiaomi",
        "huawei",
        "honor",
        "motorola",
        "nokia",
        "vivo",
        "oppo",
        "poco",
        "realme",
        "-phone",
        "sm-",           // Samsung model prefix
        "asus_",         // Asus phone prefix
        "moto",          // Motorola prefix
        "lg-",           // LG phone prefix
        "mi-",           // Xiaomi prefix
        "redmi-",        // Redmi prefix
        "nord",          // OnePlus Nord series
        "xcover",        // Samsung XCover series
        "a52",           // Samsung A series
        "a72",
        "s20",           // Samsung S series
        "s21",
        "s22",
        "s23",
        "note",          // Samsung Note series
        "fold",          // Foldable phones
        "flip",
        "tablet"         // Generic tablet identifier
    };

        private static readonly HashSet<string> AndroidMacPrefixes = new HashSet<string>
        {
        "12ED78", // Samsung phones including S23 series
        "A07893",
        "B85E7F",
        "C44619",
        "1C626E",
        "94B10A",
        "8C7712",
        "8C71F8",
        "84A466",
        "84252C",
        "78BDBC",
        "78ABBB",
        "74458A",
        "6CF373",
        "6C2F2C",
        "5CE8EB",
        "50A4C8",
        "503275",
        "4C3C16",
        "4844F7",
        "34AA99",
        "24F27F",
        "24DBED",
        "20D390",
        "1CAFF7",
        "14B484",
        "088C2C",
        "0022B0", 
        "94B10A", 
        "380B40", 
        "286C07", 
        "C44619", 
        "C4731E", 
        "E47DBD", 
        "B86CE8", 
        "BC4760", 
        "10683F", 
        "2082C0", 
        "584498", 
        "7C1DD9", 
        "ACF7F3", 
        "98FAE3", 
        "48DB50", 
        "00259E", 
        "785F4C", 
        "D0D04B", 
        "48AD08", 
        "2CAB00", 
        "C0EEFB", 
        "6C5C14", 
        "94652D", 
        "AC58A7", 
        "F0B4D2", 
        "406C8F", 
        "14A364", 
        "B08900", 
        "00E00F", 
        "903AA9"  
        };

        public async Task<string> DetectOS(string ipAddress)
        {
            try
            {
                Debug.WriteLine($"\nStarting OS detection for {ipAddress}");

                // First check Windows (Most common and reliable)
                if (await IsWindows(ipAddress))
                {
                    Debug.WriteLine($"{ipAddress} identified as Windows");
                    return "Windows";
                }

                // Check for network devices
                if (await IsNetworkDevice(ipAddress))
                {
                    Debug.WriteLine($"{ipAddress} identified as Network Device");
                    return "Network Device";
                }

                // Get TCP fingerprint early as we'll need it for both Android and Linux checks
                var tcpFingerprint = await GetTCPFingerprint(ipAddress);
                string macAddress = await GetMacAddress(ipAddress);

                // Enhanced Android detection with priority on TCP fingerprint when hostname is unknown
                bool isAndroid = await IsAndroidDevice(ipAddress, macAddress, tcpFingerprint);
                if (isAndroid)
                {
                    Debug.WriteLine($"{ipAddress} identified as Android Device");
                    return "Android Device";
                }

                // Check for iOS devices
                if (await IsIOSDevice(ipAddress))
                {
                    Debug.WriteLine($"{ipAddress} identified as iOS Device");
                    return "iOS Device";
                }

                // Check for Linux/Unix after excluding Android
                if (await IsLinux(ipAddress, tcpFingerprint))
                {
                    Debug.WriteLine($"{ipAddress} identified as Linux/Unix");
                    return "Linux/Unix";
                }

                // If all else fails, try TTL as last resort
                var ttlOS = await DetectOSByTTL(ipAddress);
                if (ttlOS != "Unknown")
                {
                    Debug.WriteLine($"{ipAddress} identified as {ttlOS} via TTL");
                    return ttlOS;
                }

                Debug.WriteLine($"{ipAddress} could not be identified");
                return "Unknown";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in OS detection for {ipAddress}: {ex.Message}");
                return "Unknown";
            }
        }

        private async Task<bool> IsWindows(string ipAddress)
        {
            try
            {
                // 1. Check SMB port first (most reliable)
                if (await CheckPort(ipAddress, 445))
                {
                    // Verify it's really SMB with protocol check
                    if (await CheckSMBProtocol(ipAddress))
                    {
                        Debug.WriteLine($"{ipAddress}: Windows confirmed via SMB");
                        return true;
                    }
                }

                // 2. Check RDP
                if (await CheckPort(ipAddress, 3389))
                {
                    Debug.WriteLine($"{ipAddress}: Windows likely via RDP");
                    return true;
                }

                // 3. Check NetBIOS
                if (await CheckPort(ipAddress, 139))
                {
                    Debug.WriteLine($"{ipAddress}: Windows likely via NetBIOS");
                    return true;
                }

                // 4. Check hostname patterns
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                    string hostname = hostEntry.HostName.ToLower();

                    if (hostname.Contains("windows") ||
                        hostname.Contains("-pc") ||
                        hostname.Contains("desktop") ||
                        (hostname.Contains("laptop") && !hostname.Contains("android")))
                    {
                        Debug.WriteLine($"{ipAddress}: Windows likely via hostname: {hostname}");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Hostname check failed for {ipAddress}: {ex.Message}");
                }

                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Windows detection error for {ipAddress}: {ex.Message}");
                return false;
            }
        }

        private async Task<bool> IsNetworkDevice(string ipAddress)
        {
            try
            {
                // Count how many router-specific characteristics we find
                int routerScore = 0;

                // 1. Check common router ports
                var routerPorts = new Dictionary<int, int>
                {
                    { 80, 2 },   
                    { 443, 2 }, 
                    { 53, 1 },   
                    { 22, 1 },  
                    { 23, 1 }   
                };

                foreach (var port in routerPorts)
                {
                    if (await CheckPort(ipAddress, port.Key))
                    {
                        routerScore += port.Value;
                        Debug.WriteLine($"{ipAddress}: Router port {port.Key} open");
                    }
                }

           
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                    string hostname = hostEntry.HostName.ToLower();

                    if (hostname.Contains("router") ||
                        hostname.Contains("gateway") ||
                        hostname.Contains("modem") ||
                        hostname.Contains("switch") ||
                        hostname.Contains("ap-") ||
                        hostname.Contains("wap"))
                    {
                        routerScore += 3; 
                        Debug.WriteLine($"{ipAddress}: Router hostname pattern found: {hostname}");
                    }
                }
                catch { }

              
                string lastOctet = ipAddress.Split('.').Last();
                if (lastOctet == "1" || lastOctet == "254")
                {
                    routerScore += 1;
                    Debug.WriteLine($"{ipAddress}: Common router IP pattern");
                }

                Debug.WriteLine($"{ipAddress}: Final router score: {routerScore}");
                return routerScore >= 3;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Network device detection error for {ipAddress}: {ex.Message}");
                return false;
            }
        }
        private async Task<bool> IsAndroidDevice(string ipAddress, string macAddress, OSFingerprint tcpFingerprint)
        {
            try
            {
                Debug.WriteLine($"\nChecking for Android: {ipAddress}");

                // Check hostname first if available
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                    string hostname = hostEntry.HostName.ToLower();
                    Debug.WriteLine($"Checking hostname: {hostname}");

                    // Check against expanded Android hostname patterns
                    if (AndroidHostnamePatterns.Any(pattern => hostname.Contains(pattern)))
                    {
                        Debug.WriteLine($"Android detected via hostname pattern match: {hostname}");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Hostname lookup failed: {ex.Message} - Proceeding with TCP fingerprint analysis");
                }

                // Give more weight to TCP fingerprinting when hostname is unknown or inconclusive
                if (tcpFingerprint != null && IsAndroidFingerprint(tcpFingerprint))
                {
                    Debug.WriteLine("Android detected via TCP fingerprint");
                    return true;
                }

                // Check MAC address prefix if available
                if (!string.IsNullOrEmpty(macAddress))
                {
                    string macPrefix = macAddress.Replace(":", "").Replace("-", "").ToUpper();
                    if (macPrefix.Length >= 6)
                    {
                        macPrefix = macPrefix.Substring(0, 6);
                        if (AndroidMacPrefixes.Contains(macPrefix))
                        {
                            Debug.WriteLine($"Android detected via MAC prefix: {macPrefix}");
                            return true;
                        }
                    }
                }

                // Additional port checks
                if (await CheckPort(ipAddress, 5555))  // Android Debug Bridge
                {
                    Debug.WriteLine("Android detected via ADB port");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Android detection error: {ex.Message}");
                return false;
            }
        }

        private async Task<bool> IsIOSDevice(string ipAddress)
        {
            try
            {
              
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                    string hostname = hostEntry.HostName.ToLower();

                    if (hostname.Contains("iphone") ||
                        hostname.Contains("ipad") ||
                        hostname.Contains("ipod"))
                    {
                        Debug.WriteLine($"{ipAddress}: iOS device detected via hostname");
                        return true;
                    }
                }
                catch { }

              
                if (await CheckPort(ipAddress, 62078) || 
                    await CheckPort(ipAddress, 5009))    
                {
                    Debug.WriteLine($"{ipAddress}: iOS device detected via ports");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"iOS detection error: {ex.Message}");
                return false;
            }
        }
        private async Task<bool> IsLinux(string ipAddress, OSFingerprint tcpFingerprint)
        {
            try
            {
                // First check TCP fingerprint if available
                if (tcpFingerprint != null && IsLinuxFingerprint(tcpFingerprint))
                {
                    Debug.WriteLine($"{ipAddress}: Linux detected via TCP fingerprint");
                    return true;
                }

                if (await CheckPort(ipAddress, 22))
                {
                    // Only consider SSH if we haven't already identified as Android and it's not a network device
                    if (!await IsNetworkDevice(ipAddress))
                    {
                        Debug.WriteLine($"{ipAddress}: Likely Linux via SSH");
                        return true;
                    }
                }

                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                    string hostname = hostEntry.HostName.ToLower();

                    if (hostname.Contains("ubuntu") ||
                        hostname.Contains("debian") ||
                        hostname.Contains("centos") ||
                        hostname.Contains("fedora") ||
                        hostname.Contains("redhat") ||
                        hostname.Contains("linux"))
                    {
                        Debug.WriteLine($"{ipAddress}: Linux confirmed via hostname");
                        return true;
                    }
                }
                catch { }

                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Linux detection error for {ipAddress}: {ex.Message}");
                return false;
            }
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
                    .ElementAtOrDefault(1)
                    ?.Replace("-", "")
                    ?.Replace(":", "");

                return macAddress;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"MAC address lookup failed: {ex.Message}");
                return null;
            }
        }
        private async Task<string> DetectOSByTTL(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, 1000);

                if (reply.Status == IPStatus.Success && reply.Options?.Ttl != null)
                {
                    int ttl = reply.Options.Ttl;
                    Debug.WriteLine($"TTL for {ipAddress}: {ttl}");

                    if (ttl >= 120 && ttl <= 128)
                        return "Windows";
                    if (ttl == 64)
                        return "Linux/Unix";
                    if (ttl == 255 || ttl == 254)
                        return "Network Device";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"TTL detection error for {ipAddress}: {ex.Message}");
            }
            return "Unknown";
        }

        private async Task<bool> CheckSMBProtocol(string ipAddress)
        {
            try
            {
                using var client = new TcpClient();
                if (!await ConnectWithTimeout(client, ipAddress, 445, 1000))
                    return false;

                using var stream = client.GetStream();
                byte[] negotiateRequest = GetSMBNegotiatePacket();

                await stream.WriteAsync(negotiateRequest, 0, negotiateRequest.Length);

                byte[] response = new byte[1024];
                int bytes = await stream.ReadAsync(response, 0, response.Length);

                if (bytes > 0)
                {
                    // Check for SMB1 or SMB2 signature
                    return (response[4] == 0xFF && response[5] == 0x53 &&
                            response[6] == 0x4D && response[7] == 0x42) ||
                           (response[4] == 0xFE && response[5] == 0x53 &&
                            response[6] == 0x4D && response[7] == 0x42);
                }
                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SMB protocol check error for {ipAddress}: {ex.Message}");
                return false;
            }
        }

        private byte[] GetSMBNegotiatePacket()
        {
            byte[] netBIOSHeader = {
                0x00, 0x00, 0x00, 0x54
            };

            byte[] smbHeader = {
                0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00,
                0x00, 0x18, 0x53, 0xC8, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00
            };

            byte[] negotiateRequest = {
                0x00, 0x0C, 0x00, 0x02, 0x4E, 0x54, 0x20, 0x4C,
                0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
            };

            var packet = new List<byte>();
            packet.AddRange(netBIOSHeader);
            packet.AddRange(smbHeader);
            packet.AddRange(negotiateRequest);

            return packet.ToArray();
        }

        private async Task<bool> CheckPort(string ip, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ip, port);
                if (await Task.WhenAny(connectTask, Task.Delay(PORT_TIMEOUT)) == connectTask)
                {
                    return client.Connected;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        private async Task<OSFingerprint> GetTCPFingerprint(string ipAddress)
        {
            try
            {
                using var client = new TcpClient();
                if (!await ConnectWithTimeout(client, ipAddress, 80, 1000))
                {
                    if (!await ConnectWithTimeout(client, ipAddress, 443, 1000))
                    {
                        return null;
                    }
                }

                using NetworkStream stream = client.GetStream();

                // Send multiple SYN packets with different flags and options
                var fingerprint = new OSFingerprint();

                // First SYN packet
                byte[] synPacket = CreateSYNPacket();
                await stream.WriteAsync(synPacket, 0, synPacket.Length);

                byte[] response = new byte[1024];
                int bytesRead = await stream.ReadAsync(response, 0, response.Length);

                if (bytesRead > 0)
                {
                    fingerprint.WindowSize = BitConverter.ToUInt16(response, 14);
                    fingerprint.TTL = response[8];
                    fingerprint.MSS = GetMSS(response);
                    fingerprint.WindowScale = GetWindowScale(response);
                    fingerprint.HasSACK = HasSACKPermitted(response);
                    fingerprint.TCPOptions = ExtractTCPOptions(response);
                    fingerprint.TCPOptionsLength = GetTCPOptionsLength(response);
                    fingerprint.HasTimestamp = HasTimestamp(response);
                    fingerprint.TimestampVal = GetTimestampValue(response);
                    fingerprint.HasSelectiveAck = HasSelectiveAck(response);
                    fingerprint.TCPFlagsSequence = ExtractTCPFlagsSequence(response);
                }

                return fingerprint;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"TCP fingerprinting error for {ipAddress}: {ex.Message}");
                return null;
            }
        }

        private int GetTCPOptionsLength(byte[] packet)
        {
            int length = 0;
            int i = 20; // Start after IP header

            while (i < packet.Length && packet[i] != 0)
            {
                if (packet[i] == 1) 
                {
                    length++;
                    i++;
                }
                else if (i + 1 < packet.Length)
                {
                    length += packet[i + 1];
                    i += packet[i + 1];
                }
                else
                {
                    break;
                }
            }
            return length;
        }

        private bool HasTimestamp(byte[] packet)
        {
            for (int i = 20; i < packet.Length - 2; i++)
            {
                if (packet[i] == 8 && packet[i + 1] == 10) // Timestamp option
                {
                    return true;
                }
            }
            return false;
        }

        private int GetTimestampValue(byte[] packet)
        {
            for (int i = 20; i < packet.Length - 6; i++)
            {
                if (packet[i] == 8 && packet[i + 1] == 10)
                {
                    return BitConverter.ToInt32(packet, i + 2);
                }
            }
            return 0;
        }

        private bool HasSelectiveAck(byte[] packet)
        {
            for (int i = 20; i < packet.Length - 2; i++)
            {
                if (packet[i] == 5 && packet[i + 1] == 2) // SACK option
                {
                    return true;
                }
            }
            return false;
        }

        private string ExtractTCPFlagsSequence(byte[] packet)
        {
            if (packet.Length >= 34)
            {
                byte flags = packet[33];
                return Convert.ToString(flags, 2).PadLeft(8, '0');
            }
            return string.Empty;
        }

        private class OSFingerprint
        {
            public ushort WindowSize { get; set; }
            public byte TTL { get; set; }
            public int MSS { get; set; }
            public int WindowScale { get; set; }
            public bool HasSACK { get; set; }
            public List<int> TCPOptions { get; set; } = new List<int>();
            public int TCPOptionsLength { get; set; }
            public bool HasTimestamp { get; set; }
            public int TimestampVal { get; set; }
            public bool HasSelectiveAck { get; set; }
            public string TCPFlagsSequence { get; set; }
        }

        private bool IsAndroidFingerprint(OSFingerprint fingerprint)
        {
            if (fingerprint == null) return false;

            // Android specific characteristics
            bool hasAndroidTraits =
                
                fingerprint.WindowSize <= 65535 &&

                
                (fingerprint.TTL == 64 || fingerprint.TTL == 128) &&

                
                (fingerprint.MSS == 1400 || fingerprint.MSS == 1440 || fingerprint.MSS == 1452) &&

                
                (fingerprint.WindowScale >= 1 && fingerprint.WindowScale <= 4) &&

        
                fingerprint.HasSACK &&

                fingerprint.HasTimestamp &&

                (fingerprint.TCPOptionsLength >= 20 && fingerprint.TCPOptionsLength <= 28);

            return hasAndroidTraits;
        }

        private bool IsLinuxFingerprint(OSFingerprint fingerprint)
        {
            if (fingerprint == null) return false;

            // Linux specific characteristics
            bool hasLinuxTraits =

                fingerprint.WindowSize >= 65535 &&

                fingerprint.TTL == 64 &&

                (fingerprint.MSS == 1460 || fingerprint.MSS == 1500) &&

                fingerprint.WindowScale >= 7 &&

                fingerprint.HasSACK &&

                fingerprint.HasTimestamp &&

                (fingerprint.TCPOptionsLength >= 28 && fingerprint.TCPOptionsLength <= 40);

            return hasLinuxTraits;
        }


        private byte[] CreateSYNPacket()
        {
     
            return new byte[]
            {

                0x45, 0x00, 0x00, 0x3C, 
                0x00, 0x00, 0x40, 0x00,
                0x40, 0x06, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,


                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x80, 0x02, 0x20, 0x00,
                0x00, 0x00, 0x00, 0x00
            };
        }

        private int GetMSS(byte[] packet)
        {
            
            for (int i = 20; i < packet.Length - 4; i++)
            {
                if (packet[i] == 2 && packet[i + 1] == 4)
                {
                    return BitConverter.ToUInt16(packet, i + 2);
                }
            }
            return 0;
        }

        private int GetWindowScale(byte[] packet)
        {
           
            for (int i = 20; i < packet.Length - 3; i++)
            {
                if (packet[i] == 3 && packet[i + 1] == 3)
                {
                    return packet[i + 2];
                }
            }
            return 0;
        }

        private bool HasSACKPermitted(byte[] packet)
        {
        
            for (int i = 20; i < packet.Length - 2; i++)
            {
                if (packet[i] == 4 && packet[i + 1] == 2)
                {
                    return true;
                }
            }
            return false;
        }

        private List<int> ExtractTCPOptions(byte[] packet)
        {
            var options = new List<int>();
            for (int i = 20; i < packet.Length - 1; i++)
            {
                if (packet[i] > 0 && packet[i] < 255)
                {
                    options.Add(packet[i]);
                }
            }
            return options;
        }

        private async Task<bool> ConnectWithTimeout(TcpClient client,
            string host, int port, int timeout)
        {
            try
            {
                var connectTask = client.ConnectAsync(host, port);
                await Task.WhenAny(connectTask, Task.Delay(timeout));
                return client.Connected;
            }
            catch
            {
                return false;
            }
        }
    }
}