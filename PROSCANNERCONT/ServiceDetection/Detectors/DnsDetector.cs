using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class DnsDetector : IServiceDetector
    {
        public string ServiceName => "DNS";
        public int[] CommonPorts => new[] { 53, 5353 };
        public int Priority => 45;

        private readonly ILogger<DnsDetector> _logger;

        public DnsDetector(ILogger<DnsDetector> logger)
        {
            _logger = logger;
        }

        public DnsDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            bool isDnsService = !string.IsNullOrEmpty(initialScan.Service) &&
                (initialScan.Service.Contains("DNS", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("Domain", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("BIND", StringComparison.OrdinalIgnoreCase));

            return isCommonPort || isDnsService;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            result.Track("DNS Detector Started");

            result.SetService("DNS");
            result.SetVersion("Unknown");
            result.Protocol = "DNS";

            try
            {
                // Try version.bind query (most common)
                if (await TryVersionBind(result, timeout, cancellationToken))
                {
                    _logger?.LogInformation($"DNS version detected: {result.Version}");
                    result.Track("DNS Detector Finished");
                    return result;
                }

                // Try standard query to confirm DNS
                if (await TryStandardQuery(result, timeout, cancellationToken))
                {
                    if (result.Version == "Unknown")
                    {
                        result.SetVersion("DNS Server (Version Hidden)");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "DNS detection error");
                result.SetVersion("DNS Server (Detection Error)");
            }

            result.Track("DNS Detector Finished");
            return result;
        }

        private async Task<bool> TryVersionBind(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                byte[] query = CreateVersionBindQuery();

                // Try UDP first
                string response = await QueryDnsOverUdp(result.IPAddress, result.Port, query, timeout, cancellationToken);

                if (!string.IsNullOrEmpty(response))
                {
                    return ExtractVersion(response, result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "version.bind query failed");
            }

            return false;
        }

        private async Task<bool> TryStandardQuery(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                byte[] query = CreateStandardQuery();
                string response = await QueryDnsOverUdp(result.IPAddress, result.Port, query, timeout, cancellationToken);

                return !string.IsNullOrEmpty(response);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Standard DNS query failed");
                return false;
            }
        }

        private bool ExtractVersion(string response, PortScanResult result)
        {
            try
            {
                // Convert to bytes for analysis
                byte[] responseBytes = Encoding.ASCII.GetBytes(response);

                // Extract TXT record
                string txtRecord = ExtractTxtRecord(responseBytes);

                if (!string.IsNullOrEmpty(txtRecord))
                {
                    _logger?.LogInformation($"Extracted TXT record: {txtRecord}");

                    // Parse version from TXT record
                    return ParseVersion(txtRecord, result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error extracting version");
            }

            return false;
        }

        private bool ParseVersion(string versionText, PortScanResult result)
        {
            // ISC BIND: "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.13"
            var bindMatch = Regex.Match(versionText, @"([\d]+\.[\d]+\.[\d]+(?:-[A-Z\d]+)?)", RegexOptions.IgnoreCase);
            if (bindMatch.Success)
            {
                result.SetService("ISC BIND");
                result.SetVersion(bindMatch.Groups[1].Value);
                return true;
            }

            // Microsoft DNS
            if (versionText.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            {
                result.SetService("Microsoft DNS");
                result.SetVersion("Windows DNS Server");
                return true;
            }

            // dnsmasq
            if (versionText.Contains("dnsmasq", StringComparison.OrdinalIgnoreCase))
            {
                var dnsmasqMatch = Regex.Match(versionText, @"dnsmasq-([\d\.]+)", RegexOptions.IgnoreCase);
                result.SetService("dnsmasq");
                result.SetVersion(dnsmasqMatch.Success ? dnsmasqMatch.Groups[1].Value : "Version Hidden");
                return true;
            }

            // PowerDNS
            if (versionText.Contains("PowerDNS", StringComparison.OrdinalIgnoreCase))
            {
                var pdnsMatch = Regex.Match(versionText, @"([\d\.]+)", RegexOptions.IgnoreCase);
                result.SetService("PowerDNS");
                result.SetVersion(pdnsMatch.Success ? pdnsMatch.Groups[1].Value : "Version Hidden");
                return true;
            }

            // Unbound
            if (versionText.Contains("unbound", StringComparison.OrdinalIgnoreCase))
            {
                var unboundMatch = Regex.Match(versionText, @"([\d\.]+)", RegexOptions.IgnoreCase);
                result.SetService("Unbound");
                result.SetVersion(unboundMatch.Success ? unboundMatch.Groups[1].Value : "Version Hidden");
                return true;
            }

            // Generic version number
            var versionMatch = Regex.Match(versionText, @"([\d]+\.[\d]+(?:\.[\d]+)?)", RegexOptions.IgnoreCase);
            if (versionMatch.Success)
            {
                result.SetService("DNS Server");
                result.SetVersion(versionMatch.Groups[1].Value);
                return true;
            }

            return false;
        }

        private string ExtractTxtRecord(byte[] response)
        {
            try
            {
                if (response == null || response.Length < 12) return null;

                // Check DNS header
                int answerCount = (response[6] << 8) | response[7];
                if (answerCount == 0) return null;

                // Skip header (12 bytes) and question section
                int pos = 12;

                // Skip question
                while (pos < response.Length && response[pos] != 0)
                {
                    int len = response[pos];
                    if ((len & 0xC0) == 0xC0)
                    {
                        pos += 2;
                        break;
                    }
                    pos += len + 1;
                }
                pos += 5; // Skip null terminator + type + class

                // Parse answer
                // Skip name
                if (pos < response.Length && (response[pos] & 0xC0) == 0xC0)
                {
                    pos += 2;
                }

                if (pos + 10 > response.Length) return null;

                int type = (response[pos] << 8) | response[pos + 1];
                pos += 10; // Skip type, class, TTL

                int dataLen = (response[pos - 2] << 8) | response[pos - 1];

                if (type == 16 && pos + dataLen <= response.Length) // TXT record
                {
                    int txtLen = response[pos];
                    if (pos + 1 + txtLen <= response.Length)
                    {
                        return Encoding.ASCII.GetString(response, pos + 1, txtLen);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error extracting TXT record");
            }

            return null;
        }

        private byte[] CreateVersionBindQuery()
        {
            return new byte[] {
                0x00, 0x01,             // Transaction ID
                0x00, 0x00,             // Flags
                0x00, 0x01,             // Questions: 1
                0x00, 0x00,             // Answers: 0
                0x00, 0x00,             // Authority: 0
                0x00, 0x00,             // Additional: 0
                
                // Query: version.bind
                0x07, (byte)'v', (byte)'e', (byte)'r', (byte)'s', (byte)'i', (byte)'o', (byte)'n',
                0x04, (byte)'b', (byte)'i', (byte)'n', (byte)'d',
                0x00,                   // Null terminator
                
                0x00, 0x10,             // Type: TXT
                0x00, 0x03              // Class: CHAOS
            };
        }

        private byte[] CreateStandardQuery()
        {
            return new byte[] {
                0x00, 0x01,             // Transaction ID
                0x01, 0x00,             // Flags: recursion desired
                0x00, 0x01,             // Questions: 1
                0x00, 0x00,             // Answers: 0
                0x00, 0x00,             // Authority: 0
                0x00, 0x00,             // Additional: 0
                
                // Query: google.com
                0x06, (byte)'g', (byte)'o', (byte)'o', (byte)'g', (byte)'l', (byte)'e',
                0x03, (byte)'c', (byte)'o', (byte)'m',
                0x00,                   // Null terminator
                
                0x00, 0x01,             // Type: A
                0x00, 0x01              // Class: IN
            };
        }

        private async Task<string> QueryDnsOverUdp(string ipAddress, int port, byte[] query, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using (var udpClient = new UdpClient())
                {
                    udpClient.Client.ReceiveTimeout = timeout;
                    udpClient.Client.SendTimeout = timeout;

                    udpClient.Connect(ipAddress, port);
                    await udpClient.SendAsync(query, query.Length);

                    using (var cts = new CancellationTokenSource(timeout))
                    using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, cancellationToken))
                    {
                        var receiveTask = Task.Run(() =>
                        {
                            try
                            {
                                IPEndPoint remoteEP = null;
                                return udpClient.Receive(ref remoteEP);
                            }
                            catch
                            {
                                return null;
                            }
                        }, linkedCts.Token);

                        var buffer = await receiveTask;

                        if (buffer != null)
                        {
                            _logger?.LogInformation($"DNS response received: {buffer.Length} bytes");
                            return Encoding.ASCII.GetString(buffer);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "DNS UDP query error");
            }

            return null;
        }
    }
}