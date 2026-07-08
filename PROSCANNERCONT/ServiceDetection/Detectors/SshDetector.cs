using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class SshDetector : IServiceDetector
    {
        public string ServiceName => "SSH";
        public int[] CommonPorts => new[] { 22, 2222 };
        public int Priority => 20;

        private readonly ILogger<SshDetector> _logger;

        public SshDetector(ILogger<SshDetector> logger)
        {
            _logger = logger;
        }

        public SshDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check common SSH ports
            foreach (int p in CommonPorts)
            {
                if (port == p) return true;
            }

            // Check if service contains SSH keywords
            if (!string.IsNullOrEmpty(initialScan.Service))
            {
                string service = initialScan.Service.ToLower();
                return service.Contains("ssh");
            }

            return false;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            // Track what we receive
            result.Track("SSH Detector Started");

            // Set defaults - Service should be the product name, not protocol
            result.SetService("SSH");
            result.SetVersion("Unknown");
            result.Protocol = "SSH";

            try
            {
                // SSH servers send banner immediately on connection
                string banner = await BannerGrabber.GrabBannerAsync(
                    result.IPAddress, result.Port, timeout, cancellationToken);

                _logger?.LogInformation($"SSH Banner received: {banner}");

                if (!string.IsNullOrEmpty(banner))
                {
                    result.RawBanner = banner;
                    ParseSshBanner(banner, result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "SSH detection error");
            }

            // Track what we're returning
            result.Track("SSH Detector Finished");
            return result;
        }

        private void ParseSshBanner(string banner, PortScanResult result)
        {
            if (string.IsNullOrEmpty(banner) || !banner.StartsWith("SSH-")) return;

            try
            {
                // SSH banners look like: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4
                // Extract the part after SSH-x.x-
                var match = Regex.Match(banner, @"SSH-[\d\.]+-(.*)", RegexOptions.IgnoreCase);
                if (match.Success && match.Groups.Count > 1)
                {
                    string serverInfo = match.Groups[1].Value.Trim();
                    _logger?.LogInformation($"Extracted SSH server info: {serverInfo}");

                    ParseSshServerType(serverInfo, result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing SSH banner");
            }
        }

        private void ParseSshServerType(string serverInfo, PortScanResult result)
        {
            try
            {
                // OpenSSH patterns - most common
                var opensshMatch = Regex.Match(serverInfo, @"OpenSSH[_\s]*([\d\.]+[p\d]*)", RegexOptions.IgnoreCase);
                if (opensshMatch.Success)
                {
                    result.SetService("OpenSSH");
                    if (opensshMatch.Groups[1].Success && !string.IsNullOrEmpty(opensshMatch.Groups[1].Value))
                    {
                        result.SetVersion(opensshMatch.Groups[1].Value);
                    }
                    return;
                }

                // Dropbear SSH patterns
                var dropbearMatch = Regex.Match(serverInfo, @"dropbear[_\s]*([\d\.]+)", RegexOptions.IgnoreCase);
                if (dropbearMatch.Success)
                {
                    result.SetService("Dropbear SSH");
                    if (dropbearMatch.Groups[1].Success && !string.IsNullOrEmpty(dropbearMatch.Groups[1].Value))
                    {
                        result.SetVersion(dropbearMatch.Groups[1].Value);
                    }
                    return;
                }

                // libssh patterns
                var libsshMatch = Regex.Match(serverInfo, @"libssh[_\s]*([\d\.]+)", RegexOptions.IgnoreCase);
                if (libsshMatch.Success)
                {
                    result.SetService("libssh");
                    if (libsshMatch.Groups[1].Success && !string.IsNullOrEmpty(libsshMatch.Groups[1].Value))
                    {
                        result.SetVersion(libsshMatch.Groups[1].Value);
                    }
                    return;
                }

                // PuTTY patterns
                var puttyMatch = Regex.Match(serverInfo, @"PuTTY[_\s]*([\d\.]+)", RegexOptions.IgnoreCase);
                if (puttyMatch.Success)
                {
                    result.SetService("PuTTY");
                    if (puttyMatch.Groups[1].Success && !string.IsNullOrEmpty(puttyMatch.Groups[1].Value))
                    {
                        result.SetVersion(puttyMatch.Groups[1].Value);
                    }
                    return;
                }

                // Generic version extraction for unknown SSH implementations
                var versionMatch = Regex.Match(serverInfo, @"([A-Za-z][A-Za-z0-9\-_]*)[_\s]+([\d]+\.[\d]+(?:\.[\d]+)?[p\d]*)", RegexOptions.IgnoreCase);
                if (versionMatch.Success)
                {
                    string serverName = versionMatch.Groups[1].Value;
                    string version = versionMatch.Groups[2].Value;

                    result.SetService(NormalizeSshServerName(serverName));
                    result.SetVersion(version);
                    return;
                }

                // If no version found, try to extract just the server name
                var serverMatch = Regex.Match(serverInfo, @"^([A-Za-z][A-Za-z0-9\-_]*)", RegexOptions.IgnoreCase);
                if (serverMatch.Success)
                {
                    string serverName = serverMatch.Groups[1].Value;
                    if (!IsGenericSshTerm(serverName))
                    {
                        result.SetService(NormalizeSshServerName(serverName));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing SSH server type");
            }
        }

        private string NormalizeSshServerName(string serverName)
        {
            if (string.IsNullOrEmpty(serverName)) return "SSH";

            var normalized = serverName.ToLowerInvariant().Trim();

            return normalized switch
            {
                "openssh" => "OpenSSH",
                "dropbear" => "Dropbear SSH",
                "libssh" => "libssh",
                "putty" => "PuTTY",
                "ssh" => "SSH",
                _ => serverName // Keep original case if not recognized
            };
        }

        private bool IsGenericSshTerm(string term)
        {
            if (string.IsNullOrEmpty(term)) return true;

            string lower = term.ToLower().Trim();
            return lower == "ssh" ||
                   lower == "server" ||
                   lower == "service" ||
                   lower == "protocol";
        }

        // ── Static convenience method for Service_Handler facade ──────────────

        public static async Task<string> DetectVersionAsync(string ipAddress, int port, CancellationToken ct = default)
        {
            try
            {
                var stub = new PROSCANNERCONT.Models.PortScanResult { IPAddress = ipAddress, Port = port };
                var detector = new SshDetector();
                var result = await detector.DetectAsync(stub, 3000, ct);
                return string.IsNullOrEmpty(result.Version) ? "Unknown SSH" : $"{result.Service} {result.Version}".Trim();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SshDetector.DetectVersionAsync] {ex.Message}");
                return "Unknown SSH";
            }
        }
    }
}