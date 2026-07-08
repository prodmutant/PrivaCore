using ControlzEx.Standard;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class TelnetDetector : IServiceDetector
    {
        public string ServiceName => "Telnet";
        public int[] CommonPorts => new[] { 23, 992, 2323 };
        public int Priority => 25;

        private readonly ILogger<TelnetDetector> _logger;

        public TelnetDetector(ILogger<TelnetDetector> logger)
        {
            _logger = logger;
        }

        public TelnetDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            bool isTelnetService = !string.IsNullOrEmpty(initialScan.Service) &&
                (initialScan.Service.Contains("Telnet", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("Terminal", StringComparison.OrdinalIgnoreCase));

            return isCommonPort || isTelnetService;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            result.Track("Telnet Detector Started");

            result.SetService("Telnet");
            result.SetVersion("Unknown");
            result.Protocol = result.Port == 992 ? "TelnetS" : "Telnet";

            try
            {
                // Grab banner
                string banner = await BannerGrabber.GrabBannerAsync(
                    result.IPAddress, result.Port, timeout, cancellationToken);

                // 🔥 DEBUG OUTPUT 🔥
                Console.WriteLine($"═══════════════════════════════════");
                Console.WriteLine($"[TELNET DEBUG] IP: {result.IPAddress}:{result.Port}");
                Console.WriteLine($"[TELNET DEBUG] Banner Length: {banner?.Length ?? 0}");
                Console.WriteLine($"[TELNET DEBUG] Banner: '{banner}'");
                Console.WriteLine($"[TELNET DEBUG] Banner Hex: {(banner != null ? BitConverter.ToString(Encoding.ASCII.GetBytes(banner)) : "NULL")}");
                Console.WriteLine($"═══════════════════════════════════");

                _logger?.LogInformation($"Telnet Banner: {banner}");

                if (!string.IsNullOrEmpty(banner))
                {
                    result.RawBanner = banner;
                    ParseTelnetBanner(banner, result);
                }
                else
                {
                    // No banner - set default based on port
                    SetDefaultByPort(result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Telnet detection error");
                SetDefaultByPort(result);
            }

            // 🔥 DEBUG OUTPUT 🔥
            Console.WriteLine($"[TELNET RESULT] Service: {result.Service}");
            Console.WriteLine($"[TELNET RESULT] Version: {result.Version}");
            Console.WriteLine($"═══════════════════════════════════\n");

            result.Track("Telnet Detector Finished");
            return result;
        }

        private void ParseTelnetBanner(string banner, PortScanResult result)
        {
            try
            {
                // Check if banner is empty or whitespace
                if (string.IsNullOrWhiteSpace(banner))
                {
                    // No banner - but port 23 is usually Linux telnetd
                    if (result.Port == 23)
                    {
                        result.SetService("Telnet");
                        result.SetVersion("Linux telnetd");
                        Console.WriteLine("[TELNET] Empty banner, port 23 → Linux telnetd");
                        return;
                    }

                    SetDefaultByPort(result);
                    return;
                }

                // Clean banner for analysis
                string cleanBanner = banner.Replace("\r", "").Replace("\n", " ").Trim();
                string lowerBanner = cleanBanner.ToLower();

                Console.WriteLine($"[TELNET] Clean banner: '{cleanBanner}'");
                Console.WriteLine($"[TELNET] Lower banner: '{lowerBanner}'");

                // Check for IAC (telnet negotiation) bytes
                if (banner.Contains("\xFF"))
                {
                    Console.WriteLine("[TELNET] Detected IAC negotiation bytes");

                    // Port 23 with IAC bytes is almost always Linux telnetd
                    if (result.Port == 23)
                    {
                        result.SetService("Telnet");
                        result.SetVersion("Linux telnetd");
                        Console.WriteLine("[TELNET] Port 23 + IAC → Linux telnetd");
                        return;
                    }
                }

                // Check for "login:" which is very common for Linux telnetd
                if (lowerBanner.Contains("login:"))
                {
                    result.SetService("Telnet");
                    result.SetVersion("Linux telnetd");
                    Console.WriteLine("[TELNET] Found 'login:' → Linux telnetd");
                    return;
                }

                // Linux telnetd: "Ubuntu 20.04.1 LTS" or "Debian GNU/Linux"
                if (lowerBanner.Contains("ubuntu") ||
                    lowerBanner.Contains("debian") ||
                    lowerBanner.Contains("linux"))
                {
                    result.SetService("Telnet");

                    if (lowerBanner.Contains("ubuntu"))
                    {
                        var ubuntuMatch = Regex.Match(cleanBanner, @"Ubuntu\s+([\d\.]+)", RegexOptions.IgnoreCase);
                        result.SetVersion(ubuntuMatch.Success
                            ? $"Linux telnetd (Ubuntu {ubuntuMatch.Groups[1].Value})"
                            : "Linux telnetd (Ubuntu)");
                        Console.WriteLine($"[TELNET] Ubuntu detected → {result.Version}");
                    }
                    else if (lowerBanner.Contains("debian"))
                    {
                        result.SetVersion("Linux telnetd (Debian)");
                        Console.WriteLine("[TELNET] Debian detected → Linux telnetd (Debian)");
                    }
                    else
                    {
                        result.SetVersion("Linux telnetd");
                        Console.WriteLine("[TELNET] Linux detected → Linux telnetd");
                    }
                    return;
                }

                // BusyBox telnetd
                var busyboxMatch = Regex.Match(cleanBanner, @"BusyBox\s+v?([\d\.]+)", RegexOptions.IgnoreCase);
                if (busyboxMatch.Success)
                {
                    result.SetService("Telnet");
                    result.SetVersion($"BusyBox telnetd {busyboxMatch.Groups[1].Value}");
                    Console.WriteLine($"[TELNET] BusyBox detected → {result.Version}");
                    return;
                }

                // Cisco IOS
                if (lowerBanner.Contains("cisco") || lowerBanner.Contains("ios"))
                {
                    result.SetService("Telnet");

                    var iosMatch = Regex.Match(cleanBanner, @"IOS\s+(?:Software,?\s+)?Version\s+([\d\.]+[A-Z]*[\d]*)", RegexOptions.IgnoreCase);
                    if (iosMatch.Success)
                    {
                        result.SetVersion($"Cisco IOS {iosMatch.Groups[1].Value}");
                    }
                    else
                    {
                        result.SetVersion("Cisco IOS");
                    }
                    Console.WriteLine($"[TELNET] Cisco detected → {result.Version}");
                    return;
                }

                // MikroTik RouterOS
                if (lowerBanner.Contains("mikrotik") || lowerBanner.Contains("routeros"))
                {
                    result.SetService("Telnet");

                    var routerOsMatch = Regex.Match(cleanBanner, @"RouterOS\s+([\d\.]+)", RegexOptions.IgnoreCase);
                    result.SetVersion(routerOsMatch.Success
                        ? $"MikroTik RouterOS {routerOsMatch.Groups[1].Value}"
                        : "MikroTik RouterOS");
                    Console.WriteLine($"[TELNET] MikroTik detected → {result.Version}");
                    return;
                }

                // OpenWrt
                if (lowerBanner.Contains("openwrt"))
                {
                    result.SetService("Telnet");
                    var owrtMatch = Regex.Match(cleanBanner, @"OpenWrt\s+([\d\.]+)", RegexOptions.IgnoreCase);
                    result.SetVersion(owrtMatch.Success
                        ? $"OpenWrt {owrtMatch.Groups[1].Value}"
                        : "OpenWrt");
                    Console.WriteLine($"[TELNET] OpenWrt detected → {result.Version}");
                    return;
                }

                // DD-WRT
                if (lowerBanner.Contains("dd-wrt"))
                {
                    result.SetService("Telnet");
                    result.SetVersion("DD-WRT");
                    Console.WriteLine("[TELNET] DD-WRT detected");
                    return;
                }

                // Windows Telnet Server
                if (lowerBanner.Contains("windows") || lowerBanner.Contains("microsoft"))
                {
                    result.SetService("Telnet");
                    result.SetVersion("Windows Telnet Server");
                    Console.WriteLine("[TELNET] Windows detected");
                    return;
                }

                // HP JetDirect
                if (lowerBanner.Contains("jetdirect") || lowerBanner.Contains("hp"))
                {
                    result.SetService("Telnet");
                    result.SetVersion("HP JetDirect");
                    Console.WriteLine("[TELNET] HP JetDirect detected");
                    return;
                }

                // ZyXEL
                if (lowerBanner.Contains("zyxel"))
                {
                    result.SetService("Telnet");
                    result.SetVersion("ZyXEL Telnet");
                    Console.WriteLine("[TELNET] ZyXEL detected");
                    return;
                }

                // Huawei
                if (lowerBanner.Contains("huawei"))
                {
                    result.SetService("Telnet");
                    result.SetVersion("Huawei Telnet");
                    Console.WriteLine("[TELNET] Huawei detected");
                    return;
                }

                // If we got a banner but couldn't identify it, and it's port 23
                if (result.Port == 23 && !string.IsNullOrWhiteSpace(cleanBanner))
                {
                    result.SetService("Telnet");

                    // Use first meaningful line as version
                    var firstLine = cleanBanner.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
                    if (firstLine.Length < 50 && firstLine.Length > 3)
                    {
                        result.SetVersion($"Linux telnetd ({firstLine})");
                        Console.WriteLine($"[TELNET] Port 23 unidentified banner → Linux telnetd ({firstLine})");
                    }
                    else
                    {
                        result.SetVersion("Linux telnetd");
                        Console.WriteLine("[TELNET] Port 23 unidentified → Linux telnetd");
                    }
                    return;
                }

                // Default
                Console.WriteLine("[TELNET] No match found, using default");
                SetDefaultByPort(result);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing Telnet banner");
                Console.WriteLine($"[TELNET ERROR] {ex.Message}");

                // Even on error, port 23 is likely Linux telnetd
                if (result.Port == 23)
                {
                    result.SetService("Telnet");
                    result.SetVersion("Linux telnetd");
                    Console.WriteLine("[TELNET] Parse error on port 23 → Linux telnetd");
                }
                else
                {
                    SetDefaultByPort(result);
                }
            }
        }

        private void SetDefaultByPort(PortScanResult result)
        {
            // Set reasonable defaults based on port
            result.SetService("Telnet");

            if (result.Port == 992)
            {
                result.Protocol = "TelnetS";
                result.SetVersion("Secure Telnet (TLS/SSL)");
                Console.WriteLine("[TELNET] Port 992 → Secure Telnet");
            }
            else if (result.Port == 2323)
            {
                result.SetVersion("Telnet (Non-standard Port)");
                Console.WriteLine("[TELNET] Port 2323 → Non-standard");
            }
            else if (result.Port == 23)
            {
                result.SetVersion("Linux telnetd");
                Console.WriteLine("[TELNET] Port 23 default → Linux telnetd");
            }
            else
            {
                result.SetVersion("Telnet Server");
                Console.WriteLine($"[TELNET] Port {result.Port} default → Telnet Server");
            }
        }
    }
}
