using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class FtpDetector : IServiceDetector
    {
        public string ServiceName => "FTP";
        public int[] CommonPorts => new[] { 21, 2121 };
        public int Priority => 30;

        private readonly ILogger<FtpDetector> _logger;

        public FtpDetector(ILogger<FtpDetector> logger)
        {
            _logger = logger;
        }

        public FtpDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            foreach (int p in CommonPorts)
            {
                if (port == p) return true;
            }

            if (!string.IsNullOrEmpty(initialScan.Service))
            {
                string service = initialScan.Service.ToLower();
                return service.Contains("ftp");
            }

            return false;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            result.Track("FTP Detector Started");

            result.SetService("FTP");
            result.SetVersion("Unknown");
            result.Protocol = "FTP";

            try
            {
                // Get FTP banner (220 greeting)
                string banner = await BannerGrabber.GrabBannerAsync(
                    result.IPAddress, result.Port, timeout, cancellationToken);

                _logger?.LogInformation($"FTP Banner: {banner}");

                if (!string.IsNullOrEmpty(banner))
                {
                    result.RawBanner = banner;

                    if (!ParseFtpBanner(banner, result))
                    {
                        // If banner parsing failed, try SYST command
                        await EnhanceWithSyst(result, timeout, cancellationToken);
                    }
                }
                else
                {
                    // No banner - try SYST anyway
                    await EnhanceWithSyst(result, timeout, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "FTP detection error");
            }

            result.Track("FTP Detector Finished");
            return result;
        }

        private bool ParseFtpBanner(string banner, PortScanResult result)
        {
            if (string.IsNullOrEmpty(banner)) return false;

            try
            {
                // Remove "220 " status code and clean up
                var cleanBanner = Regex.Replace(banner, @"^220[\s-]", "", RegexOptions.Multiline);
                cleanBanner = cleanBanner.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[0];

                _logger?.LogInformation($"Clean FTP banner: {cleanBanner}");

                // vsftpd: "220 (vsFTPd 3.0.3)"
                var vsftpdMatch = Regex.Match(cleanBanner, @"\(vsFTPd\s+([\d\.]+)\)", RegexOptions.IgnoreCase);
                if (vsftpdMatch.Success)
                {
                    result.SetService("vsftpd");
                    result.SetVersion(vsftpdMatch.Groups[1].Value);
                    return true;
                }

                // ProFTPD: "220 ProFTPD 1.3.5e Server"
                var proftpdMatch = Regex.Match(cleanBanner, @"ProFTPD\s+([\d\.]+[a-z]*)", RegexOptions.IgnoreCase);
                if (proftpdMatch.Success)
                {
                    result.SetService("ProFTPD");
                    result.SetVersion(proftpdMatch.Groups[1].Value);
                    return true;
                }

                // Pure-FTPd: "220---------- Welcome to Pure-FTPd ----------"
                if (cleanBanner.Contains("Pure-FTPd", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("Pure-FTPd");
                    var pureMatch = Regex.Match(cleanBanner, @"Pure-FTPd\s+([\d\.]+)", RegexOptions.IgnoreCase);
                    result.SetVersion(pureMatch.Success ? pureMatch.Groups[1].Value : "Version Hidden");
                    return true;
                }

                // FileZilla Server: "220-FileZilla Server 0.9.60 beta"
                var filezillaMatch = Regex.Match(cleanBanner, @"FileZilla\s+Server\s+([\d\.\s]+(?:beta|alpha|rc\d+)?)", RegexOptions.IgnoreCase);
                if (filezillaMatch.Success)
                {
                    result.SetService("FileZilla Server");
                    result.SetVersion(filezillaMatch.Groups[1].Value.Trim());
                    return true;
                }

                // Microsoft FTP Service: "220 Microsoft FTP Service"
                if (cleanBanner.Contains("Microsoft FTP", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("Microsoft FTP Service");

                    // Try to extract IIS version
                    var iisMatch = Regex.Match(cleanBanner, @"Version\s+([\d\.]+)", RegexOptions.IgnoreCase);
                    result.SetVersion(iisMatch.Success ? $"IIS {iisMatch.Groups[1].Value}" : "Version Hidden");
                    return true;
                }

                // Wu-FTPd: "220 hostname FTP server (Wu-FTPd 2.6.1)"
                var wuftpdMatch = Regex.Match(cleanBanner, @"Wu-FTPd\s+([\d\.]+)", RegexOptions.IgnoreCase);
                if (wuftpdMatch.Success)
                {
                    result.SetService("Wu-FTPd");
                    result.SetVersion(wuftpdMatch.Groups[1].Value);
                    return true;
                }

                // Generic "FTP server ready"
                if (cleanBanner.Contains("FTP server", StringComparison.OrdinalIgnoreCase) ||
                    cleanBanner.Contains("FTP Service", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("FTP");

                    // Try to extract any version number
                    var versionMatch = Regex.Match(cleanBanner, @"([\d]+\.[\d]+(?:\.[\d]+)?)", RegexOptions.IgnoreCase);
                    result.SetVersion(versionMatch.Success
                        ? $"Server Identity Hidden (v{versionMatch.Groups[1].Value})"
                        : "Server Identity Hidden");
                    return true;
                }

                // Generic "ready" message
                if (cleanBanner.Contains("ready", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("FTP");
                    result.SetVersion("Server Identity Hidden");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing FTP banner");
                return false;
            }
        }

        private async Task EnhanceWithSyst(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                // Send SYST command to get system type
                var systCommand = Encoding.ASCII.GetBytes("SYST\r\n");
                string systResponse = await BannerGrabber.GrabBannerWithTriggerAsync(
                    result.IPAddress, result.Port, systCommand, timeout, cancellationToken);

                _logger?.LogInformation($"FTP SYST Response: {systResponse}");

                if (!string.IsNullOrEmpty(systResponse))
                {
                    ParseSystResponse(systResponse, result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "FTP SYST command failed");
            }
        }

        private void ParseSystResponse(string systResponse, PortScanResult result)
        {
            try
            {
                // SYST response format: "215 UNIX Type: L8"

                // Remove status code
                var cleanResponse = Regex.Replace(systResponse, @"^215[\s-]", "", RegexOptions.Multiline);

                if (cleanResponse.Contains("UNIX", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("FTP");
                    result.SetVersion(result.Version == "Unknown"
                        ? "UNIX FTP Server"
                        : result.Version + " (UNIX)");
                }
                else if (cleanResponse.Contains("Windows", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("FTP");
                    result.SetVersion(result.Version == "Unknown"
                        ? "Windows FTP Server"
                        : result.Version + " (Windows)");
                }
                else if (cleanResponse.Contains("Linux", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("FTP");
                    result.SetVersion(result.Version == "Unknown"
                        ? "Linux FTP Server"
                        : result.Version + " (Linux)");
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing SYST response");
            }
        }

        // ── Static convenience method for Service_Handler facade ──────────────

        /// <summary>
        /// Quick version string extraction without a full <see cref="PortScanResult"/> object.
        /// Used by <see cref="PROSCANNERCONT.Service_Handler.Service_Handler"/>.
        /// </summary>
        public static async Task<string> DetectVersionAsync(string ipAddress, int port, CancellationToken ct = default)
        {
            try
            {
                var stub = new PROSCANNERCONT.Models.PortScanResult { IPAddress = ipAddress, Port = port };
                var detector = new FtpDetector();
                var result = await detector.DetectAsync(stub, 3000, ct);
                return string.IsNullOrEmpty(result.Version) ? "Unknown FTP" : $"{result.Service} {result.Version}".Trim();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[FtpDetector.DetectVersionAsync] {ex.Message}");
                return "Unknown FTP";
            }
        }
    }
}