using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;
using PROSCANNERCONT.ServiceDetection.Models;
using PROSCANNERCONT.ServiceDetection.Scanners;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class NetBIOSDetector : IServiceDetector
    {
        private readonly ILogger<NetBIOSDetector> _logger;

        public NetBIOSDetector(ILogger<NetBIOSDetector> logger)
        {
            _logger = logger;
        }
    
        public string ServiceName => "NetBIOS-SSN";

        public int[] CommonPorts => new[] { 139, 445 }; // NetBIOS Session Service and Direct SMB

        public int Priority => 45; // Between common services and databases

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check if it's a common NetBIOS/SMB port
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            // Check if initial scan already suggests NetBIOS/SMB
            bool isSmbService = initialScan.Service?.Contains("netbios", StringComparison.OrdinalIgnoreCase) == true ||
                               initialScan.Service?.Contains("smb", StringComparison.OrdinalIgnoreCase) == true ||
                               initialScan.Service?.Contains("cifs", StringComparison.OrdinalIgnoreCase) == true;

            return isCommonPort || isSmbService;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"NetBIOS detection on {result.IPAddress}:{result.Port}");

                // Create version info structure
                var versionInfo = new SmbVersionInfo();

                // Use your existing scanners with async wrapper
                bool detectionSuccess = await Task.Run(() =>
                {
                    // Create scanner instances
                    var smb1Scanner = new Smb1Scanner(result.IPAddress, result.Port);
                    var smb2Scanner = new Smb2Scanner(result.IPAddress, result.Port);
                    var smb3Scanner = new Smb3Scanner(result.IPAddress, result.Port);

                    // Test SMB1 first
                    bool smb1Success = smb1Scanner.TestSupport(ref versionInfo);

                    // If SMB1 test was successful but SMB1 not supported, try SMB2
                    if (smb1Success && !versionInfo.Smb1Supported)
                    {
                        bool smb2Success = smb2Scanner.TestSupport(ref versionInfo);

                        // If SMB2 is detected, try SMB3
                        if (smb2Success && versionInfo.Smb2Supported)
                        {
                            smb3Scanner.TestSupport(ref versionInfo);
                        }
                    }

                    return smb1Success;
                }, cancellationToken);

                if (detectionSuccess)
                {
                    // Build service information based on detected versions
                    result.Service = BuildServiceName(versionInfo);
                    result.Version = BuildVersionString(versionInfo);

                    // Add security assessment if SMB1 is enabled
                    if (versionInfo.Smb1Supported)
                    {
                        result.Version += " [WARNING: SMB1 enabled]";
                    }
                }
                else
                {
                    // Fallback to banner grabbing if SMB detection fails
                    await PerformBannerGrabbing(result, timeout, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                result.Service = "NetBIOS-SSN";
                result.Version = "Detection cancelled";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"NetBIOS detection error on {result.IPAddress}:{result.Port}");
                result.Service = "NetBIOS-SSN";
                result.Version = "Detection failed";

                // Try basic banner grabbing as fallback
                try
                {
                    await PerformBannerGrabbing(result, timeout, cancellationToken);
                }
                catch
                {
                    // Ignore fallback errors
                }
            }

            return result;
        }

        private string BuildServiceName(SmbVersionInfo versionInfo)
        {
            if (versionInfo.Smb3Supported)
                return "SMB 3.x (NetBIOS-SSN)";
            else if (versionInfo.Smb2Supported)
                return "SMB 2.x (NetBIOS-SSN)";
            else if (versionInfo.Smb1Supported)
                return "SMB 1.0 (NetBIOS-SSN)";
            else
                return "NetBIOS-SSN";
        }

        private string BuildVersionString(SmbVersionInfo versionInfo)
        {
            var versionParts = new List<string>();

            if (versionInfo.Smb1Supported)
                versionParts.Add("SMB1");
            if (versionInfo.Smb2Supported)
                versionParts.Add("SMB2");
            if (versionInfo.Smb3Supported)
                versionParts.Add("SMB3");

            if (versionInfo.HighestVersion != null)
            {
                versionParts.Add($"v{versionInfo.HighestVersion}");
            }

            return versionParts.Count > 0
                ? string.Join(", ", versionParts)
                : versionInfo.GetHighestVersionString();
        }

        private async Task PerformBannerGrabbing(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            string banner = await BannerGrabber.GrabBannerAsync(
                result.IPAddress, result.Port, timeout, cancellationToken);

            result.Service = "NetBIOS-SSN";
            result.Version = string.IsNullOrEmpty(banner)
                ? "NetBIOS Session Service (no banner)"
                : $"NetBIOS Session Service: {BannerGrabber.GetFirstLine(banner)}";
        }

        // ── Static convenience method for Service_Handler facade ──────────────

        public static async Task<string> DetectVersionAsync(string ipAddress, int port, CancellationToken ct = default)
        {
            try
            {
                var stub = new PortScanResult { IPAddress = ipAddress, Port = port };
                var detector = new NetBIOSDetector(null!);
                var result = await detector.DetectAsync(stub, 3000, ct);
                return string.IsNullOrEmpty(result.Version) ? "NetBIOS/SMB (Unknown Version)" : $"{result.Service} {result.Version}".Trim();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NetBIOSDetector.DetectVersionAsync] {ex.Message}");
                return "NetBIOS/SMB (Detection Failed)";
            }
        }
    }
}