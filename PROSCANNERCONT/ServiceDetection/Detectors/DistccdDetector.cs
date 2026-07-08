using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class DistccdDetector : IServiceDetector
    {
        public string ServiceName => "distccd";
        public int[] CommonPorts => new[] { 3632 };
        public int Priority => 40;

        private readonly ILogger<DistccdDetector> _logger;

        public DistccdDetector(ILogger<DistccdDetector> logger)
        {
            _logger = logger;
        }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Always detect on common port
            if (port == 3632) return true;

            // Detect if service name suggests distcc
            if (!string.IsNullOrEmpty(initialScan.Service))
            {
                return initialScan.Service.Contains("distcc", StringComparison.OrdinalIgnoreCase) ||
                       initialScan.Service.Contains("distccd", StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogDebug("Starting distccd detection on {IP}:{Port}", result.IPAddress, result.Port);

                // Try direct protocol detection first
                var protocolResult = await DetectWithDistccProtocolAsync(result, timeout, cancellationToken);
                if (protocolResult.Detected)
                {
                    result.Service = "distccd";
                    result.Version = protocolResult.Version ?? "distccd (version unknown)";
                    return result;
                }

                // Fallback to banner grabbing if protocol detection fails
                await TryBannerGrabFallback(result, timeout, cancellationToken);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Distccd detection failed on {IP}:{Port}", result.IPAddress, result.Port);
                return result;
            }
        }

        private async Task<(bool Detected, string Version)> DetectWithDistccProtocolAsync(
            PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new TcpClient();
                client.SendTimeout = timeout;
                client.ReceiveTimeout = timeout;

                // Connect with timeout
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(timeout);

                await client.ConnectAsync(result.IPAddress, result.Port, connectCts.Token);

                using var stream = client.GetStream();

                // Build and send the distcc protocol handshake
                var handshake = BuildDistccHandshake();
                await stream.WriteAsync(handshake, 0, handshake.Length, cancellationToken);
                await stream.FlushAsync(cancellationToken);

                // Read response with timeout
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                readCts.CancelAfter(timeout);

                var buffer = new byte[1024];
                var response = new StringBuilder();
                int bytesRead;

                while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, readCts.Token)) > 0)
                {
                    response.Append(Encoding.ASCII.GetString(buffer, 0, bytesRead));
                    if (!stream.DataAvailable) break;
                }


                // Check if we got a valid distcc response
                if (IsDistccResponse(response.ToString()))
                {
                    string version = ParseDistccVersion(response.ToString());
                    return (true, version);
                }

                return (false, null);
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Distccd detection timed out on {IP}:{Port}", result.IPAddress, result.Port);
                return (false, null);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Distccd protocol detection failed on {IP}:{Port}", result.IPAddress, result.Port);
                return (false, null);
            }
        }

        private byte[] BuildDistccHandshake()
        {
            string payload =
                "DIST00000001" +
                "ARGC00000003" +
                "ARGV00000003gcc" +
                "ARGV00000002-c" +
                "ARGV00000008test.c" +
                "DOTI00000000" +
                "DOTO00000000";
            return Encoding.ASCII.GetBytes(payload);
        }


        private bool IsDistccResponse(string response)
        {
            if (string.IsNullOrEmpty(response))
                return false;

            // Check for common distcc response patterns
            return response.Contains("distccd") ||
                   response.Contains("Usage:") ||
                   response.Contains("DIST") ||  // Protocol response
                   response.Contains("ERROR");  // Error response
        }

        private string ParseDistccVersion(string response)
        {
            if (string.IsNullOrWhiteSpace(response))
                return "distccd (version unknown)";

            var match = System.Text.RegularExpressions.Regex.Match(
                response,
                @"distccd.*\((?:version|v)?\s*([\d.]+).*?GNU.*?([\d.]+)?\)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            if (match.Success)
            {
                string protoVer = match.Groups[1].Value;
                string gnuVer = match.Groups[2].Success ? match.Groups[2].Value : null;

                return gnuVer != null
                    ? $"distccd v{protoVer} (GNU) {gnuVer}"
                    : $"distccd v{protoVer}";
            }

            return "distccd (version unknown)";
        }




        private async Task TryBannerGrabFallback(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                // First try standard banner grab
                string banner = await BannerGrabber.GrabBannerAsync(
                    result.IPAddress,
                    result.Port,
                    timeout,
                    cancellationToken);

                if (string.IsNullOrEmpty(banner))
                {
                    // Try with a version trigger
                    byte[] trigger = Encoding.ASCII.GetBytes("VERSION\n");
                    banner = await BannerGrabber.GrabBannerWithTriggerAsync(
                        result.IPAddress,
                        result.Port,
                        trigger,
                        timeout,
                        cancellationToken);
                }

                if (!string.IsNullOrEmpty(banner) &&
                    (banner.Contains("distcc", StringComparison.OrdinalIgnoreCase) ||
                     banner.Contains("distccd", StringComparison.OrdinalIgnoreCase)))
                {
                    result.Service = "distccd";
                    result.Version = ParseDistccVersion(banner);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Banner grab failed on {IP}:{Port}", result.IPAddress, result.Port);
            }
        }
    }
}