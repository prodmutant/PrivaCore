using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Models;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class CcproxyDetector : IServiceDetector
    {
        private readonly ILogger<CcproxyDetector> _logger;

        public CcproxyDetector(ILogger<CcproxyDetector> logger)
        {
            _logger = logger;
        }

        public string ServiceName => "ccproxy ftp";
        public int[] CommonPorts => new[] { 2121 };
        public int Priority => 1; 

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            return CommonPorts.Contains(port) ||
                   (initialScan.Service?.Equals("ftp", StringComparison.OrdinalIgnoreCase) == true && port == 2121);
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 1000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Starting CCProxy detection on {result.IPAddress}:{result.Port}");

                string banner = await GetFtpBannerAsync(result.IPAddress, result.Port, timeout, cancellationToken);

                if (!string.IsNullOrEmpty(banner) && banner.ToLower().Contains("ccproxy"))
                {
                    result.Service = "ccproxy"; 
                    result.Version = ExtractVersionFromBanner(banner);
                }
                else
                {
                    result.Service = "ccproxy-ftp";
                    result.Version = banner?.Trim() ?? "unknown";
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, $"Error during CCProxy detection on {result.IPAddress}:{result.Port}");
            }

            return result;
        }

        private async Task<string> GetFtpBannerAsync(string ip, int port, int timeout, CancellationToken cancellationToken)
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(ip, port);
            var delayTask = Task.Delay(timeout, cancellationToken);

            if (await Task.WhenAny(connectTask, delayTask) != connectTask)
                return null;

            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);

            stream.ReadTimeout = timeout;
            stream.WriteTimeout = timeout;

            // Read the FTP banner greeting (e.g. "220 CCProxy FTP Server ready")
            string banner = await reader.ReadLineAsync();
            return banner;
        }

        private string ExtractVersionFromBanner(string banner)
        {
            // Attempt to extract version number from the banner
            // e.g., "220 CCProxy FTP Server 8.0 ready"
            var lower = banner.ToLower();
            int idx = lower.IndexOf("ccproxy");

            if (idx >= 0)
            {
                var after = banner.Substring(idx);
                var tokens = after.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var token in tokens)
                {
                    if (Version.TryParse(token, out var _))
                        return token;
                }

                return "unknown version";
            }

            return "unknown";
        }
    }
}
