using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class MySqlDetector : IServiceDetector
    {
        public string ServiceName => "MySQL";
        public int[] CommonPorts => new[] { 3306 };
        public int Priority => 10;

        private readonly ILogger<MySqlDetector>? _logger;

        public MySqlDetector(ILogger<MySqlDetector> logger) { _logger = logger; }
        public MySqlDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            if (Array.IndexOf(CommonPorts, port) >= 0) return true;
            return initialScan.Service?.Equals("mysql", StringComparison.OrdinalIgnoreCase) == true;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 8000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(result.IPAddress, result.Port);
                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                {
                    _logger?.LogWarning("Timeout connecting to MySQL at {Address}:{Port}", result.IPAddress, result.Port);
                    return result;
                }

                using var stream = client.GetStream();
                stream.ReadTimeout = 3000;

                var buffer = new byte[512];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                if (bytesRead < 5) return result;

                int offset = 4; // skip 3-byte length + 1-byte packet ID
                byte protocolVersion = buffer[offset++];
                if (protocolVersion < 0x0A) return result;

                int nullIndex = Array.IndexOf(buffer, (byte)0x00, offset);
                if (nullIndex <= offset) return result;

                string version = Encoding.ASCII.GetString(buffer, offset, nullIndex - offset).Trim();
                result.Service = "MySQL";
                result.Version = string.IsNullOrWhiteSpace(version) ? "MySQL (version unknown)" : $"MySQL {version}";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[MySqlDetector.DetectAsync] {ex.Message}");
            }

            return result;
        }

        // ── Static convenience method for Service_Handler facade ──────────────

        public static async Task<string> DetectVersionAsync(string ipAddress, int port, CancellationToken ct = default)
        {
            try
            {
                var stub = new PortScanResult { IPAddress = ipAddress, Port = port };
                var detector = new MySqlDetector();
                var result = await detector.DetectAsync(stub, 3000, ct);
                return string.IsNullOrEmpty(result.Version) ? "Unknown MySQL" : result.Version;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[MySqlDetector.DetectVersionAsync] {ex.Message}");
                return "Unknown MySQL";
            }
        }
    }
}
