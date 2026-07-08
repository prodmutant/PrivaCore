using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class PostgreSqlDetector : IServiceDetector
    {
        public string ServiceName => "PostgreSQL";
        public int[] CommonPorts => new[] { 5432 };
        public int Priority => 10;

        private readonly ILogger<PostgreSqlDetector> _logger;

        public PostgreSqlDetector(ILogger<PostgreSqlDetector> logger)
        {
            _logger = logger;
        }

        public PostgreSqlDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            return port == 5432 || (initialScan.Service?.ToLower().Contains("postgres") ?? false);
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            result.Track("PostgreSQL Detector Started");

            result.SetService("PostgreSQL");
            result.SetVersion("Unknown");
            result.Protocol = "PostgreSQL";

            try
            {
                using var client = new TcpClient();

                var connectTask = client.ConnectAsync(result.IPAddress, result.Port);
                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                {
                    result.SetVersion("Connection Timeout");
                    return result;
                }

                using var stream = client.GetStream();

                // Send SSL request
                await stream.WriteAsync(BuildSSLRequestMessage(), 0, 8, cancellationToken);
                int responseByte = stream.ReadByte();

                Stream finalStream = stream;
                bool sslEnabled = false;

                if (responseByte == 'S')
                {
                    // SSL supported
                    sslEnabled = true;
                    var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true);
                    await sslStream.AuthenticateAsClientAsync(result.IPAddress);
                    finalStream = sslStream;
                }
                else if (responseByte != 'N')
                {
                    result.SetVersion($"Invalid SSL Response: {(char)responseByte}");
                    return result;
                }

                // Send startup message
                byte[] startupMessage = CreateStartupMessage();
                await finalStream.WriteAsync(startupMessage, 0, startupMessage.Length, cancellationToken);

                // Read response
                byte[] buffer = new byte[2048];
                int bytesRead = await finalStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                byte[] response = buffer.Take(bytesRead).ToArray();

                // Match version
                string version = MatchPostgreSQLVersion(response);

                if (!string.IsNullOrEmpty(version))
                {
                    result.SetVersion(version + (sslEnabled ? " (SSL)" : ""));
                }
                else
                {
                    result.SetVersion("PostgreSQL Server" + (sslEnabled ? " (SSL)" : ""));
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "PostgreSQL detection error");
                result.SetVersion($"Error: {ex.Message}");
            }

            result.Track("PostgreSQL Detector Finished");
            return result;
        }

        private byte[] BuildSSLRequestMessage()
        {
            byte[] request = new byte[8];
            Array.Copy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(8)), 0, request, 0, 4);
            Array.Copy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(80877103)), 0, request, 4, 4);
            return request;
        }

        private byte[] CreateStartupMessage()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(0); // Length placeholder
            writer.Write(IPAddress.HostToNetworkOrder(196608)); // Protocol version 3.0

            WriteCString(writer, "user");
            WriteCString(writer, "postgres");
            WriteCString(writer, "database");
            WriteCString(writer, "postgres");
            WriteCString(writer, "client_encoding");
            WriteCString(writer, "UTF8");
            writer.Write((byte)0); // Terminator

            int totalLength = (int)ms.Length;
            ms.Position = 0;
            writer.Write(IPAddress.HostToNetworkOrder(totalLength));

            return ms.ToArray();
        }

        private void WriteCString(BinaryWriter writer, string value)
        {
            writer.Write(Encoding.ASCII.GetBytes(value));
            writer.Write((byte)0);
        }

        private string MatchPostgreSQLVersion(byte[] response)
        {
            try
            {
                // Convert to hex for fingerprinting
                string hex = BitConverter.ToString(response).Replace("-", " ");

                // Enhanced fingerprint database
                var fingerprints = new Dictionary<string, string>
                {
                    // Error messages
                    { "45 00 00 00", "PostgreSQL 9.x-15.x" },
                    { "52 00 00 00", "PostgreSQL Server (Auth Required)" },
                    
                    // Specific error codes
                    { "53 46 41 54 41 4C", "PostgreSQL 9.0+" }, // SFATAL
                    
                    // Authentication responses
                    { "52 00 00 00 08 00 00 00 00", "PostgreSQL (No Password)" },
                    { "52 00 00 00 08 00 00 00 05", "PostgreSQL (MD5 Auth)" },
                    { "52 00 00 00 08 00 00 00 0A", "PostgreSQL (SASL Auth)" }
                };

                // Check fingerprints
                foreach (var fp in fingerprints)
                {
                    if (hex.StartsWith(fp.Key))
                    {
                        return fp.Value;
                    }
                }

                // Try to extract version from error messages
                string ascii = Encoding.ASCII.GetString(response.Where(b => b >= 32 && b <= 126).ToArray());

                if (ascii.Contains("PostgreSQL"))
                {
                    // Look for version numbers
                    var match = System.Text.RegularExpressions.Regex.Match(ascii, @"(\d+\.\d+(?:\.\d+)?)");
                    if (match.Success)
                    {
                        return $"PostgreSQL {match.Groups[1].Value}";
                    }
                }

                // Check response type
                if (response.Length > 0)
                {
                    char msgType = (char)response[0];

                    return msgType switch
                    {
                        'R' => "PostgreSQL (Authentication)", // Auth request
                        'E' => "PostgreSQL Server", // Error
                        'S' => "PostgreSQL (Parameter Status)", // Parameter status
                        _ => "PostgreSQL Server"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Error matching PostgreSQL version");
            }

            return null;
        }
    }
}