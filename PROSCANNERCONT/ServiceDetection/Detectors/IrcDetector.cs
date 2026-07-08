using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class IRCDetector : IServiceDetector
    {
        private readonly ILogger<IRCDetector> _logger;

        public string ServiceName => "IRC";
        public int[] CommonPorts => new[] { 6667 };
        public int Priority => 10;

        public IRCDetector(ILogger<IRCDetector> logger)
        {
            _logger = logger;
        }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            return Array.Exists(CommonPorts, p => p == port);
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 10000, CancellationToken cancellationToken = default)
        {
            try
            {
                await Task.Delay(2000, cancellationToken); // Reduce throttling delay

                using var client = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(timeout);

                await client.ConnectAsync(result.IPAddress, result.Port, cts.Token);
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII);
                using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

                // Send standard IRC handshake
                string nick = "NmapScan" + new Random().Next(1000, 9999);
                await writer.WriteLineAsync($"NICK {nick}");
                await writer.WriteLineAsync($"USER {nick} 0 * :Scanner");

                string versionInfo = null;
                var response = new StringBuilder();
                var deadline = DateTime.Now.AddSeconds(15); // Increased timeout
                bool receivedNotice = false;
                bool sentPong = false;

                while (DateTime.Now < deadline && !cts.Token.IsCancellationRequested)
                {
                    if (reader.Peek() >= 0)
                    {
                        var line = await reader.ReadLineAsync();
                        if (line == null) break;

                        _logger.LogInformation($"IRC >> {line}");
                        response.AppendLine(line);

                        if (line.Contains(" 004 "))
                        {
                            var ver = ExtractVersionFrom004(line);
                            if (!string.IsNullOrEmpty(ver))
                            {
                                versionInfo = ver;
                                break; // got good info, exit loop
                            }
                        }
                        else if (line.Contains("NOTICE AUTH"))
                        {
                            receivedNotice = true;

                            var unrealVer = ExtractUnrealVersion(line);
                            if (!string.IsNullOrEmpty(unrealVer))
                            {
                                versionInfo = unrealVer;
                                break;
                            }

                            var genericVer = ExtractServerFromNotice(line);
                            if (!string.IsNullOrEmpty(genericVer))
                                versionInfo = genericVer; // fallback if Unreal not found
                        }

                        else if (line.Contains("Closing Link") || line.Contains("Throttled") || line.Contains("ERROR"))
                        {
                            if (line.Contains("Throttled"))
                                versionInfo = "IRC Server (Connection Throttled)";
                            else
                                versionInfo = "IRC Server (Connection Closed)";
                            break;
                        }
                        else if (line.StartsWith("PING"))
                        {
                            await writer.WriteLineAsync(line.Replace("PING", "PONG"));
                        }
                        // add other parsing as needed
                    }
                    else
                    {
                        await Task.Delay(200, cancellationToken);
                    }
                }


                // If we didn't get specific version info, use what we have
                if (string.IsNullOrEmpty(versionInfo) && receivedNotice)
                {
                    versionInfo = "IRC Server (Authenticated)";
                }

                result.Service = "IRC";
                result.Version = versionInfo ?? "IRC Server (Unknown Version)";
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"IRC detection failed on {result.IPAddress}:{result.Port}");
                result.Service = "IRC";
                result.Version = "IRC Server (Detection Error)";
                return result;
            }
        }

        private string ExtractServerFromNotice(string line)
        {
            // Extract server name from NOTICE AUTH line
            // Format: :servername NOTICE AUTH :message
            if (line.StartsWith(":"))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    var serverName = parts[0].Substring(1); // Remove leading ':'
                    return $"IRC Server ({serverName})";
                }
            }
            return "IRC Server (AUTH Notice)";
        }

        private string ExtractServerFromWelcome(string line)
        {
            // Welcome messages often contain server software info
            if (line.ToLower().Contains("unreal"))
            {
                return ExtractUnrealVersion(line);
            }
            else if (line.ToLower().Contains("inspircd"))
            {
                var match = ExtractWordWithVersion(line, "inspircd");
                return $"InspIRCd ({match})";
            }
            else if (line.ToLower().Contains("ircd"))
            {
                var match = ExtractWordWithVersion(line, "ircd");
                return $"IRCd ({match})";
            }

            // Extract server name from welcome format
            if (line.StartsWith(":"))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    var serverName = parts[0].Substring(1);
                    return $"IRC Server ({serverName})";
                }
            }

            return null;
        }

        private string ExtractServerFromSupport(string line)
        {
            // 005 ISUPPORT lines sometimes contain server info
            if (line.ToLower().Contains("unreal"))
            {
                return ExtractUnrealVersion(line);
            }
            else if (line.ToLower().Contains("inspircd"))
            {
                var match = ExtractWordWithVersion(line, "inspircd");
                return $"InspIRCd ({match})";
            }

            return null;
        }

        private string ExtractVersionFrom004(string line)
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length >= 4)
            {
                var versionCandidate = parts[3]; // 0-based index 3 is usually the version string

                if (versionCandidate.StartsWith("Unreal", StringComparison.OrdinalIgnoreCase) ||
                    line.ToLower().Contains("unreal"))
                {
                    return $"Unreal IRCd ({versionCandidate})";
                }
                // Add other known IRCd here, e.g., InspIRCd:
                if (versionCandidate.ToLower().Contains("inspircd"))
                {
                    return $"InspIRCd ({versionCandidate})";
                }
                // Fallback generic:
                return $"IRC Server ({versionCandidate})";
            }

            return null;
        }






        private string ExtractUnrealVersion(string line)
        {
            var start = line.IndexOf("unreal", StringComparison.OrdinalIgnoreCase);
            if (start >= 0)
            {
                var version = ExtractWordOrVersion(line, start);
                return $"Unreal IRCd ({version})";
            }
            return "Unreal IRCd (Version Unknown)";
        }


        private string ExtractWordWithVersion(string text, string keyword)
        {
            var start = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
            if (start >= 0)
            {
                return ExtractWordOrVersion(text, start);
            }
            return keyword;
        }

        private string ExtractWordOrVersion(string text, int startIndex)
        {
            if (startIndex < 0 || startIndex >= text.Length)
                return "Unknown";

            var version = new StringBuilder();
            for (int i = startIndex; i < text.Length; i++)
            {
                char c = text[i];
                if (char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_')
                    version.Append(c);
                else if (version.Length > 0 && !char.IsLetterOrDigit(c))
                    break; // Stop at first non-alphanumeric after we've started collecting
            }

            return version.Length > 0 ? version.ToString() : "Unknown";
        }
    }
}