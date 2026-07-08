// Services/ServiceProbeHandler.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Linq;
using PROSCANNERCONT.Models;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public class ServiceProbe
    {
        public string Name { get; set; }
        public byte[] ProbeString { get; set; }
        public List<MatchPattern> Matches { get; set; } = new List<MatchPattern>();
        public List<int> Ports { get; set; } = new List<int>();
        public bool SSLTrigger { get; set; }
    }

    public class MatchPattern
    {
        public string Pattern { get; set; }
        public string ServiceName { get; set; }
        public string VersionInfo { get; set; }
    }

    public class PortScannerService
    {
        private readonly ServiceProbeHandler _probeHandler;
        private readonly string _nmapServicesPath;
        private readonly Dictionary<int, string> _serviceDatabase;

        // Compiled regex cache: avoids constructing Regex objects inside hot paths.
        // Key = pattern string, Value = compiled Regex instance.
        private static readonly ConcurrentDictionary<string, Regex> _compiledPatterns = new();

        private static Regex GetPattern(string pattern) =>
            _compiledPatterns.GetOrAdd(pattern,
                p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline));

        public PortScannerService(string nmapDbPath)
        {
            _nmapServicesPath = Path.Combine(nmapDbPath, "nmap-services");
            _probeHandler = new ServiceProbeHandler(Path.Combine(nmapDbPath, "nmap-service-probes"));
            _serviceDatabase = LoadServiceDatabase();
        }

        private Dictionary<int, string> LoadServiceDatabase()
        {
            var database = new Dictionary<int, string>();
            if (File.Exists(_nmapServicesPath))
            {
                foreach (string line in File.ReadLines(_nmapServicesPath))
                {
                    if (!line.StartsWith("#") && !string.IsNullOrWhiteSpace(line))
                    {
                        var parts = line.Split('\t');
                        if (parts.Length >= 2)
                        {
                            var serviceParts = parts[1].Split('/');
                            if (serviceParts.Length >= 2 && int.TryParse(serviceParts[0], out int port))
                            {
                                database[port] = parts[0];
                            }
                        }
                    }
                }
            }
            return database;
        }

        public async Task<PortScanResult> ScanPortAsync(string ipAddress, int port)
        {
            var result = new PortScanResult
            {
                IPAddress = ipAddress,
                Port = port,
                Protocol = "TCP",
                IsOpen = false,
                Status = "Closed"
            };

            try
            {
                using var client = new TcpClient();
                var timeoutTask = Task.Delay(AppConstants.Scanning.DefaultConnectionTimeoutMs);
                var connectTask = client.ConnectAsync(ipAddress, port);

                if (await Task.WhenAny(connectTask, timeoutTask) == connectTask)
                {
                    try
                    {
                        await connectTask;
                        result.IsOpen = true;
                        result.Status = "Open";

                        if (_serviceDatabase.TryGetValue(port, out string serviceName))
                            result.Service = serviceName;

                        using var cts = new CancellationTokenSource(AppConstants.Scanning.VersionDetectionTimeoutMs);
                        try
                        {
                            string versionInfo = await DetectVersionAsync(client, port, cts.Token);
                            result.Version = string.IsNullOrEmpty(versionInfo) ? "Unknown" : versionInfo;
                        }
                        catch (OperationCanceledException)
                        {
                            result.Version = "Version detection timed out";
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"[PortScannerService.ScanPortAsync] Version detection port={port}: {ex.Message}");
                            result.Version = $"Error detecting version: {ex.Message}";
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PortScannerService.ScanPortAsync] Connect port={port}: {ex.Message}");
                        result.Status = "Closed";
                    }
                }
                else
                {
                    result.Status = "Timeout";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PortScannerService.ScanPortAsync] Outer port={port}: {ex.Message}");
                result.Status = "Closed";
            }

            return result;
        }


        // Static compiled pattern table — built once, reused across all calls.
        private static readonly IReadOnlyDictionary<string, Regex> _versionPatterns =
            new Dictionary<string, string>
            {
                { "ssh",          @"SSH[-\s]+([\d\.]+)" },
                { "ftp",          @"^220[\s-](.*?)(?=\r|\n)" },
                { "smtp",         @"^220[\s-](.*?)(?=\r|\n)" },
                { "pop3",         @"^\+OK[\s-](.*?)(?=\r|\n)" },
                { "imap",         @"^\* OK[\s-](.*?)(?=\r|\n)" },
                { "mysql",        @"(\d+\.\d+\.\d+)" },
                { "telnet",       @"telnetd?\s*([\d\.]+)" },
                { "domain",       @"(BIND|ISC DNS|dnsmasq)[/\s-]*([\d\.]+)" },
                { "http",         @"Server:\s*(.*?)(?=\r|\n)" },
                { "rpcbind",      @"rpcbind.*?([\d\.]+)" },
                { "netbios-ssn",  @"NetBIOS.*?([\d\.]+)" },
                { "microsoft-ds", @"SMB.*?([\d\.]+)" },
                { "biff",         @"biff.*?([\d\.]+)" },
                { "syslog",       @"(rsyslogd|syslog-ng|syslogd)[\s-]*([\d\.]+)" },
                { "who",          @"whoami\s+([\d\.]+)" },
                { "general",      @"(?:version|ver|v)[:\s]+([\d]+(?:\.[\w\-]+)+)" }
            }.ToDictionary(
                kv => kv.Key,
                kv => new Regex(kv.Value, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline));

        private async Task<string> DetectVersionAsync(TcpClient client, int port, CancellationToken cancellationToken)
        {
            try
            {
                using (var stream = client.GetStream())
                {
                    stream.ReadTimeout = AppConstants.Scanning.VersionDetectionTimeoutMs;

                    // Try initial banner grab
                    try
                    {
                        byte[] initialBuffer = new byte[4096];
                        var initialReadTask = stream.ReadAsync(initialBuffer, 0, initialBuffer.Length, cancellationToken);

                        if (await Task.WhenAny(initialReadTask, Task.Delay(1500, cancellationToken)) == initialReadTask)
                        {
                            int bytesRead = await initialReadTask;
                            if (bytesRead > 0)
                            {
                                string initialBanner = Encoding.ASCII.GetString(initialBuffer, 0, bytesRead);
                                Debug.WriteLine($"Initial banner for port {port}: {initialBanner}");

                                foreach (var rx in _versionPatterns.Values)
                                {
                                    var match = rx.Match(initialBanner);
                                    if (match.Success)
                                    {
                                        var version = match.Groups[match.Groups.Count - 1].Value.Trim();
                                        if (!string.IsNullOrWhiteSpace(version))
                                        {
                                            Debug.WriteLine($"Found version from initial banner: {version}");
                                            return version;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Initial banner grab failed for port {port}: {ex.Message}");
                    }

                    // Get and try nmap probes
                    var probesForPort = _probeHandler.GetProbesForPort(port);
                    if (!probesForPort.Any())
                    {
                        probesForPort = _probeHandler.GetGeneralProbes();
                    }

                    foreach (var probe in probesForPort)
                    {
                        try
                        {
                            Debug.WriteLine($"Trying probe {probe.Name} on port {port}");
                            await stream.WriteAsync(probe.ProbeString, 0, probe.ProbeString.Length, cancellationToken);
                            await stream.FlushAsync(cancellationToken);

                            // Allow some time for the service to process the probe
                            await Task.Delay(300, cancellationToken);

                            byte[] buffer = new byte[4096];
                            var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                            if (await Task.WhenAny(readTask, Task.Delay(2500, cancellationToken)) == readTask)
                            {
                                int bytesRead = await readTask;
                                if (bytesRead > 0)
                                {
                                    byte[] response = new byte[bytesRead];
                                    Array.Copy(buffer, response, bytesRead);
                                    string responseStr = Encoding.ASCII.GetString(response);
                                    Debug.WriteLine($"Response from probe {probe.Name}: {responseStr}");

                                    string result = _probeHandler.AnalyzeResponse(response, new List<ServiceProbe> { probe });
                                    if (!string.Equals(result, "Unknown", StringComparison.OrdinalIgnoreCase))
                                    {
                                        Debug.WriteLine($"Found version from probe: {result}");
                                        return result;
                                    }

                                    foreach (var rx in _versionPatterns.Values)
                                    {
                                        var match = rx.Match(responseStr);
                                        if (match.Success)
                                        {
                                            var version = match.Groups[match.Groups.Count - 1].Value.Trim();
                                            if (!string.IsNullOrWhiteSpace(version))
                                            {
                                                Debug.WriteLine($"Found version from pattern: {version}");
                                                return version;
                                            }
                                        }
                                    }

                                    var firstLine = responseStr.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                                               .FirstOrDefault()?.Trim();
                                    if (!string.IsNullOrWhiteSpace(firstLine) &&
                                        firstLine.Length > 5 &&
                                        !firstLine.Contains("Unknown", StringComparison.OrdinalIgnoreCase))
                                    {
                                        Debug.WriteLine($"Using first line as version: {firstLine}");
                                        return firstLine;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Probe {probe.Name} failed: {ex.Message}");
                            continue;
                        }
                    }

                    // Final aggressive probe attempt using port-specific commands
                    try
                    {
                        string probeString = string.Empty;
                        switch (port)
                        {
                            case 21: probeString = "HELP\r\n"; break;       // FTP
                            case 22: probeString = "\r\n"; break;             // SSH
                            case 23: probeString = "?\r\n"; break;             // Telnet – might try a help command
                            case 25: probeString = "EHLO test\r\n"; break;      // SMTP
                            case 80: probeString = "GET / HTTP/1.0\r\n\r\n"; break;  // HTTP
                            case 443: probeString = "GET / HTTP/1.0\r\n\r\n"; break; // HTTPS
                            case 3306: probeString = "\r\n"; break;           // MySQL
                            default: probeString = "\r\n"; break;
                        }

                        if (!string.IsNullOrEmpty(probeString))
                        {
                            byte[] probeBytes = Encoding.ASCII.GetBytes(probeString);
                            await stream.WriteAsync(probeBytes, 0, probeBytes.Length, cancellationToken);
                            await stream.FlushAsync(cancellationToken);

                            // Wait a bit longer for the response in this final attempt
                            byte[] buffer = new byte[4096];
                            var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                            if (await Task.WhenAny(readTask, Task.Delay(3000, cancellationToken)) == readTask)
                            {
                                int bytesRead = await readTask;
                                if (bytesRead > 0)
                                {
                                    string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                    Debug.WriteLine($"Final attempt response: {response}");

                                    foreach (var rx in _versionPatterns.Values)
                                    {
                                        var match = rx.Match(response);
                                        if (match.Success)
                                        {
                                            var version = match.Groups[match.Groups.Count - 1].Value.Trim();
                                            if (!string.IsNullOrWhiteSpace(version))
                                            {
                                                Debug.WriteLine($"Found version in final attempt: {version}");
                                                return version;
                                            }
                                        }
                                    }

                                    var firstLine = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                                            .FirstOrDefault()?.Trim();
                                    if (!string.IsNullOrWhiteSpace(firstLine) &&
                                        firstLine.Length > 5 &&
                                        !firstLine.Contains("Unknown", StringComparison.OrdinalIgnoreCase))
                                    {
                                        Debug.WriteLine($"Using first line as version in final attempt: {firstLine}");
                                        return firstLine;
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Final attempt failed: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Version detection failed: {ex.Message}");
            }

            return "Unknown";
        }





    }

    public class ServiceProbeHandler
    {
        private readonly List<ServiceProbe> _probes = new List<ServiceProbe>();

        // Compiled regex cache shared across all ServiceProbeHandler instances.
        private static readonly ConcurrentDictionary<string, Regex> _patternCache = new();

        private static Regex GetCachedRegex(string pattern) =>
            _patternCache.GetOrAdd(pattern,
                p => new Regex(p, RegexOptions.Compiled | RegexOptions.Multiline));

        public ServiceProbeHandler(string probeFilePath)
        {
            LoadProbes(probeFilePath);
        }
        public List<ServiceProbe> GetGeneralProbes()
        {
            // Return probes that are not port-specific or are marked as general-purpose
            return _probes.Where(p =>
                p.Ports.Count == 0 || // Probes with no specific ports
                p.Name.Contains("NULL") || // NULL probes
                p.Name.Contains("GenericLines") || // Generic probes
                p.Ports.Count > 100 // Probes that work on many ports
            ).ToList();
        }
        private void LoadProbes(string filePath)
        {
            if (!File.Exists(filePath))
                return;

            ServiceProbe currentProbe = null;
            foreach (string line in File.ReadLines(filePath))
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    if (line.StartsWith("Probe"))
                    {
                        currentProbe = ParseProbeDefinition(line);
                        if (currentProbe != null)
                            _probes.Add(currentProbe);
                    }
                    else if (line.StartsWith("match") && currentProbe != null)
                    {
                        var match = ParseMatchLine(line);
                        if (match != null)
                            currentProbe.Matches.Add(match);
                    }
                    else if (line.StartsWith("ports") && currentProbe != null)
                    {
                        ParsePortsLine(line, currentProbe);
                    }
                    else if (line.StartsWith("sslports") && currentProbe != null)
                    {
                        currentProbe.SSLTrigger = true;
                        ParsePortsLine(line, currentProbe);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error parsing line: {line}. Error: {ex.Message}");
                }
            }
        }

        private ServiceProbe ParseProbeDefinition(string line)
        {
            var match = Regex.Match(line, @"Probe\s+(?<protocol>\w+)\s+(?<name>\w+)\s+(?<probe>.+)");
            if (!match.Success)
                return null;

            string probeString = match.Groups["probe"].Value;
            if (probeString.StartsWith("q|") && probeString.EndsWith("|"))
            {
                probeString = probeString.Substring(2, probeString.Length - 3);
            }

            return new ServiceProbe
            {
                Name = match.Groups["name"].Value,
                ProbeString = ParseProbeString(probeString)
            };
        }

        private byte[] ParseProbeString(string probeString)
        {
            var bytes = new List<byte>();
            for (int i = 0; i < probeString.Length; i++)
            {
                if (probeString[i] == '\\' && i + 1 < probeString.Length)
                {
                    switch (probeString[i + 1])
                    {
                        case 'r': bytes.Add(13); break;
                        case 'n': bytes.Add(10); break;
                        case 't': bytes.Add(9); break;
                        case '0': bytes.Add(0); break;
                        default: bytes.Add((byte)probeString[i + 1]); break;
                    }
                    i++;
                }
                else
                {
                    bytes.Add((byte)probeString[i]);
                }
            }
            return bytes.ToArray();
        }

        private MatchPattern ParseMatchLine(string line)
        {
            var match = Regex.Match(line, @"match\s+(?<service>\w+)\s+(?<pattern>m\|.+?\|)(?<version>.*)");
            if (!match.Success)
                return null;

            string pattern = match.Groups["pattern"].Value;
            if (pattern.StartsWith("m|") && pattern.EndsWith("|"))
            {
                pattern = pattern.Substring(2, pattern.Length - 3);
            }

            return new MatchPattern
            {
                Pattern = pattern,
                ServiceName = match.Groups["service"].Value,
                VersionInfo = match.Groups["version"].Value
            };
        }

        private void ParsePortsLine(string line, ServiceProbe probe)
        {
            var portsPart = line.Split(new[] { ' ' }, 2)[1];
            foreach (var portRange in portsPart.Split(','))
            {
                if (portRange.Contains("-"))
                {
                    var range = portRange.Split('-');
                    if (int.TryParse(range[0], out int start) && int.TryParse(range[1], out int end))
                    {
                        probe.Ports.AddRange(Enumerable.Range(start, end - start + 1));
                    }
                }
                else if (int.TryParse(portRange, out int port))
                {
                    probe.Ports.Add(port);
                }
            }
        }

        public List<ServiceProbe> GetProbesForPort(int port)
        {
            return _probes.Where(p => p.Ports.Contains(port)).ToList();
        }

        public string AnalyzeResponse(byte[] response, List<ServiceProbe> probes)
        {
            string responseStr = System.Text.Encoding.ASCII.GetString(response);

            foreach (var probe in probes)
            {
                foreach (var matchPattern in probe.Matches)
                {
                    try
                    {
                        var regex = GetCachedRegex(matchPattern.Pattern);
                        var match = regex.Match(responseStr);

                        if (match.Success)
                        {
                            string version = matchPattern.VersionInfo;
                            foreach (var groupName in regex.GetGroupNames())
                            {
                                version = version.Replace($"${groupName}", match.Groups[groupName].Value);
                            }

                            return $"{matchPattern.ServiceName} {version}".Trim();
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }

            return "Unknown";
        }
    }
}
