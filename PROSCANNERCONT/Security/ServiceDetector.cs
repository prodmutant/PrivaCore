using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;

namespace PROSCANNERCONT.Security
{
    public class ServiceDetector
    {
        private readonly Dictionary<int, ServiceInfo> _serviceDb;
        private readonly List<ServiceProbe> _probes;

        private static readonly string NMAPDB_DIR = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "Resources",
            "NmapDB"
        );

        private static readonly string SERVICES_FILE = Path.Combine(NMAPDB_DIR, "nmap-services");
        private static readonly string PROBES_FILE = Path.Combine(NMAPDB_DIR, "nmap-service-probes");

        private const string NMAP_SERVICES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services";
        private const string NMAP_PROBES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes";

        public class ServiceInfo
        {
            public string Name { get; set; } = string.Empty;
            public string Frequency { get; set; } = string.Empty;
            public string Protocol { get; set; } = string.Empty;
        }

        public class ServiceProbe
        {
            public string ProbeName { get; set; } = string.Empty;
            public string ProbeString { get; set; } = string.Empty;
            public List<string> Matches { get; set; } = new List<string>();
            public int Rarity { get; set; }
            public int TotalWaitMS { get; set; }
        }

        public ServiceDetector()
        {
            // Ensure files exist before loading
            EnsureResourcesExistAsync().GetAwaiter().GetResult();

            _serviceDb = LoadNmapServices();
            _probes = LoadServiceProbes();

            Console.WriteLine($"✅ ServiceDetector initialized with {_serviceDb.Count} services and {_probes.Count} probes");
        }

        /// <summary>
        /// Ensures all required nmap database files exist, downloading if necessary
        /// </summary>
        private async Task EnsureResourcesExistAsync()
        {
            try
            {
                // Create directories if they don't exist
                if (!Directory.Exists(NMAPDB_DIR))
                {
                    Console.WriteLine($"📁 Creating NmapDB directory: {NMAPDB_DIR}");
                    Directory.CreateDirectory(NMAPDB_DIR);
                }

                // Check and download nmap-services
                await EnsureFileExists(SERVICES_FILE, NMAP_SERVICES_URL, "nmap-services");

                // Check and download nmap-service-probes
                await EnsureFileExists(PROBES_FILE, NMAP_PROBES_URL, "nmap-service-probes");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Warning: Could not ensure resources exist: {ex.Message}");
                // Don't throw - allow the system to work with whatever files are available
            }
        }

        /// <summary>
        /// Checks if a file exists and downloads it if missing
        /// </summary>
        private async Task EnsureFileExists(string filePath, string url, string fileName)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"⚠️ {fileName} not found, downloading...");
                await DownloadFile(url, filePath, fileName);
            }
            else
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length < 1000)
                {
                    Console.WriteLine($"⚠️ {fileName} appears corrupted, re-downloading...");
                    File.Delete(filePath);
                    await DownloadFile(url, filePath, fileName);
                }
                else
                {
                    Console.WriteLine($"✅ {fileName} exists ({FormatFileSize(fileInfo.Length)})");
                }
            }
        }

        /// <summary>
        /// Downloads a file from URL
        /// </summary>
        private async Task DownloadFile(string url, string destinationPath, string fileName)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromMinutes(2);
                    Console.WriteLine($"📥 Downloading {fileName} from GitHub...");

                    var response = await client.GetAsync(url);
                    response.EnsureSuccessStatusCode();

                    var content = await response.Content.ReadAsByteArrayAsync();
                    await File.WriteAllBytesAsync(destinationPath, content);

                    var fileInfo = new FileInfo(destinationPath);
                    Console.WriteLine($"✅ {fileName} downloaded successfully ({FormatFileSize(fileInfo.Length)})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Failed to download {fileName}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Formats file size for display
        /// </summary>
        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        private Dictionary<int, ServiceInfo> LoadNmapServices()
        {
            var services = new Dictionary<int, ServiceInfo>();

            if (!File.Exists(SERVICES_FILE))
            {
                Console.WriteLine($"⚠️ Warning: {SERVICES_FILE} not found. Service detection will be limited.");
                return services;
            }

            try
            {
                string[] lines = File.ReadAllLines(SERVICES_FILE);
                int loadedCount = 0;

                foreach (string line in lines)
                {
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                        continue;

                    string[] parts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 3)
                    {
                        string[] portProtoParts = parts[1].Split('/');
                        if (portProtoParts.Length == 2 && int.TryParse(portProtoParts[0], out int port))
                        {
                            if (!services.ContainsKey(port))
                            {
                                services[port] = new ServiceInfo
                                {
                                    Name = parts[0],
                                    Protocol = portProtoParts[1],
                                    Frequency = parts[2]
                                };
                                loadedCount++;
                            }
                        }
                    }
                }

                Console.WriteLine($"📊 Loaded {loadedCount} services from nmap-services");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error loading nmap-services: {ex.Message}");
            }

            return services;
        }

        private List<ServiceProbe> LoadServiceProbes()
        {
            var probes = new List<ServiceProbe>();

            if (!File.Exists(PROBES_FILE))
            {
                Console.WriteLine($"⚠️ Warning: {PROBES_FILE} not found. Advanced service detection will be limited.");
                return probes;
            }

            try
            {
                string[] lines = File.ReadAllLines(PROBES_FILE);
                ServiceProbe? currentProbe = null;
                int probeCount = 0;

                foreach (string line in lines)
                {
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                        continue;

                    if (line.StartsWith("Probe"))
                    {
                        if (currentProbe != null)
                        {
                            probes.Add(currentProbe);
                            probeCount++;
                        }

                        string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 1)
                        {
                            currentProbe = new ServiceProbe
                            {
                                ProbeName = parts[1],
                                ProbeString = parts.Length > 2 ? string.Join(" ", parts.Skip(2)) : "",
                                Matches = new List<string>(),
                                Rarity = 1,
                                TotalWaitMS = 5000
                            };
                        }
                    }
                    else if (line.StartsWith("match") && currentProbe != null)
                    {
                        currentProbe.Matches.Add(line);
                    }
                    else if (line.StartsWith("rarity") && currentProbe != null)
                    {
                        string[] parts = line.Split(' ');
                        if (parts.Length > 1 && int.TryParse(parts[1], out int rarity))
                            currentProbe.Rarity = rarity;
                    }
                    else if (line.StartsWith("totalwaitms") && currentProbe != null)
                    {
                        string[] parts = line.Split(' ');
                        if (parts.Length > 1 && int.TryParse(parts[1], out int wait))
                            currentProbe.TotalWaitMS = wait;
                    }
                }

                if (currentProbe != null)
                {
                    probes.Add(currentProbe);
                    probeCount++;
                }

                Console.WriteLine($"📊 Loaded {probeCount} service probes from nmap-service-probes");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error loading nmap-service-probes: {ex.Message}");
            }

            return probes;
        }

        public async Task<(string ServiceName, string Version)> DetectService(string host, int port)
        {
            // First, try to get service name from port database
            string baseServiceName = "unknown";
            if (_serviceDb.TryGetValue(port, out ServiceInfo? serviceInfo))
            {
                baseServiceName = serviceInfo.Name;
            }

            // If we have no probes, return basic info
            if (_probes.Count == 0)
            {
                return (baseServiceName, "Unknown");
            }

            // Try probes in order of rarity
            foreach (var probe in _probes.OrderBy(p => p.Rarity))
            {
                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(host, port);
                    var timeoutTask = Task.Delay(probe.TotalWaitMS);

                    if (await Task.WhenAny(connectTask, timeoutTask) == timeoutTask)
                    {
                        continue; // Timeout occurred
                    }

                    if (!client.Connected)
                        continue;

                    using var stream = client.GetStream();

                    // Send probe
                    if (!string.IsNullOrEmpty(probe.ProbeString))
                    {
                        byte[] probeBytes = Encoding.ASCII.GetBytes(probe.ProbeString);
                        await stream.WriteAsync(probeBytes);
                    }

                    // Read response
                    byte[] buffer = new byte[2048];
                    stream.ReadTimeout = probe.TotalWaitMS;

                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
                    var readTimeoutTask = Task.Delay(probe.TotalWaitMS);

                    if (await Task.WhenAny(readTask, readTimeoutTask) == readTimeoutTask)
                    {
                        continue;
                    }

                    int bytesRead = await readTask;
                    if (bytesRead == 0)
                        continue;

                    string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    // Check matches
                    foreach (string match in probe.Matches)
                    {
                        if (response.Contains(match.Replace("match ", "")))
                        {
                            var versionMatch = Regex.Match(response, @"version[:\s]+([^\s\r\n]+)", RegexOptions.IgnoreCase);
                            if (versionMatch.Success)
                            {
                                return (baseServiceName != "unknown" ? baseServiceName : probe.ProbeName,
                                       versionMatch.Groups[1].Value);
                            }

                            return (baseServiceName != "unknown" ? baseServiceName : probe.ProbeName,
                                   "Detected");
                        }
                    }
                }
                catch
                {
                    continue;
                }
            }

            return (baseServiceName, "Unknown");
        }
    }
}