using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace PROSCANNERCONT.PortScanProtocols
{
    public class ServiceDetection
    {
        private static readonly Dictionary<int, ServiceInfo> _services = new Dictionary<int, ServiceInfo>();
        private static bool _isInitialized = false;
        private static readonly object _lock = new object();

        private static readonly string RESOURCES_DIR = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "Resources"
        );

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
            public string Name { get; set; }
            public string Protocol { get; set; }
            public double Frequency { get; set; }
            public string Description { get; set; }
        }

        /// <summary>
        /// Synchronous initialization (for backward compatibility)
        /// </summary>
        public static void Initialize()
        {
            InitializeAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Asynchronous initialization - RECOMMENDED
        /// </summary>
        public static async Task InitializeAsync()
        {
            // Thread-safe check
            lock (_lock)
            {
                if (_isInitialized)
                {
                    Console.WriteLine("✅ Service Detection already initialized");
                    return;
                }
            }

            try
            {
                Console.WriteLine("🔧 Initializing Service Detection...");

                // Step 1: Ensure directories exist
                EnsureDirectoriesExist();

                // Step 2: Check and download required files (async)
                await EnsureRequiredFilesExist();

                // Step 3: Load services
                LoadServices(SERVICES_FILE);

                lock (_lock)
                {
                    _isInitialized = true;
                }

                Console.WriteLine($"✅ Service Detection initialized with {_services.Count} services");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Failed to initialize service detection: {ex.Message}");
                // Don't throw - allow app to continue with limited functionality
            }
        }

        private static void EnsureDirectoriesExist()
        {
            try
            {
                if (!Directory.Exists(RESOURCES_DIR))
                {
                    Console.WriteLine($"📁 Creating Resources directory: {RESOURCES_DIR}");
                    Directory.CreateDirectory(RESOURCES_DIR);
                }

                if (!Directory.Exists(NMAPDB_DIR))
                {
                    Console.WriteLine($"📁 Creating NmapDB directory: {NMAPDB_DIR}");
                    Directory.CreateDirectory(NMAPDB_DIR);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to create directories: {ex.Message}", ex);
            }
        }

        private static async Task EnsureRequiredFilesExist()
        {
            var filesToCheck = new[]
            {
                (SERVICES_FILE, NMAP_SERVICES_URL, "nmap-services"),
                (PROBES_FILE, NMAP_PROBES_URL, "nmap-service-probes")
            };

            foreach (var (filePath, url, fileName) in filesToCheck)
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
        }

        private static async Task DownloadFile(string url, string destinationPath, string fileName)
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
            catch (HttpRequestException ex)
            {
                throw new Exception($"Failed to download {fileName}: Network error - {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to download {fileName}: {ex.Message}", ex);
            }
        }

        private static string FormatFileSize(long bytes)
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

        public static void LoadServices(string filePath)
        {
            try
            {
                lock (_lock)
                {
                    _services.Clear();
                }

                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"⚠️ Services file not found: {filePath}");
                    return;
                }

                var linesProcessed = 0;
                var servicesLoaded = 0;

                foreach (string line in File.ReadLines(filePath))
                {
                    linesProcessed++;

                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    var parts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                    if (parts.Length >= 3)
                    {
                        string serviceName = parts[0];
                        string[] portProtocol = parts[1].Split('/');

                        if (portProtocol.Length == 2 && int.TryParse(portProtocol[0], out int port))
                        {
                            double.TryParse(parts[2], out double frequency);

                            var serviceInfo = new ServiceInfo
                            {
                                Name = serviceName,
                                Protocol = portProtocol[1].ToUpper(),
                                Frequency = frequency,
                                Description = parts.Length > 3 ? string.Join(" ", parts.Skip(3)) : ""
                            };

                            lock (_lock)
                            {
                                if (!_services.ContainsKey(port))
                                {
                                    _services.Add(port, serviceInfo);
                                    servicesLoaded++;
                                }
                            }
                        }
                    }
                }

                Console.WriteLine($"📊 Processed {linesProcessed} lines, loaded {servicesLoaded} services");
            }
            catch (Exception ex)
            {
                throw new Exception($"Error loading services file: {ex.Message}", ex);
            }
        }

        public static ServiceInfo GetService(int port, string protocol = "tcp")
        {
            lock (_lock)
            {
                if (_services.Count == 0 && !_isInitialized)
                {
                    Console.WriteLine("⚠️ Service detection not initialized, attempting lazy initialization...");
                    Initialize();
                }

                if (_services.TryGetValue(port, out ServiceInfo service) &&
                    service.Protocol.Equals(protocol, StringComparison.OrdinalIgnoreCase))
                {
                    return service;
                }

                return new ServiceInfo
                {
                    Name = "unknown",
                    Protocol = protocol.ToUpper(),
                    Frequency = 0,
                    Description = ""
                };
            }
        }

        public static bool IsInitialized
        {
            get
            {
                lock (_lock)
                {
                    return _isInitialized;
                }
            }
        }

        public static int ServiceCount
        {
            get
            {
                lock (_lock)
                {
                    return _services.Count;
                }
            }
        }

        public static async Task<bool> ValidateAndRepairAsync()
        {
            try
            {
                Console.WriteLine("🔍 Validating service detection files...");

                EnsureDirectoriesExist();
                await EnsureRequiredFilesExist();

                lock (_lock)
                {
                    if (!_isInitialized || _services.Count == 0)
                    {
                        LoadServices(SERVICES_FILE);
                        _isInitialized = true;
                    }
                }

                Console.WriteLine("✅ Validation complete");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Validation failed: {ex.Message}");
                return false;
            }
        }

        public static void Reinitialize()
        {
            lock (_lock)
            {
                _services.Clear();
                _isInitialized = false;
            }
            Initialize();
        }
    }
}