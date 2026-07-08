using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    /// <summary>
    /// Detector for database services (MySQL, PostgreSQL, MSSQL, etc.)
    /// </summary>
    public class DatabaseDetector : IServiceDetector
    {
        public string ServiceName => "Database";

        public int[] CommonPorts => new[] {
            1433,  // MSSQL
            3306,  // MySQL
            5432,  // PostgreSQL
            1521,  // Oracle
            27017, // MongoDB
            6379,  // Redis
            9042,  // Cassandra
            8086   // InfluxDB
        };

        public int Priority => 40;

        // Dictionary mapping ports to database types
        private readonly Dictionary<int, string> _portToDbMap = new Dictionary<int, string>
        {
            { 1433, "MSSQL" },
            { 3306, "MySQL" },
            { 5432, "PostgreSQL" },
            { 1521, "Oracle" },
            { 27017, "MongoDB" },
            { 6379, "Redis" },
            { 9042, "Cassandra" },
            { 8086, "InfluxDB" }
        };

        // Specific protocol handlers for different database types
        private readonly Dictionary<string, Func<string, int, int, CancellationToken, Task<string>>> _dbDetectors =
            new Dictionary<string, Func<string, int, int, CancellationToken, Task<string>>>(StringComparer.OrdinalIgnoreCase);

        public DatabaseDetector()
        {
            // Register handlers for specific database types
            _dbDetectors["MySQL"] = DetectMySQLVersionAsync;
            _dbDetectors["PostgreSQL"] = DetectPostgreSQLVersionAsync;
            _dbDetectors["Redis"] = DetectRedisVersionAsync;
            _dbDetectors["MongoDB"] = DetectMongoDBVersionAsync;
            // Add more as needed
        }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check if it's a known database port
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            // Check if the service has already been identified as a database
            bool isDbService = !string.IsNullOrEmpty(initialScan.Service) &&
                (initialScan.Service.Contains("SQL", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("MySQL", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("MSSQL", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("Oracle", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("MongoDB", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("Redis", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("Cassandra", StringComparison.OrdinalIgnoreCase) ||
                 initialScan.Service.Contains("InfluxDB", StringComparison.OrdinalIgnoreCase));

            return isCommonPort || isDbService;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            try
            {
                // Try to determine database type from port
                string dbType = null;
                if (_portToDbMap.TryGetValue(result.Port, out string mappedDbType))
                {
                    dbType = mappedDbType;
                    result.Service = dbType;
                }
                else if (!string.IsNullOrEmpty(result.Service))
                {
                    // Use service from initial scan if available
                    dbType = result.Service;
                }
                else
                {
                    // Default to generic database
                    dbType = "Database";
                    result.Service = dbType;
                }

                // Check if we have a specific detector for this database type
                if (_dbDetectors.TryGetValue(dbType, out var detectorFunc))
                {
                    string version = await detectorFunc(result.IPAddress, result.Port, timeout, cancellationToken);

                    if (!string.IsNullOrEmpty(version))
                    {
                        result.Version = version;
                    }
                    else
                    {
                        result.Version = $"{dbType} (version unknown)";
                    }
                }
                else
                {
                    // Try generic banner grabbing
                    string banner = await BannerGrabber.GrabBannerAsync(
                        result.IPAddress,
                        result.Port,
                        timeout,
                        cancellationToken);

                    if (!string.IsNullOrEmpty(banner))
                    {
                        var versionRegex = new Regex(@"(?:version|ver)[:\s]+(\d+(?:\.\d+)+)", RegexOptions.IgnoreCase);
                        var match = versionRegex.Match(banner);

                        if (match.Success)
                        {
                            result.Version = $"{dbType} {match.Groups[1].Value}";
                        }
                        else
                        {
                            result.Version = BannerGrabber.GetFirstLine(banner);
                        }
                    }
                    else
                    {
                        result.Version = $"{dbType} (no banner)";
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database detection error: {ex.Message}");
                if (string.IsNullOrEmpty(result.Service))
                {
                    result.Service = "Database";
                }

                result.Version = $"{result.Service} (detection error)";
            }

            return result;
        }

        /// <summary>
        /// Detects MySQL version by connecting and parsing the handshake packet
        /// </summary>
        private async Task<string> DetectMySQLVersionAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        return null; // Connection timeout
                    }

                    using (var stream = client.GetStream())
                    {
                        // MySQL sends a handshake packet on connection
                        byte[] buffer = new byte[1024];
                        var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                        if (await Task.WhenAny(readTask, Task.Delay(timeout, cancellationToken)) != readTask)
                        {
                            return null; // Read timeout
                        }

                        int bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            // Parse MySQL handshake packet
                            // Format: [4-byte header][1-byte protocol][string version]...
                            if (bytesRead > 5)
                            {
                                // Skip the first 5 bytes (4-byte header + 1-byte protocol)
                                int versionEnd = 5;
                                while (versionEnd < bytesRead && buffer[versionEnd] != 0)
                                {
                                    versionEnd++;
                                }

                                if (versionEnd > 5)
                                {
                                    string version = Encoding.ASCII.GetString(buffer, 5, versionEnd - 5);
                                    return $"MySQL {version}";
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MySQL detection error: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Detects PostgreSQL version by sending a startup message and parsing the response
        /// </summary>
        private async Task<string> DetectPostgreSQLVersionAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        return null; // Connection timeout
                    }

                    using (var stream = client.GetStream())
                    {
                        // Send PostgreSQL startup message 
                        // Format: [length][protocol version][user\0][database\0][params]
                        byte[] startupMessage = new byte[] {
                            0, 0, 0, 8,  // Message length (8 bytes)
                            0, 3, 0, 0   // Protocol version (3.0)
                        };

                        await stream.WriteAsync(startupMessage, 0, startupMessage.Length, cancellationToken);

                        // Read response
                        byte[] buffer = new byte[1024];
                        var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                        if (await Task.WhenAny(readTask, Task.Delay(timeout, cancellationToken)) != readTask)
                        {
                            return null; // Read timeout
                        }

                        int bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            // Convert to string and look for version info
                            string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            var versionRegex = new Regex(@"PostgreSQL\s*([\d\.]+)", RegexOptions.IgnoreCase);
                            var match = versionRegex.Match(response);

                            if (match.Success)
                            {
                                return $"PostgreSQL {match.Groups[1].Value}";
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PostgreSQL detection error: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Detects Redis version by sending the INFO command
        /// </summary>
        private async Task<string> DetectRedisVersionAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                // Redis responds to the INFO command with server information
                byte[] infoCommand = Encoding.ASCII.GetBytes("INFO\r\n");

                string infoResponse = await BannerGrabber.GrabBannerWithTriggerAsync(
                    ipAddress,
                    port,
                    infoCommand,
                    timeout,
                    cancellationToken);

                if (!string.IsNullOrEmpty(infoResponse))
                {
                    // Parse Redis INFO response
                    var versionRegex = new Regex(@"redis_version:([\d\.]+)", RegexOptions.IgnoreCase);
                    var match = versionRegex.Match(infoResponse);

                    if (match.Success)
                    {
                        return $"Redis {match.Groups[1].Value}";
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Redis detection error: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Detects MongoDB version by trying a simple ismaster command
        /// </summary>
        private async Task<string> DetectMongoDBVersionAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        return null; // Connection timeout
                    }

                    // MongoDB wire protocol is binary, but we don't need to implement the full protocol
                    // Just checking if it accepts connections is often enough
                    return "MongoDB";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MongoDB detection error: {ex.Message}");
            }

            return null;
        }
    }
}