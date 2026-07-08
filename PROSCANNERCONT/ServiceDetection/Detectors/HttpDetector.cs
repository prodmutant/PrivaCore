using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class HttpDetector : IServiceDetector
    {
        public string ServiceName => "HTTP";
        public int[] CommonPorts => new[] { 80, 443, 8080, 8443 };
        public int Priority => 10;

        private readonly ILogger<HttpDetector> _logger;

        public HttpDetector(ILogger<HttpDetector> logger)
        {
            _logger = logger;
        }

        public HttpDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check common HTTP ports
            foreach (int p in CommonPorts)
            {
                if (port == p) return true;
            }

            // Check if service contains HTTP keywords
            if (!string.IsNullOrEmpty(initialScan.Service))
            {
                string service = initialScan.Service.ToLower();
                return service.Contains("http") || service.Contains("web");
            }

            return false;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            // Track what we receive (if using the debugging system)
            result.Track("HTTP Detector Started");

            // Set defaults
            result.SetService(result.Port == 443 || result.Port == 8443 ? "HTTPS" : "HTTP");
            result.SetVersion("Unknown");
            result.Protocol = result.Port == 443 || result.Port == 8443 ? "HTTPS" : "HTTP";

            try
            {
                // Send HTTP HEAD request to get server information
                var trigger = Encoding.ASCII.GetBytes("HEAD / HTTP/1.1\r\nHost: " + result.IPAddress + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
                string banner = await BannerGrabber.GrabBannerWithTriggerAsync(
                    result.IPAddress, result.Port, trigger, timeout, cancellationToken);

                _logger?.LogInformation($"HTTP Banner received: {banner}");

                if (!string.IsNullOrEmpty(banner))
                {
                    result.RawBanner = banner;
                    ParseHttpResponse(banner, result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "HTTP detection error");
            }

            // Track what we're returning
            result.Track("HTTP Detector Finished");
            return result;
        }

        private void ParseHttpResponse(string response, PortScanResult result)
        {
            if (string.IsNullOrEmpty(response)) return;

            try
            {
                // First, look for Server header which contains the web server info
                var serverHeaderMatch = Regex.Match(response, @"(?i)^Server:\s*(.+)$", RegexOptions.Multiline);

                if (serverHeaderMatch.Success)
                {
                    string serverInfo = serverHeaderMatch.Groups[1].Value.Trim();
                    _logger?.LogInformation($"Found Server header: {serverInfo}");
                    ParseServerHeader(serverInfo, result);
                }
                else
                {
                    // Server header is hidden - check for alternative headers
                    _logger?.LogInformation("Server header not found, checking alternatives...");

                    // Check X-Powered-By (alternative source)
                    var poweredByMatch = Regex.Match(response, @"(?i)^X-Powered-By:\s*(.+)$", RegexOptions.Multiline);
                    if (poweredByMatch.Success)
                    {
                        string poweredBy = poweredByMatch.Groups[1].Value.Trim();
                        _logger?.LogInformation($"Found X-Powered-By: {poweredBy}");
                        ParsePoweredByHeader(poweredBy, result);
                    }
                    else
                    {
                        // Check for other identifying headers
                        DetectServerFromHeaders(response, result);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing HTTP response");
            }
        }

        private void ParseServerHeader(string serverHeader, PortScanResult result)
        {
            // Examples to handle:
            // "Apache/2.2.8 (Ubuntu) DAV/2"
            // "nginx/1.18.0"
            // "Microsoft-IIS/10.0"
            // "lighttpd/1.4.59"

            try
            {
                // Apache patterns
                var apacheMatch = Regex.Match(serverHeader, @"Apache/([\d\.]+)", RegexOptions.IgnoreCase);
                if (apacheMatch.Success)
                {
                    result.SetService("Apache HTTP Server");
                    result.SetVersion(apacheMatch.Groups[1].Value);
                    return;
                }

                // Nginx patterns
                var nginxMatch = Regex.Match(serverHeader, @"nginx/([\d\.]+)", RegexOptions.IgnoreCase);
                if (nginxMatch.Success)
                {
                    result.SetService("nginx");
                    result.SetVersion(nginxMatch.Groups[1].Value);
                    return;
                }

                // Microsoft IIS patterns
                var iisMatch = Regex.Match(serverHeader, @"Microsoft-IIS/([\d\.]+)", RegexOptions.IgnoreCase);
                if (iisMatch.Success)
                {
                    result.SetService("Microsoft IIS");
                    result.SetVersion(iisMatch.Groups[1].Value);
                    return;
                }

                // Lighttpd patterns
                var lighttpdMatch = Regex.Match(serverHeader, @"lighttpd/([\d\.]+)", RegexOptions.IgnoreCase);
                if (lighttpdMatch.Success)
                {
                    result.SetService("lighttpd");
                    result.SetVersion(lighttpdMatch.Groups[1].Value);
                    return;
                }

                // Tomcat patterns
                var tomcatMatch = Regex.Match(serverHeader, @"Apache-Coyote/([\d\.]+)", RegexOptions.IgnoreCase);
                if (tomcatMatch.Success)
                {
                    result.SetService("Apache Tomcat");
                    result.SetVersion(tomcatMatch.Groups[1].Value);
                    return;
                }

                // Generic server with version pattern
                var genericMatch = Regex.Match(serverHeader, @"([^/\s]+)/([\d\.]+)", RegexOptions.IgnoreCase);
                if (genericMatch.Success)
                {
                    string serverName = genericMatch.Groups[1].Value;
                    string version = genericMatch.Groups[2].Value;

                    result.SetService(NormalizeServerName(serverName));
                    result.SetVersion(version);
                    return;
                }

                // If no version found, just use the server name
                var serverNameMatch = Regex.Match(serverHeader, @"^([^/\s\(]+)", RegexOptions.IgnoreCase);
                if (serverNameMatch.Success)
                {
                    result.SetService(NormalizeServerName(serverNameMatch.Groups[1].Value));
                    result.SetVersion("Version Hidden");
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing server header");
            }
        }

        private void ParsePoweredByHeader(string poweredBy, PortScanResult result)
        {
            // Examples:
            // "PHP/7.4.3"
            // "ASP.NET"
            // "Express"

            try
            {
                // PHP patterns
                var phpMatch = Regex.Match(poweredBy, @"PHP/([\d\.]+)", RegexOptions.IgnoreCase);
                if (phpMatch.Success)
                {
                    result.SetService("HTTP (PHP)");
                    result.SetVersion($"PHP {phpMatch.Groups[1].Value}");
                    return;
                }

                // ASP.NET patterns
                if (poweredBy.Contains("ASP.NET", StringComparison.OrdinalIgnoreCase))
                {
                    var aspMatch = Regex.Match(poweredBy, @"ASP\.NET\s+([\d\.]+)?");
                    if (aspMatch.Success && aspMatch.Groups[1].Success)
                    {
                        result.SetService("HTTP (ASP.NET)");
                        result.SetVersion($"ASP.NET {aspMatch.Groups[1].Value}");
                    }
                    else
                    {
                        result.SetService("HTTP (ASP.NET)");
                        result.SetVersion("ASP.NET (version hidden)");
                    }
                    return;
                }

                // Express.js patterns
                if (poweredBy.Contains("Express", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("HTTP (Express.js)");
                    result.SetVersion("Express.js");
                    return;
                }

                // Generic powered by
                result.SetService("HTTP");
                result.SetVersion($"Powered by {poweredBy}");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing X-Powered-By header");
            }
        }

        private void DetectServerFromHeaders(string response, PortScanResult result)
        {
            // Look for identifying headers when Server header is hidden
            try
            {
                // Check for Cloudflare
                if (response.Contains("cf-ray:", StringComparison.OrdinalIgnoreCase) ||
                    response.Contains("CF-RAY:", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("HTTP (Cloudflare CDN)");
                    result.SetVersion("Behind Cloudflare");
                    _logger?.LogInformation("Detected Cloudflare CDN");
                    return;
                }

                // Check for AWS CloudFront
                if (response.Contains("X-Amz-Cf-Id:", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("HTTP (AWS CloudFront)");
                    result.SetVersion("Behind CloudFront");
                    _logger?.LogInformation("Detected AWS CloudFront");
                    return;
                }

                // Check for Akamai
                if (response.Contains("X-Akamai", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("HTTP (Akamai CDN)");
                    result.SetVersion("Behind Akamai");
                    _logger?.LogInformation("Detected Akamai CDN");
                    return;
                }

                // Check for ASP.NET (from headers)
                if (response.Contains("X-AspNet-Version:", StringComparison.OrdinalIgnoreCase) ||
                    response.Contains("X-AspNetMvc-Version:", StringComparison.OrdinalIgnoreCase))
                {
                    var aspNetMatch = Regex.Match(response, @"X-AspNet-Version:\s*([\d\.]+)", RegexOptions.IgnoreCase);
                    if (aspNetMatch.Success)
                    {
                        result.SetService("HTTP (ASP.NET)");
                        result.SetVersion($"ASP.NET {aspNetMatch.Groups[1].Value}");
                    }
                    else
                    {
                        result.SetService("HTTP (ASP.NET)");
                        result.SetVersion("ASP.NET (version hidden)");
                    }
                    _logger?.LogInformation("Detected ASP.NET from headers");
                    return;
                }

                // Check HTTP response line for protocol version (last resort)
                var httpVersionMatch = Regex.Match(response, @"^HTTP/([\d\.]+)\s+(\d+)", RegexOptions.Multiline);
                if (httpVersionMatch.Success)
                {
                    string httpVersion = httpVersionMatch.Groups[1].Value;
                    string statusCode = httpVersionMatch.Groups[2].Value;

                    // Don't set "HTTP/1.1" as version - it's misleading
                    // Instead, indicate that server identity is hidden
                    result.SetService("HTTP");
                    result.SetVersion($"Server Identity Hidden (HTTP/{httpVersion})");

                    _logger?.LogInformation($"Server header hidden. HTTP/{httpVersion} with status {statusCode}");
                    return;
                }

                // Absolute fallback
                result.SetVersion("Server Identity Hidden");
                _logger?.LogInformation("Could not determine server identity - headers are hidden");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error detecting server from headers");
            }
        }

        private string NormalizeServerName(string serverName)
        {
            if (string.IsNullOrEmpty(serverName)) return "HTTP";
            var normalized = serverName.ToLowerInvariant().Trim();
            return normalized switch
            {
                "apache"           => "Apache HTTP Server",
                "nginx"            => "nginx",
                "microsoft-iis" or "iis" => "Microsoft IIS",
                "lighttpd"         => "lighttpd",
                "tomcat"           => "Apache Tomcat",
                "jetty"            => "Eclipse Jetty",
                "weblogic"         => "Oracle WebLogic Server",
                "websphere"        => "IBM WebSphere Application Server",
                _                  => serverName
            };
        }

        // ── Static convenience method for Service_Handler facade ──────────────

        public static async Task<string> DetectVersionAsync(string ipAddress, int port, CancellationToken ct = default)
        {
            try
            {
                var stub = new PROSCANNERCONT.Models.PortScanResult { IPAddress = ipAddress, Port = port };
                var detector = new HttpDetector();
                var result = await detector.DetectAsync(stub, 3000, ct);
                return string.IsNullOrEmpty(result.Version) ? "HTTP Server (Unknown Version)" : $"{result.Service} {result.Version}".Trim();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HttpDetector.DetectVersionAsync] {ex.Message}");
                return "HTTP Server (Detection Failed)";
            }
        }
    }
}