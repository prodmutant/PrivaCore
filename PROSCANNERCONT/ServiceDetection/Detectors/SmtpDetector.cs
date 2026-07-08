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
    public class SmtpDetector : IServiceDetector
    {
        public string ServiceName => "SMTP";
        public int[] CommonPorts => new[] { 25, 587, 465, 2525 };
        public int Priority => 35;

        private readonly ILogger<SmtpDetector> _logger;

        public SmtpDetector(ILogger<SmtpDetector> logger)
        {
            _logger = logger;
        }

        public SmtpDetector() : this(null) { }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check common ports
            foreach (int p in CommonPorts)
            {
                if (port == p) return true;
            }

            // Check service keywords
            if (!string.IsNullOrEmpty(initialScan.Service))
            {
                string service = initialScan.Service.ToLower();
                return service.Contains("smtp") || service.Contains("mail");
            }

            return false;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            result.Track("SMTP Detector Started");

            // Set defaults
            result.SetService("SMTP");
            result.SetVersion("Unknown");
            result.Protocol = DetermineProtocol(result.Port);

            try
            {
                // Phase 1: Get initial banner (220 greeting)
                string banner = await BannerGrabber.GrabBannerAsync(
                    result.IPAddress, result.Port, timeout, cancellationToken);

                _logger?.LogInformation($"SMTP Banner: {banner}");

                if (!string.IsNullOrEmpty(banner))
                {
                    result.RawBanner = banner;

                    // Try to parse the initial banner
                    if (!ParseSmtpBanner(banner, result))
                    {
                        // Phase 2: Send EHLO to get more info
                        await EnhanceWithEhlo(result, timeout, cancellationToken);
                    }
                }
                else
                {
                    // No banner - try EHLO anyway
                    await EnhanceWithEhlo(result, timeout, cancellationToken);
                }

                // Add security warnings
                AddSecurityAssessment(result);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "SMTP detection error");
            }

            result.Track("SMTP Detector Finished");
            return result;
        }

        private string DetermineProtocol(int port)
        {
            return port switch
            {
                465 => "SMTPS",    // SMTP over SSL
                587 => "SMTP/STARTTLS", // Submission port
                _ => "SMTP"
            };
        }

        private bool ParseSmtpBanner(string banner, PortScanResult result)
        {
            if (string.IsNullOrEmpty(banner)) return false;

            try
            {
                // Remove status code (220) if present
                var cleanBanner = Regex.Replace(banner, @"^220[\s-]", "", RegexOptions.Multiline);

                _logger?.LogInformation($"Clean banner: {cleanBanner}");

                // Check for specific SMTP servers

                // Postfix: "220 mail.example.com ESMTP Postfix"
                var postfixMatch = Regex.Match(cleanBanner, @"ESMTP\s+Postfix(?:\s+([\d\.]+))?", RegexOptions.IgnoreCase);
                if (postfixMatch.Success)
                {
                    result.SetService("Postfix");
                    result.SetVersion(postfixMatch.Groups[1].Success && !string.IsNullOrEmpty(postfixMatch.Groups[1].Value)
                        ? postfixMatch.Groups[1].Value
                        : "Version Hidden");
                    return true;
                }

                // Exim: "220 mail.example.com ESMTP Exim 4.94.2"
                var eximMatch = Regex.Match(cleanBanner, @"ESMTP\s+Exim\s+([\d\.]+)", RegexOptions.IgnoreCase);
                if (eximMatch.Success)
                {
                    result.SetService("Exim");
                    result.SetVersion(eximMatch.Groups[1].Value);
                    return true;
                }

                // Sendmail: "220 mail.example.com ESMTP Sendmail 8.17.1"
                var sendmailMatch = Regex.Match(cleanBanner, @"Sendmail\s+([\d\.]+)", RegexOptions.IgnoreCase);
                if (sendmailMatch.Success)
                {
                    result.SetService("Sendmail");
                    result.SetVersion(sendmailMatch.Groups[1].Value);
                    return true;
                }

                // Microsoft Exchange: "220 mail.example.com Microsoft ESMTP MAIL Service ready"
                var exchangeMatch = Regex.Match(cleanBanner, @"Microsoft\s+ESMTP", RegexOptions.IgnoreCase);
                if (exchangeMatch.Success)
                {
                    result.SetService("Microsoft Exchange");

                    // Try to extract version
                    var versionMatch = Regex.Match(cleanBanner, @"Version:\s*([\d\.]+)", RegexOptions.IgnoreCase);
                    if (versionMatch.Success)
                    {
                        result.SetVersion(versionMatch.Groups[1].Value);
                    }
                    else
                    {
                        result.SetVersion("Version Hidden");
                    }
                    return true;
                }

                // qmail: "220 mail.example.com ESMTP"
                if (cleanBanner.Contains("qmail", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("qmail");
                    var qmailMatch = Regex.Match(cleanBanner, @"qmail\s+([\d\.]+)", RegexOptions.IgnoreCase);
                    result.SetVersion(qmailMatch.Success ? qmailMatch.Groups[1].Value : "Version Hidden");
                    return true;
                }

                // Generic ESMTP check
                if (cleanBanner.Contains("ESMTP", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("SMTP");
                    result.SetVersion("Server Identity Hidden (ESMTP)");
                    return true;
                }

                // Check for "SMTP" keyword
                if (cleanBanner.Contains("SMTP", StringComparison.OrdinalIgnoreCase))
                {
                    result.SetService("SMTP");
                    result.SetVersion("Server Identity Hidden");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing SMTP banner");
                return false;
            }
        }

        private async Task EnhanceWithEhlo(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                // Send EHLO command to get server capabilities
                var ehloCommand = Encoding.ASCII.GetBytes($"EHLO scanner.local\r\n");
                string ehloResponse = await BannerGrabber.GrabBannerWithTriggerAsync(
                    result.IPAddress, result.Port, ehloCommand, timeout, cancellationToken);

                _logger?.LogInformation($"EHLO Response: {ehloResponse}");

                if (!string.IsNullOrEmpty(ehloResponse))
                {
                    ParseEhloResponse(ehloResponse, result);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "EHLO enhancement failed");
            }
        }

        private void ParseEhloResponse(string ehloResponse, PortScanResult result)
        {
            try
            {
                // EHLO response format:
                // 250-mail.example.com
                // 250-PIPELINING
                // 250-SIZE 10240000
                // 250-VRFY
                // 250-ETRN
                // 250-STARTTLS
                // 250-AUTH PLAIN LOGIN
                // 250 HELP

                var lines = ehloResponse.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

                // First line often contains server name
                if (lines.Length > 0)
                {
                    var firstLine = lines[0];

                    // Extract server name from first 250 response
                    var serverMatch = Regex.Match(firstLine, @"250[\s-](.+?)(?:\s|$)", RegexOptions.IgnoreCase);
                    if (serverMatch.Success)
                    {
                        string serverInfo = serverMatch.Groups[1].Value.Trim();

                        // Check if it contains server software info
                        if (CheckForServerSoftware(serverInfo, result))
                        {
                            return;
                        }
                    }
                }

                // Check for AUTH methods
                bool hasAuth = ehloResponse.Contains("AUTH", StringComparison.OrdinalIgnoreCase);
                bool hasStartTls = ehloResponse.Contains("STARTTLS", StringComparison.OrdinalIgnoreCase);

                // Update protocol info
                if (hasStartTls && result.Protocol == "SMTP")
                {
                    result.Protocol = "SMTP/STARTTLS";
                }

                // If still unknown, mark as detected SMTP
                if (result.Version == "Unknown" || string.IsNullOrEmpty(result.Version))
                {
                    string securityInfo = hasStartTls ? " (STARTTLS)" : " (Plaintext)";
                    result.SetVersion($"Server Identity Hidden{securityInfo}");
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing EHLO response");
            }
        }

        private bool CheckForServerSoftware(string serverInfo, PortScanResult result)
        {
            // Check for common SMTP servers in EHLO response

            if (serverInfo.Contains("Postfix", StringComparison.OrdinalIgnoreCase))
            {
                result.SetService("Postfix");
                var match = Regex.Match(serverInfo, @"Postfix\s+([\d\.]+)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    result.SetVersion(match.Groups[1].Value);
                }
                else
                {
                    result.SetVersion("Version Hidden");
                }
                return true;
            }

            if (serverInfo.Contains("Exim", StringComparison.OrdinalIgnoreCase))
            {
                result.SetService("Exim");
                var match = Regex.Match(serverInfo, @"Exim\s+([\d\.]+)", RegexOptions.IgnoreCase);
                result.SetVersion(match.Success ? match.Groups[1].Value : "Version Hidden");
                return true;
            }

            if (serverInfo.Contains("Sendmail", StringComparison.OrdinalIgnoreCase))
            {
                result.SetService("Sendmail");
                var match = Regex.Match(serverInfo, @"Sendmail\s+([\d\.]+)", RegexOptions.IgnoreCase);
                result.SetVersion(match.Success ? match.Groups[1].Value : "Version Hidden");
                return true;
            }

            if (serverInfo.Contains("Exchange", StringComparison.OrdinalIgnoreCase) ||
                serverInfo.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            {
                result.SetService("Microsoft Exchange");
                result.SetVersion("Version Hidden");
                return true;
            }

            return false;
        }

        private void AddSecurityAssessment(PortScanResult result)
        {
            if (result.Port == 25 && result.Protocol == "SMTP")
                result.SetVersion(result.Version + " ⚠️ Plaintext");
            if (result.Port == 25 && result.Protocol == "SMTP/STARTTLS")
                result.SetVersion(result.Version + " ✓ STARTTLS");
            if (result.Port == 587)
                result.SetVersion(result.Version + " ✓ Submission");
            if (result.Port == 465)
                result.SetVersion(result.Version + " ✓ Encrypted");
        }

        // ── Static convenience method for Service_Handler facade ──────────────

        public static async Task<string> DetectVersionAsync(string ipAddress, int port, CancellationToken ct = default)
        {
            try
            {
                var stub = new PROSCANNERCONT.Models.PortScanResult { IPAddress = ipAddress, Port = port };
                var detector = new SmtpDetector();
                var result = await detector.DetectAsync(stub, 3000, ct);
                return string.IsNullOrEmpty(result.Version) ? "Unknown SMTP" : $"{result.Service} {result.Version}".Trim();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SmtpDetector.DetectVersionAsync] {ex.Message}");
                return "Unknown SMTP";
            }
        }
    }
}