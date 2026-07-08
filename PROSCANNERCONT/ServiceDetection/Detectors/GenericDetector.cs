using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;
using System.Text.RegularExpressions;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    /// <summary>
    /// Generic detector for unknown services
    /// Provides fallback detection for services not covered by specialized detectors
    /// </summary>
    public class GenericDetector : IServiceDetector
    {
        public string ServiceName => "Generic";

        public int[] CommonPorts => Array.Empty<int>();

        // Lowest priority so it runs last
        public int Priority => int.MaxValue;

        // Dictionary of port to common service triggers
        private readonly Dictionary<int, byte[]> _portTriggers = new Dictionary<int, byte[]>
        {
            { 21, Encoding.ASCII.GetBytes("HELP\r\n") },                // FTP
            { 25, Encoding.ASCII.GetBytes("EHLO test\r\n") },           // SMTP
            { 110, Encoding.ASCII.GetBytes("CAPA\r\n") },               // POP3
            { 119, Encoding.ASCII.GetBytes("HELP\r\n") },               // NNTP
            { 143, Encoding.ASCII.GetBytes("a001 CAPABILITY\r\n") },    // IMAP
            { 3306, new byte[] { 0x03, 0x00, 0x00, 0x00 } }             // MySQL
        };

        // Common service patterns for basic identification
        private readonly Dictionary<int, Regex> _servicePatterns = new Dictionary<int, Regex>
        {
            { 21, new Regex(@"^220[\s-](.+?)(?:$|\r|\n)", RegexOptions.Compiled) },        // FTP
            { 25, new Regex(@"^220[\s-](.+?)(?:$|\r|\n)", RegexOptions.Compiled) },        // SMTP
            { 110, new Regex(@"^\+OK[\s-](.+?)(?:$|\r|\n)", RegexOptions.Compiled) },      // POP3
            { 143, new Regex(@"^\* OK[\s-](.+?)(?:$|\r|\n)", RegexOptions.Compiled) },     // IMAP
            { 3306, new Regex(@"([.\d]+)", RegexOptions.Compiled) }                        // MySQL
        };

        // Generic version regex that works for many services
        private static readonly Regex GenericVersionRegex =
            new Regex(@"(?:version|ver)[:\s]+(\d+(?:\.\d+)+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Generic detector can try to detect any open port
            return true;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // CRITICAL: Don't overwrite results from specialized detectors
                // If we already have a service name that's not "Unknown", don't interfere
                if (!string.IsNullOrEmpty(result.Service) &&
                    result.Service != "Unknown" &&
                    result.Service != "Generic")
                {
                    // Just fill in missing protocol if needed
                    if (string.IsNullOrEmpty(result.Protocol))
                    {
                        result.Protocol = "TCP";
                    }
                    return result;
                }

                // Try to get a banner with no trigger first
                string banner = await BannerGrabber.GrabBannerAsync(
                    result.IPAddress,
                    result.Port,
                    timeout,
                    cancellationToken);

                // If we got a banner, try to identify from it
                if (!string.IsNullOrEmpty(banner))
                {
                    AnalyzeBanner(banner, result);

                    // If we identified something useful, return it
                    if (!string.IsNullOrEmpty(result.Version) &&
                        result.Version != "Unknown" &&
                        IsCleanVersion(result.Version))
                    {
                        return result;
                    }
                }

                // If no banner or couldn't identify, try with a specific trigger
                if (_portTriggers.TryGetValue(result.Port, out byte[] trigger))
                {
                    string triggeredBanner = await BannerGrabber.GrabBannerWithTriggerAsync(
                        result.IPAddress,
                        result.Port,
                        trigger,
                        timeout,
                        cancellationToken);

                    if (!string.IsNullOrEmpty(triggeredBanner))
                    {
                        AnalyzeBanner(triggeredBanner, result);
                    }
                }
                else
                {
                    // Try a generic trigger for other ports
                    byte[] genericTrigger = Encoding.ASCII.GetBytes("HELP\r\n");
                    string genericResponse = await BannerGrabber.GrabBannerWithTriggerAsync(
                        result.IPAddress,
                        result.Port,
                        genericTrigger,
                        timeout,
                        cancellationToken);

                    if (!string.IsNullOrEmpty(genericResponse))
                    {
                        AnalyzeBanner(genericResponse, result);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Generic detector error: {ex.Message}");
            }

            // Set fallback values only if we don't have anything
            if (string.IsNullOrEmpty(result.Service) || result.Service == "Unknown")
            {
                result.Service = GetServiceNameByPort(result.Port);
            }

            if (string.IsNullOrEmpty(result.Version) || result.Version == "Unknown")
            {
                result.Version = "Unknown";
            }

            if (string.IsNullOrEmpty(result.Protocol))
            {
                result.Protocol = "TCP";
            }

            return result;
        }

        private bool IsCleanVersion(string version)
        {
            if (string.IsNullOrEmpty(version)) return false;

            // Check if version looks like a raw banner (contains things that shouldn't be in version)
            return !version.Contains("220") &&
                   !version.Contains("ESMTP") &&
                   !version.Contains("localdomain") &&
                   !version.Contains("(") &&
                   version.Length < 50; // Reasonable version length
        }

        private void AnalyzeBanner(string banner, PortScanResult result)
        {
            try
            {
                // Store the banner for reference
                if (string.IsNullOrEmpty(result.RawBanner))
                {
                    result.RawBanner = banner;
                }

                // Try specific port pattern if available
                if (_servicePatterns.TryGetValue(result.Port, out Regex pattern))
                {
                    var match = pattern.Match(banner);
                    if (match.Success)
                    {
                        string versionInfo = match.Groups[1].Value.Trim();
                        if (!string.IsNullOrEmpty(versionInfo))
                        {
                            // Only set service if we don't have one
                            if (string.IsNullOrEmpty(result.Service) || result.Service == "Unknown")
                            {
                                result.Service = GetServiceNameByPort(result.Port);
                            }

                            // Extract clean version number only
                            string cleanVersion = ExtractCleanVersion(versionInfo);
                            if (!string.IsNullOrEmpty(cleanVersion))
                            {
                                result.Version = cleanVersion;
                            }
                            return;
                        }
                    }
                }

                // Try generic version regex
                var versionMatch = GenericVersionRegex.Match(banner);
                if (versionMatch.Success)
                {
                    string version = versionMatch.Groups[1].Value;
                    if (!string.IsNullOrEmpty(version))
                    {
                        if (string.IsNullOrEmpty(result.Service) || result.Service == "Unknown")
                        {
                            result.Service = GetServiceNameByPort(result.Port);
                        }

                        result.Version = version; // This is already a clean version number
                        return;
                    }
                }

                // REMOVED: The problematic code that set the entire first line as version
                // We no longer put raw banners in the version field
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing banner: {ex.Message}");
            }
        }

        private string ExtractCleanVersion(string versionInfo)
        {
            if (string.IsNullOrEmpty(versionInfo)) return null;

            // Try to extract just version numbers from the version info
            var versionMatch = Regex.Match(versionInfo, @"(\d+(?:\.\d+)+)");
            if (versionMatch.Success)
            {
                return versionMatch.Groups[1].Value;
            }

            // If no version number found, don't use the raw text
            return null;
        }

        private string GetServiceNameByPort(int port)
        {
            switch (port)
            {
                case 20:
                case 21:
                    return "FTP";
                case 22:
                    return "SSH";
                case 23:
                    return "Telnet";
                case 25:
                case 587:
                    return "SMTP";
                case 53:
                    return "DNS";
                case 80:
                case 8080:
                    return "HTTP";
                case 110:
                    return "POP3";
                case 143:
                    return "IMAP";
                case 443:
                case 8443:
                    return "HTTPS";
                case 445:
                    return "SMB";
                case 1433:
                    return "MSSQL";
                case 3306:
                    return "MySQL";
                case 3389:
                    return "RDP";
                case 5432:
                    return "PostgreSQL";
                case 6379:
                    return "Redis";
                case 27017:
                    return "MongoDB";
                default:
                    return "Unknown";
            }
        }
    }
}