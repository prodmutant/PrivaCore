using System;
using System.Collections.Generic;
using System.Net;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Identifies traffic to well-known DNS-over-HTTPS / DNS-over-TLS providers.
    /// These flows bypass the IDS's DNS-tunnel detector because the queries are
    /// encrypted inside TLS, so the most we can do is flag the destination
    /// against a known-provider catalogue.
    ///
    /// Used by IDSManager: if an outbound TCP/443 (DoH) or TCP/853 (DoT) flow
    /// hits one of these IPs, the engine emits a Medium-severity informational
    /// alert with category "Encrypted DNS" so analysts know the host is doing
    /// out-of-band DNS resolution that won't appear in their on-prem resolver
    /// logs.
    /// </summary>
    public static class DohDetector
    {
        private static readonly Dictionary<string, string> _ipMap = new(StringComparer.OrdinalIgnoreCase)
        {
            // Cloudflare 1.1.1.1
            ["1.1.1.1"]              = "Cloudflare",
            ["1.0.0.1"]              = "Cloudflare",
            ["2606:4700:4700::1111"] = "Cloudflare",
            ["2606:4700:4700::1001"] = "Cloudflare",
            // Google Public DNS
            ["8.8.8.8"]              = "Google",
            ["8.8.4.4"]              = "Google",
            ["2001:4860:4860::8888"] = "Google",
            ["2001:4860:4860::8844"] = "Google",
            // Quad9
            ["9.9.9.9"]              = "Quad9",
            ["149.112.112.112"]      = "Quad9",
            ["2620:fe::fe"]          = "Quad9",
            // OpenDNS / Cisco Umbrella
            ["208.67.222.222"]       = "OpenDNS",
            ["208.67.220.220"]       = "OpenDNS",
            // AdGuard
            ["94.140.14.14"]         = "AdGuard",
            ["94.140.15.15"]         = "AdGuard",
            // NextDNS (anycast prefix sample)
            ["45.90.28.0"]           = "NextDNS",
            ["45.90.30.0"]           = "NextDNS",
            // Mullvad DNS
            ["194.242.2.2"]          = "Mullvad",
            ["194.242.2.3"]          = "Mullvad",
            // CleanBrowsing
            ["185.228.168.9"]        = "CleanBrowsing",
            ["185.228.169.9"]        = "CleanBrowsing",
        };

        public sealed record EncryptedDnsHit(string Provider, string Protocol, int Port);

        public static EncryptedDnsHit? Detect(string dstIp, int dstPort)
        {
            if (string.IsNullOrEmpty(dstIp)) return null;
            if (!_ipMap.TryGetValue(dstIp, out var provider)) return null;

            return dstPort switch
            {
                443 => new EncryptedDnsHit(provider, "DoH", 443),
                853 => new EncryptedDnsHit(provider, "DoT", 853),
                _   => null,
            };
        }

        public static bool IsKnownProvider(string ip) =>
            !string.IsNullOrEmpty(ip) && _ipMap.ContainsKey(ip);

        public static IReadOnlyDictionary<string, string> KnownProviders => _ipMap;
    }
}
