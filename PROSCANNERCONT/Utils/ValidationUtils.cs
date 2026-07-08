using System;
using System.Net;
using System.Text.RegularExpressions;

namespace PROSCANNERCONT.Utils
{
    /// <summary>
    /// Input validation helpers used at all user-facing entry points before processing.
    /// </summary>
    public static class ValidationUtils
    {
        private static readonly Regex _ipRangeRegex = new Regex(
            @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$",
            RegexOptions.Compiled);

        /// <summary>Returns true when <paramref name="ip"/> is a valid IPv4 or IPv6 address.</summary>
        public static bool IsValidIpAddress(string ip) =>
            !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);

        /// <summary>Returns true when <paramref name="port"/> is in the valid TCP/UDP range [1–65535].</summary>
        public static bool IsValidPort(int port) => port >= 1 && port <= 65535;

        /// <summary>Returns true when <paramref name="portStr"/> can be parsed and is in range [1–65535].</summary>
        public static bool IsValidPort(string portStr) =>
            int.TryParse(portStr, out int p) && IsValidPort(p);

        /// <summary>
        /// Returns true for valid IPv4 CIDR notation (e.g. "192.168.1.0/24").
        /// Prefix must be in [0, 32].
        /// </summary>
        public static bool IsValidCidr(string cidr)
        {
            if (string.IsNullOrWhiteSpace(cidr)) return false;
            var parts = cidr.Split('/');
            return parts.Length == 2
                   && IPAddress.TryParse(parts[0], out _)
                   && int.TryParse(parts[1], out int prefix)
                   && prefix >= 0 && prefix <= 32;
        }

        /// <summary>
        /// Returns true for a range like "192.168.1.1-254" or a single IP or a CIDR.
        /// </summary>
        public static bool IsValidIpRangeOrCidr(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            if (IsValidIpAddress(input)) return true;
            if (IsValidCidr(input)) return true;
            return _ipRangeRegex.IsMatch(input);
        }

        /// <summary>
        /// Returns true when <paramref name="start"/> &lt;= <paramref name="end"/> and both are valid ports.
        /// </summary>
        public static bool IsValidPortRange(int start, int end) =>
            IsValidPort(start) && IsValidPort(end) && start <= end;

        /// <summary>
        /// Clamps a timeout value to a safe range [100 ms – 30 000 ms].
        /// </summary>
        public static int ClampTimeout(int timeoutMs) =>
            Math.Clamp(timeoutMs, 100, 30_000);
    }
}
