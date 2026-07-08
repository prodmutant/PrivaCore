using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Manages Windows Firewall inbound-block rules for IPS mode.
    /// Requires the application to be running as Administrator.
    /// Rule names are prefixed with "PrivaCore_Block_" for easy identification and cleanup.
    /// </summary>
    public static class IpsBlocklistService
    {
        private const string RulePrefix = "PrivaCore_Block_";

        public static bool BlockIp(string ip, out string error)
        {
            error = "";
            if (string.IsNullOrWhiteSpace(ip)) { error = "IP address is empty."; return false; }

            return RunNetsh(
                $"advfirewall firewall add rule name=\"{RulePrefix}{ip}\" " +
                $"dir=in action=block remoteip={ip} enable=yes protocol=any",
                out error);
        }

        public static bool UnblockIp(string ip, out string error)
        {
            error = "";
            return RunNetsh($"advfirewall firewall delete rule name=\"{RulePrefix}{ip}\"", out error);
        }

        public static void UnblockAll(List<BlockedIpEntry> blockedList, out string error)
        {
            error = "";
            foreach (var entry in blockedList.ToList())
            {
                UnblockIp(entry.IP, out _);
            }
        }

        /// <summary>
        /// Checks whether a firewall rule already exists for this IP (avoids duplicate rules).
        /// </summary>
        public static bool IsBlocked(string ip)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh",
                    $"advfirewall firewall show rule name=\"{RulePrefix}{ip}\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                string output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(3000);
                return output.Contains("Rule Name", StringComparison.OrdinalIgnoreCase) &&
                       output.Contains(ip, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static bool RunNetsh(string args, out string error)
        {
            error = "";
            try
            {
                var psi = new ProcessStartInfo("netsh", args)
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                string stdout = proc?.StandardOutput.ReadToEnd() ?? "";
                string stderr = proc?.StandardError.ReadToEnd() ?? "";
                proc?.WaitForExit(5000);
                if (proc?.ExitCode != 0)
                {
                    error = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
                    return false;
                }
                return true;
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }
    }
}
