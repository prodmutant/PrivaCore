using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace PrivaCore.ModuleSdk;

/// <summary>
/// Helpers to make a module reachable as a server on the LAN: enumerate the host's
/// real IPv4 addresses and (best-effort) open the Windows Firewall for the port.
/// </summary>
public static class NetworkReach
{
    /// <summary>Non-loopback IPv4 addresses of up interfaces — the addresses other machines use.</summary>
    public static List<string> LocalIPv4()
    {
        var list = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ua.Address))
                        list.Add(ua.Address.ToString());
            }
        }
        catch { }
        return list.Distinct().ToList();
    }

    /// <summary>
    /// Adds an inbound TCP allow rule via netsh so other machines can reach the module.
    /// Needs Administrator; returns false if it couldn't (then run the app elevated or
    /// use Allow-Firewall.cmd). Idempotent.
    /// </summary>
    public static bool TryOpenFirewall(string ruleName, int port)
    {
        if (!OperatingSystem.IsWindows()) return true;
        try
        {
            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");
            return RunNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=allow protocol=TCP localport={port}");
        }
        catch { return false; }
    }

    private static bool RunNetsh(string args)
    {
        var psi = new ProcessStartInfo("netsh", args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi);
        if (p == null) return false;
        p.WaitForExit(5000);
        return p.ExitCode == 0;
    }
}
