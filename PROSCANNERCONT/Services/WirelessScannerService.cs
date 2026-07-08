using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public sealed class WifiNetwork
    {
        public string Ssid { get; set; } = "";
        public string Bssid { get; set; } = "";
        public int SignalPercent { get; set; }
        public int Channel { get; set; }
        public string Radio { get; set; } = "";    // 802.11n / ax / ac etc
        public string Authentication { get; set; } = "";
        public string Encryption { get; set; } = "";
        public bool WpsEnabled { get; set; }
        public string SecurityFinding =>
            (Authentication.Equals("Open", StringComparison.OrdinalIgnoreCase) ? "OPEN " : "") +
            (Authentication.Contains("WEP", StringComparison.OrdinalIgnoreCase) ? "WEP " : "") +
            (WpsEnabled ? "WPS-ENABLED " : "") +
            (Authentication.Contains("WPA3", StringComparison.OrdinalIgnoreCase) ? "WPA3-OK" : "");
    }

    /// <summary>
    /// Wi-Fi visible-network enumeration. Wraps Windows' `netsh wlan show
    /// networks mode=bssid` rather than P/Invoking the native WLAN API — netsh
    /// is universally present, no extra package needed, and parses cleanly.
    /// To force a fresh scan, runs `netsh wlan show networks` first which
    /// triggers the radio to re-probe.
    /// </summary>
    public sealed class WirelessScannerService
    {
        public async Task<List<WifiNetwork>> ScanAsync()
        {
            var text = await RunAsync("netsh", "wlan show networks mode=bssid");
            return Parse(text);
        }

        private static async Task<string> RunAsync(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi)!;
            var stdout = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return stdout;
        }

        public static List<WifiNetwork> Parse(string netshOutput)
        {
            var list = new List<WifiNetwork>();
            if (string.IsNullOrWhiteSpace(netshOutput)) return list;

            WifiNetwork? current = null;
            var lines = netshOutput.Split('\n');
            var ssidRx   = new Regex(@"^\s*SSID \d+\s*:\s*(.*)$",   RegexOptions.IgnoreCase);
            var authRx   = new Regex(@"^\s*Authentication\s*:\s*(.*)$", RegexOptions.IgnoreCase);
            var encRx    = new Regex(@"^\s*Encryption\s*:\s*(.*)$",    RegexOptions.IgnoreCase);
            var bssidRx  = new Regex(@"^\s*BSSID \d+\s*:\s*([0-9a-f:]+)", RegexOptions.IgnoreCase);
            var signalRx = new Regex(@"^\s*Signal\s*:\s*(\d+)%", RegexOptions.IgnoreCase);
            var channelRx= new Regex(@"^\s*Channel\s*:\s*(\d+)", RegexOptions.IgnoreCase);
            var radioRx  = new Regex(@"^\s*Radio type\s*:\s*(.*)$", RegexOptions.IgnoreCase);

            string? ssid = null, auth = "", enc = "";

            foreach (var raw in lines)
            {
                var line = raw.TrimEnd('\r');
                Match m;
                if ((m = ssidRx.Match(line)).Success)  { ssid = m.Groups[1].Value.Trim(); }
                else if ((m = authRx.Match(line)).Success) { auth = m.Groups[1].Value.Trim(); }
                else if ((m = encRx.Match(line)).Success)  { enc  = m.Groups[1].Value.Trim(); }
                else if ((m = bssidRx.Match(line)).Success)
                {
                    current = new WifiNetwork
                    {
                        Ssid = ssid ?? "(hidden)", Bssid = m.Groups[1].Value,
                        Authentication = auth, Encryption = enc,
                        WpsEnabled = enc.Contains("WPS", StringComparison.OrdinalIgnoreCase),
                    };
                    list.Add(current);
                }
                else if ((m = signalRx.Match(line)).Success && current != null)
                    current.SignalPercent = int.Parse(m.Groups[1].Value);
                else if ((m = channelRx.Match(line)).Success && current != null)
                    current.Channel = int.Parse(m.Groups[1].Value);
                else if ((m = radioRx.Match(line)).Success && current != null)
                    current.Radio = m.Groups[1].Value.Trim();
            }
            return list;
        }
    }
}
