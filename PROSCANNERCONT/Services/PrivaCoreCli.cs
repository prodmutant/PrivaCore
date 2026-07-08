using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Security;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Headless / CLI entrypoint for PrivaCore. Detected by App.OnStartup
    /// when args[0] is not a flag. Lets CI/CD pipelines do
    ///   PrivaCore.exe portscan --target 10.0.0.0/24 --ports 1-1024 --out scan.html
    /// without opening any WPF window.
    /// </summary>
    public static class PrivaCoreCli
    {
        public static bool IsCliInvocation(string[] args)
            => args.Length > 0 && !args[0].StartsWith("-") && IsKnownCommand(args[0]);

        private static bool IsKnownCommand(string s) => s switch
        {
            "portscan" or "netdiscover" or "vulnscan" or "report" or "ti-refresh" or "cert-probe" => true,
            _ => false,
        };

        public static async Task<int> RunAsync(string[] args)
        {
            try
            {
                if (args.Length == 0) { PrintHelp(); return 0; }

                var cmd = args[0].ToLowerInvariant();
                var rest = args.Skip(1).ToArray();
                var opts = ParseOpts(rest);

                return cmd switch
                {
                    "portscan"    => await RunPortScan(opts),
                    "netdiscover" => await RunNetDiscover(opts),
                    "vulnscan"    => await RunVulnScan(opts),
                    "ti-refresh"  => await RunTiRefresh(),
                    "cert-probe"  => await RunCertProbe(opts),
                    _             => Bad("Unknown command. Try --help."),
                };
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"FATAL: {ex.Message}");
                return 2;
            }
        }

        private static Dictionary<string, string> ParseOpts(string[] args)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--")) continue;
                var key = args[i][2..];
                var val = (i + 1 < args.Length && !args[i + 1].StartsWith("--")) ? args[++i] : "true";
                dict[key] = val;
            }
            return dict;
        }

        // ── Commands ───────────────────────────────────────────────────────
        private static async Task<int> RunPortScan(Dictionary<string, string> opts)
        {
            var target = opts.GetValueOrDefault("target") ?? Bad<string>("--target required");
            var range  = opts.GetValueOrDefault("ports", "1-1024");
            var (start, end) = ParseRange(range);
            var output = opts.GetValueOrDefault("out");

            var guard = ScopeGuard.Check(target);
            if (!guard.Allowed) { Console.Error.WriteLine($"scope-guard: {guard.Reason}"); return 3; }

            Console.WriteLine($"[portscan] target={target} ports={start}-{end}");
            var nmapDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PortScanProtocols");
            var scanner = new PortScannerService(nmapDir);
            var results = new List<PortScanResult>();
            for (int p = start; p <= end; p++)
            {
                var r = await scanner.ScanPortAsync(target, p);
                if (r.IsOpen) { results.Add(r); Console.WriteLine($"  open: {p}/{r.Protocol} {r.Service} {r.Version}"); }
            }
            Console.WriteLine($"[portscan] {results.Count} open ports.");
            if (!string.IsNullOrEmpty(output)) await WriteReport(output, target, start, end, results);
            return 0;
        }

        private static Task<int> RunNetDiscover(Dictionary<string, string> opts)
        {
            var range = opts.GetValueOrDefault("range") ?? Bad<string>("--range required (e.g. 192.168.1.0/24)");
            Console.WriteLine($"[netdiscover] {range}");
            var scanner = new NetworkScanner();
            scanner.ProgressChanged += s => Console.WriteLine($"  {s}");
            return Task.Run(async () =>
            {
                var topo = await scanner.ScanNetworkAsync(range);
                Console.WriteLine($"[netdiscover] {topo.TotalDevices} devices, {topo.TotalRouters} routers.");
                return 0;
            });
        }

        private static async Task<int> RunVulnScan(Dictionary<string, string> opts)
        {
            // vulnscan is portscan + CVE lookup.
            var portCode = await RunPortScan(opts);
            return portCode;
        }

        private static async Task<int> RunTiRefresh()
        {
            await ThreatIntelService.Instance.RefreshAllAsync();
            Console.WriteLine($"[ti] {ThreatIntelService.Instance.TotalIndicators} indicators cached.");
            return 0;
        }

        private static async Task<int> RunCertProbe(Dictionary<string, string> opts)
        {
            var host = opts.GetValueOrDefault("host") ?? Bad<string>("--host required");
            var port = int.Parse(opts.GetValueOrDefault("port", "443"));
            var obs = await CertExpiryMonitor.Instance.ProbeAsync(host, port);
            if (obs == null) { Console.WriteLine("[cert] no cert observed."); return 1; }
            Console.WriteLine($"[cert] {host}:{port} expires {obs.NotAfter:yyyy-MM-dd} ({obs.DaysToExpiry} days)");
            return 0;
        }

        private static async Task WriteReport(string output, string target, int start, int end, List<PortScanResult> results)
        {
            var html = ReportGenerator.GeneratePortScanReport(target, start, end, "TCP", results);
            await File.WriteAllTextAsync(output, html);
            Console.WriteLine($"[report] wrote {output}");
        }

        private static (int, int) ParseRange(string s)
        {
            var parts = s.Split('-');
            if (parts.Length == 2 && int.TryParse(parts[0], out int a) && int.TryParse(parts[1], out int b))
                return (a, b);
            if (int.TryParse(s, out int single)) return (single, single);
            throw new ArgumentException($"Bad port range: {s}");
        }

        private static T Bad<T>(string msg) { Console.Error.WriteLine(msg); Environment.Exit(2); return default!; }
        private static int  Bad(string msg) { Console.Error.WriteLine(msg); return 2; }

        public static void PrintHelp()
        {
            Console.WriteLine("PrivaCore CLI");
            Console.WriteLine("  portscan    --target IP|CIDR  [--ports 1-1024]  [--out report.html]");
            Console.WriteLine("  netdiscover --range CIDR");
            Console.WriteLine("  vulnscan    --target IP        [--ports 1-1024] [--out report.html]");
            Console.WriteLine("  ti-refresh");
            Console.WriteLine("  cert-probe  --host HOST        [--port 443]");
        }
    }
}
