using System;
using System.Collections.Generic;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    public sealed class PortDelta
    {
        public string Ip { get; init; } = "";
        public int Port { get; init; }
        public string Protocol { get; init; } = "TCP";
        public string Change { get; init; } = ""; // "Opened" | "Closed" | "ServiceChanged" | "VersionChanged"
        public string? Before { get; init; }
        public string? After { get; init; }
    }

    public sealed class CveDelta
    {
        public string Ip { get; init; } = "";
        public int Port { get; init; }
        public string CveId { get; init; } = "";
        public string Change { get; init; } = ""; // "New" | "Fixed"
        public string Severity { get; init; } = "";
    }

    public sealed class ScanDiff
    {
        public DateTime Baseline { get; init; }
        public DateTime Latest { get; init; }
        public string Target { get; init; } = "";
        public List<PortDelta> Ports { get; } = new();
        public List<CveDelta> Cves { get; } = new();
        public int OpenedCount  => Ports.Count(p => p.Change == "Opened");
        public int ClosedCount  => Ports.Count(p => p.Change == "Closed");
        public int NewCveCount  => Cves.Count(c => c.Change == "New");
        public int FixedCveCount => Cves.Count(c => c.Change == "Fixed");
    }

    /// <summary>
    /// Compares two PortScanResult collections (typically the same target at
    /// two different points in time) and produces a structured delta. Used by
    /// the Dashboard "What changed since the last scan?" widget and the
    /// patch-tracking report section.
    /// </summary>
    public static class ScanDiffService
    {
        public static ScanDiff Compare(
            IReadOnlyList<PortScanResult> baseline,
            IReadOnlyList<PortScanResult> latest,
            string target,
            DateTime baselineTime,
            DateTime latestTime)
        {
            var diff = new ScanDiff
            {
                Baseline = baselineTime,
                Latest   = latestTime,
                Target   = target,
            };

            var baseKey  = baseline.ToDictionary(p => $"{p.IPAddress}:{p.Port}:{p.Protocol}", p => p);
            var latKey   = latest  .ToDictionary(p => $"{p.IPAddress}:{p.Port}:{p.Protocol}", p => p);

            // Opened ports — present in latest but not baseline (or was closed before).
            foreach (var (k, p) in latKey)
            {
                bool wasOpen = baseKey.TryGetValue(k, out var b) && b.IsOpen;
                if (p.IsOpen && !wasOpen)
                {
                    diff.Ports.Add(new PortDelta
                    {
                        Ip = p.IPAddress, Port = p.Port, Protocol = p.Protocol,
                        Change = "Opened", Before = wasOpen ? b!.Service : null, After = p.Service
                    });
                }
                else if (p.IsOpen && wasOpen)
                {
                    if (!string.Equals(b!.Service, p.Service, StringComparison.OrdinalIgnoreCase))
                        diff.Ports.Add(new PortDelta
                        {
                            Ip = p.IPAddress, Port = p.Port, Protocol = p.Protocol,
                            Change = "ServiceChanged", Before = b.Service, After = p.Service
                        });
                    else if (!string.Equals(b.Version, p.Version, StringComparison.OrdinalIgnoreCase))
                        diff.Ports.Add(new PortDelta
                        {
                            Ip = p.IPAddress, Port = p.Port, Protocol = p.Protocol,
                            Change = "VersionChanged", Before = b.Version, After = p.Version
                        });
                }
            }

            // Closed ports — open in baseline but not latest.
            foreach (var (k, b) in baseKey)
                if (b.IsOpen && (!latKey.TryGetValue(k, out var l) || !l.IsOpen))
                    diff.Ports.Add(new PortDelta
                    {
                        Ip = b.IPAddress, Port = b.Port, Protocol = b.Protocol,
                        Change = "Closed", Before = b.Service, After = null
                    });

            // CVE deltas
            var baseCves = baseline
                .Where(p => p.IsOpen && p.CveFindings != null)
                .SelectMany(p => p.CveFindings!.Select(c => (Port: p, Cve: c)))
                .ToDictionary(x => $"{x.Port.IPAddress}:{x.Port.Port}:{x.Cve.CveId}", x => x);
            var latCves = latest
                .Where(p => p.IsOpen && p.CveFindings != null)
                .SelectMany(p => p.CveFindings!.Select(c => (Port: p, Cve: c)))
                .ToDictionary(x => $"{x.Port.IPAddress}:{x.Port.Port}:{x.Cve.CveId}", x => x);

            foreach (var (k, x) in latCves)
                if (!baseCves.ContainsKey(k))
                    diff.Cves.Add(new CveDelta { Ip = x.Port.IPAddress, Port = x.Port.Port, CveId = x.Cve.CveId, Change = "New", Severity = x.Cve.Severity ?? "" });
            foreach (var (k, x) in baseCves)
                if (!latCves.ContainsKey(k))
                    diff.Cves.Add(new CveDelta { Ip = x.Port.IPAddress, Port = x.Port.Port, CveId = x.Cve.CveId, Change = "Fixed", Severity = x.Cve.Severity ?? "" });

            return diff;
        }

        public static string ToMarkdown(ScanDiff diff)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"# Scan diff — {diff.Target}");
            sb.AppendLine($"Baseline: {diff.Baseline:yyyy-MM-dd HH:mm} → Latest: {diff.Latest:yyyy-MM-dd HH:mm}");
            sb.AppendLine();
            sb.AppendLine($"- **Opened**: {diff.OpenedCount}");
            sb.AppendLine($"- **Closed**: {diff.ClosedCount}");
            sb.AppendLine($"- **New CVEs**: {diff.NewCveCount}");
            sb.AppendLine($"- **Fixed CVEs**: {diff.FixedCveCount}");
            sb.AppendLine();
            if (diff.Ports.Count > 0)
            {
                sb.AppendLine("## Port changes");
                sb.AppendLine("| IP | Port | Change | Before | After |");
                sb.AppendLine("|---|---|---|---|---|");
                foreach (var p in diff.Ports)
                    sb.AppendLine($"| {p.Ip} | {p.Port}/{p.Protocol} | {p.Change} | {p.Before ?? "—"} | {p.After ?? "—"} |");
                sb.AppendLine();
            }
            if (diff.Cves.Count > 0)
            {
                sb.AppendLine("## CVE changes");
                sb.AppendLine("| IP | Port | CVE | Change | Severity |");
                sb.AppendLine("|---|---|---|---|---|");
                foreach (var c in diff.Cves)
                    sb.AppendLine($"| {c.Ip} | {c.Port} | {c.CveId} | {c.Change} | {c.Severity} |");
            }
            return sb.ToString();
        }
    }
}
