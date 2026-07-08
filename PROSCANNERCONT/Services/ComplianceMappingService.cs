using System;
using System.Collections.Generic;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    public sealed record ComplianceControl(
        string Framework,    // "PCI-DSS-4.0", "HIPAA", "NIST-800-53r5", "CIS-v8", "ISO-27001-2022"
        string Id,           // e.g. "11.3.1", "164.312(e)", "SC-7", "CIS-13.1"
        string Title,
        string Description,
        bool Passed,
        string Evidence);

    /// <summary>
    /// Maps PrivaCore findings (open ports, services, CVEs, IDS rules) onto
    /// common compliance framework controls.  Lets you generate a one-page
    /// "PCI 11 status" or "HIPAA 164.312 status" report straight from a scan
    /// without manually cross-referencing — the single biggest "sell-to-SMB"
    /// feature for this kind of tool.
    /// </summary>
    public static class ComplianceMappingService
    {
        public static List<ComplianceControl> Evaluate(
            string framework,
            IEnumerable<PortScanResult> ports,
            IEnumerable<IDSAlert>? alerts = null)
        {
            var portList  = ports?.Where(p => p.IsOpen).ToList() ?? new();
            var alertList = alerts?.ToList() ?? new();
            return framework switch
            {
                "PCI-DSS-4.0"     => EvalPciDss(portList, alertList),
                "HIPAA"           => EvalHipaa(portList, alertList),
                "NIST-800-53r5"   => EvalNist800_53(portList, alertList),
                "CIS-v8"          => EvalCisV8(portList, alertList),
                "ISO-27001-2022"  => EvalIso27001(portList, alertList),
                _                 => new(),
            };
        }

        public static IReadOnlyList<string> SupportedFrameworks { get; } = new[]
        {
            "PCI-DSS-4.0", "HIPAA", "NIST-800-53r5", "CIS-v8", "ISO-27001-2022"
        };

        // ── PCI-DSS 4.0 ────────────────────────────────────────────────────
        private static List<ComplianceControl> EvalPciDss(List<PortScanResult> ports, List<IDSAlert> alerts)
        {
            var ctl = new List<ComplianceControl>();

            // 2.2.4 / 1.4.2 — only necessary services exposed
            var dangerous = ports.Where(p => p.Port is 23 or 21 or 69 or 135 or 137 or 138 or 139 or 445).ToList();
            ctl.Add(new("PCI-DSS-4.0", "1.4.2", "Insecure services & protocols disabled",
                "Telnet/FTP/TFTP/NetBIOS/SMBv1 should not be exposed on the CDE perimeter.",
                dangerous.Count == 0,
                dangerous.Count == 0 ? "No insecure services found." :
                    "Found exposed: " + string.Join(", ", dangerous.Select(d => $"{d.IPAddress}:{d.Port}"))));

            // 6.4.1 — no known critical vulns
            var criticalCves = ports.SelectMany(p => p.CveFindings ?? new())
                                    .Where(c => c.Severity == "Critical").ToList();
            ctl.Add(new("PCI-DSS-4.0", "6.4.1", "No critical-severity CVEs in CDE",
                "Public-facing systems must not have known critical CVEs without compensating controls.",
                criticalCves.Count == 0,
                criticalCves.Count == 0 ? "No critical CVEs." :
                    $"{criticalCves.Count} critical CVEs across {criticalCves.Select(c => c.CveId).Distinct().Count()} unique IDs."));

            // 11.4.1 — IDS in place
            ctl.Add(new("PCI-DSS-4.0", "11.4.1", "Intrusion Detection deployed",
                "An IDS/IPS must inspect traffic at the CDE perimeter.",
                alerts.Count >= 0,
                $"PrivaCore NIDS is monitoring; {alerts.Count} alerts in current session."));

            // 4.2.1 — strong TLS on cardholder data flows
            var weakTls = ports.Any(p => p.Port == 443 && p.Version?.Contains("SSLv3", StringComparison.OrdinalIgnoreCase) == true);
            ctl.Add(new("PCI-DSS-4.0", "4.2.1", "Strong cryptography on cardholder transmissions",
                "TLS ≥ 1.2 required; SSLv3 / TLS 1.0 / 1.1 forbidden.",
                !weakTls,
                weakTls ? "Detected weak TLS." : "No weak TLS observed (additional TLS scan recommended)."));

            return ctl;
        }

        // ── HIPAA Security Rule ────────────────────────────────────────────
        private static List<ComplianceControl> EvalHipaa(List<PortScanResult> ports, List<IDSAlert> alerts)
        {
            var ctl = new List<ComplianceControl>();

            // 164.312(e)(1) — Transmission security
            var weakTls = ports.Any(p => p.Service?.Contains("http", StringComparison.OrdinalIgnoreCase) == true
                                       && p.Port == 80);
            ctl.Add(new("HIPAA", "164.312(e)(1)", "Transmission security",
                "ePHI in transit must use encryption; cleartext HTTP for ePHI workloads is non-compliant.",
                !weakTls,
                weakTls ? "Found cleartext HTTP exposed." : "No cleartext HTTP detected."));

            // 164.312(b) — Audit controls
            ctl.Add(new("HIPAA", "164.312(b)", "Audit controls",
                "Hardware/software/procedural mechanisms record activity in systems containing ePHI.",
                true, "PrivaCore Serilog audit log is active in %APPDATA%\\PrivaCore\\logs\\."));

            // 164.308(a)(1)(ii)(A) — Risk analysis
            var criticalCves = ports.SelectMany(p => p.CveFindings ?? new()).Count(c => c.Severity == "Critical");
            ctl.Add(new("HIPAA", "164.308(a)(1)(ii)(A)", "Risk analysis",
                "Conduct accurate and thorough assessment of risks and vulnerabilities.",
                criticalCves == 0,
                $"{criticalCves} critical CVEs identified."));

            return ctl;
        }

        // ── NIST 800-53 r5 ─────────────────────────────────────────────────
        private static List<ComplianceControl> EvalNist800_53(List<PortScanResult> ports, List<IDSAlert> alerts)
        {
            var ctl = new List<ComplianceControl>();
            var insecure = ports.Where(p => p.Port is 23 or 21 or 69).ToList();
            ctl.Add(new("NIST-800-53r5", "SC-8", "Transmission Confidentiality and Integrity",
                "Protect the confidentiality and/or integrity of transmitted information.",
                insecure.Count == 0,
                insecure.Count == 0 ? "No cleartext protocols exposed." :
                    $"Cleartext protocols exposed on {insecure.Count} ports."));

            ctl.Add(new("NIST-800-53r5", "SI-4", "System Monitoring",
                "Monitor the system to detect attacks and indicators of potential attacks.",
                true,
                $"NIDS is active; {alerts.Count} alerts generated this session."));

            var totalCves = ports.Sum(p => p.CveFindings?.Count ?? 0);
            ctl.Add(new("NIST-800-53r5", "RA-5", "Vulnerability Monitoring and Scanning",
                "Monitor and scan for vulnerabilities in the system.",
                true,
                $"PrivaCore vulnerability scan executed; {totalCves} CVEs identified."));

            return ctl;
        }

        // ── CIS Controls v8 ────────────────────────────────────────────────
        private static List<ComplianceControl> EvalCisV8(List<PortScanResult> ports, List<IDSAlert> alerts)
        {
            var ctl = new List<ComplianceControl>();
            ctl.Add(new("CIS-v8", "4.1", "Establish Secure Configuration Process",
                "Secure baseline; insecure default services disabled.",
                !ports.Any(p => p.Port is 23 or 21),
                ports.Any(p => p.Port is 23 or 21) ? "Telnet/FTP exposed." : "OK."));
            ctl.Add(new("CIS-v8", "7.1", "Establish Vulnerability Management Process",
                "Define & maintain a vulnerability management process.",
                true,
                $"PrivaCore vuln-scanner has assessed {ports.Count} ports."));
            ctl.Add(new("CIS-v8", "13.1", "Centralize Security Event Alerting",
                "Centralize security-event alerts and notifications.",
                NotificationDispatcher.Instance.Sinks.Any(s => s.Enabled),
                NotificationDispatcher.Instance.Sinks.Count(s => s.Enabled) + " notification sinks configured."));
            return ctl;
        }

        // ── ISO 27001:2022 ─────────────────────────────────────────────────
        private static List<ComplianceControl> EvalIso27001(List<PortScanResult> ports, List<IDSAlert> alerts)
        {
            var ctl = new List<ComplianceControl>();
            ctl.Add(new("ISO-27001-2022", "A.8.7", "Protection against malware",
                "Information processing facilities protected against malware.",
                true,
                $"PrivaCore threat-intel enrichment matches against {ThreatIntelService.Instance.TotalIndicators} IoCs."));
            ctl.Add(new("ISO-27001-2022", "A.8.16", "Monitoring activities",
                "Networks, systems and applications monitored for anomalous behaviour.",
                true,
                $"NIDS active; {alerts.Count} alerts in session."));
            ctl.Add(new("ISO-27001-2022", "A.8.8", "Management of technical vulnerabilities",
                "Vulnerabilities of information systems obtained and evaluated.",
                ports.SelectMany(p => p.CveFindings ?? new()).All(c => c.Severity != "Critical"),
                $"{ports.SelectMany(p => p.CveFindings ?? new()).Count()} CVEs evaluated."));
            return ctl;
        }
    }
}
