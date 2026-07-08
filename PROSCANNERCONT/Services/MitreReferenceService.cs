using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// MITRE ATT&CK technique reference and category-→-technique fallback mapping.
    ///
    /// Every IDS alert now carries a MitreTechniqueId so analysts can pivot
    /// straight to attack.mitre.org and reason about the kill-chain stage
    /// (Reconnaissance → Initial Access → Execution → Persistence → ...).
    /// Built-in rules set the technique explicitly in LoadDefaultRules; user
    /// rules and behavioural detectors fall back to FromCategory().
    /// </summary>
    public static class MitreReferenceService
    {
        public sealed record TechniqueInfo(
            string Id,
            string Name,
            string Tactic,
            string TacticId,
            string Url);

        // Tactic colour scheme — used by alert UI to colour-code badges by tactic.
        private static readonly Dictionary<string, string> _tacticColours = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Reconnaissance"]        = "#7B61FF",
            ["Resource Development"]  = "#9C27B0",
            ["Initial Access"]        = "#E91E63",
            ["Execution"]             = "#F44336",
            ["Persistence"]           = "#FF5722",
            ["Privilege Escalation"]  = "#FF9800",
            ["Defense Evasion"]       = "#FFC107",
            ["Credential Access"]     = "#FFEB3B",
            ["Discovery"]             = "#CDDC39",
            ["Lateral Movement"]      = "#8BC34A",
            ["Collection"]            = "#4CAF50",
            ["Command and Control"]   = "#009688",
            ["Exfiltration"]          = "#00BCD4",
            ["Impact"]                = "#03A9F4",
        };

        private static readonly Dictionary<string, TechniqueInfo> _techniques = new(StringComparer.OrdinalIgnoreCase)
        {
            // Recon
            ["T1595"]      = new("T1595",      "Active Scanning",                  "Reconnaissance",     "TA0043", "https://attack.mitre.org/techniques/T1595/"),
            ["T1595.001"]  = new("T1595.001",  "Scanning IP Blocks",                "Reconnaissance",     "TA0043", "https://attack.mitre.org/techniques/T1595/001/"),
            ["T1595.002"]  = new("T1595.002",  "Vulnerability Scanning",            "Reconnaissance",     "TA0043", "https://attack.mitre.org/techniques/T1595/002/"),
            ["T1046"]      = new("T1046",      "Network Service Discovery",          "Discovery",          "TA0007", "https://attack.mitre.org/techniques/T1046/"),

            // Initial Access / Exploit
            ["T1190"]      = new("T1190",      "Exploit Public-Facing Application", "Initial Access",     "TA0001", "https://attack.mitre.org/techniques/T1190/"),
            ["T1133"]      = new("T1133",      "External Remote Services",          "Initial Access",     "TA0001", "https://attack.mitre.org/techniques/T1133/"),

            // Credential Access
            ["T1110"]      = new("T1110",      "Brute Force",                       "Credential Access",  "TA0006", "https://attack.mitre.org/techniques/T1110/"),
            ["T1110.001"]  = new("T1110.001",  "Password Guessing",                  "Credential Access",  "TA0006", "https://attack.mitre.org/techniques/T1110/001/"),
            ["T1110.003"]  = new("T1110.003",  "Password Spraying",                  "Credential Access",  "TA0006", "https://attack.mitre.org/techniques/T1110/003/"),
            ["T1558.003"]  = new("T1558.003",  "Kerberoasting",                      "Credential Access",  "TA0006", "https://attack.mitre.org/techniques/T1558/003/"),
            ["T1558.004"]  = new("T1558.004",  "AS-REP Roasting",                    "Credential Access",  "TA0006", "https://attack.mitre.org/techniques/T1558/004/"),

            // Defense Evasion / Tunnelling
            ["T1572"]      = new("T1572",      "Protocol Tunneling",                "Command and Control","TA0011", "https://attack.mitre.org/techniques/T1572/"),
            ["T1071.001"]  = new("T1071.001",  "Web Protocols",                     "Command and Control","TA0011", "https://attack.mitre.org/techniques/T1071/001/"),
            ["T1071.004"]  = new("T1071.004",  "DNS",                                "Command and Control","TA0011", "https://attack.mitre.org/techniques/T1071/004/"),

            // C2 / Beaconing
            ["T1071"]      = new("T1071",      "Application Layer Protocol",        "Command and Control","TA0011", "https://attack.mitre.org/techniques/T1071/"),
            ["T1095"]      = new("T1095",      "Non-Application Layer Protocol",    "Command and Control","TA0011", "https://attack.mitre.org/techniques/T1095/"),
            ["T1571"]      = new("T1571",      "Non-Standard Port",                 "Command and Control","TA0011", "https://attack.mitre.org/techniques/T1571/"),

            // DoS / Impact
            ["T1498"]      = new("T1498",      "Network Denial of Service",         "Impact",             "TA0040", "https://attack.mitre.org/techniques/T1498/"),
            ["T1498.001"]  = new("T1498.001",  "Direct Network Flood",              "Impact",             "TA0040", "https://attack.mitre.org/techniques/T1498/001/"),
            ["T1499"]      = new("T1499",      "Endpoint Denial of Service",        "Impact",             "TA0040", "https://attack.mitre.org/techniques/T1499/"),

            // Exfiltration
            ["T1041"]      = new("T1041",      "Exfiltration Over C2 Channel",      "Exfiltration",       "TA0010", "https://attack.mitre.org/techniques/T1041/"),
            ["T1048"]      = new("T1048",      "Exfiltration Over Alternative Protocol", "Exfiltration", "TA0010", "https://attack.mitre.org/techniques/T1048/"),

            // Discovery / MITM
            ["T1557"]      = new("T1557",      "Adversary-in-the-Middle",           "Credential Access",  "TA0006", "https://attack.mitre.org/techniques/T1557/"),
            ["T1557.002"]  = new("T1557.002",  "ARP Cache Poisoning",               "Credential Access",  "TA0006", "https://attack.mitre.org/techniques/T1557/002/"),

            // Web exploitation
            ["T1190.001"]  = new("T1190.001",  "SQL Injection",                     "Initial Access",     "TA0001", "https://attack.mitre.org/techniques/T1190/"),
            ["T1059.007"]  = new("T1059.007",  "JavaScript / XSS",                  "Execution",          "TA0002", "https://attack.mitre.org/techniques/T1059/007/"),

            // HIDS-side
            ["T1078"]      = new("T1078",      "Valid Accounts",                    "Defense Evasion",    "TA0005", "https://attack.mitre.org/techniques/T1078/"),
            ["T1136"]      = new("T1136",      "Create Account",                    "Persistence",        "TA0003", "https://attack.mitre.org/techniques/T1136/"),
            ["T1053"]      = new("T1053",      "Scheduled Task/Job",                "Execution",          "TA0002", "https://attack.mitre.org/techniques/T1053/"),
            ["T1547"]      = new("T1547",      "Boot or Logon Autostart Execution", "Persistence",        "TA0003", "https://attack.mitre.org/techniques/T1547/"),
            ["T1059.001"]  = new("T1059.001",  "PowerShell",                        "Execution",          "TA0002", "https://attack.mitre.org/techniques/T1059/001/"),
        };

        public static TechniqueInfo? Get(string? techniqueId)
        {
            if (string.IsNullOrWhiteSpace(techniqueId)) return null;
            return _techniques.TryGetValue(techniqueId, out var t) ? t : null;
        }

        public static IReadOnlyDictionary<string, TechniqueInfo> All => _techniques;

        /// <summary>
        /// Best-effort mapping from the free-form AttackCategory string used by
        /// legacy rules and behavioural detectors to a MITRE technique. Returns
        /// (TechniqueId, Tactic) so the caller can populate alert fields.
        /// </summary>
        public static (string? TechniqueId, string? Tactic) FromCategory(string? category)
        {
            if (string.IsNullOrWhiteSpace(category)) return (null, null);
            var c = category.Trim().ToLowerInvariant();

            return c switch
            {
                "dos" or "ddos" or "dos/ddos"   => ("T1498",     "Impact"),
                "reconnaissance" or "recon"     => ("T1046",     "Discovery"),
                "port scan"                     => ("T1046",     "Discovery"),
                "brute force"                   => ("T1110",     "Credential Access"),
                "ssh brute force"               => ("T1110.001", "Credential Access"),
                "malware" or "c2" or "beacon"   => ("T1071",     "Command and Control"),
                "web attack" or "sql injection" => ("T1190",     "Initial Access"),
                "xss"                           => ("T1059.007", "Execution"),
                "exploit"                       => ("T1190",     "Initial Access"),
                "exfiltration"                  => ("T1041",     "Exfiltration"),
                "dns tunneling" or "dns tunnel" => ("T1071.004", "Command and Control"),
                "mitm" or "arp spoofing"        => ("T1557.002", "Credential Access"),
                "kerberoast"                    => ("T1558.003", "Credential Access"),
                "as-rep roast" or "asrep"       => ("T1558.004", "Credential Access"),
                _                               => (null, null),
            };
        }

        public static string TacticColour(string? tactic)
        {
            if (string.IsNullOrWhiteSpace(tactic)) return "#666666";
            return _tacticColours.TryGetValue(tactic, out var c) ? c : "#666666";
        }
    }
}
