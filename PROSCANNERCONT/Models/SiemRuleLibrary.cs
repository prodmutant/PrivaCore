using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// A catalog of ready-made detection rules (the "prebuilt rules" of Elastic Security), tagged
    /// with MITRE ATT&amp;CK technique + tactic. Each entry is a template the user can add and tweak.
    /// </summary>
    public static class SiemRuleLibrary
    {
        public static List<SiemRule> All() => new()
        {
            // ── Reconnaissance ──
            R("Port scan reconnaissance", "event.action:port_scan", SiemRuleType.GroupThreshold, "source.ip", 1, 10,
                SiemSeverity.Medium, "T1046", "Network Service Discovery", "Reconnaissance"),

            // ── Initial Access ──
            R("Firewall block flood from one source", "event.action:denied", SiemRuleType.GroupThreshold, "source.ip", 25, 5,
                SiemSeverity.Medium, "T1190", "Exploit Public-Facing Application", "Initial Access"),
            R("Suspicious access to sensitive URI (.env / wp-login)", "url.path:.env", SiemRuleType.Threshold, "", 3, 10,
                SiemSeverity.Medium, "T1190", "Exploit Public-Facing Application", "Initial Access"),

            // ── Execution ──
            R("Malware detected", "category:threat malware", SiemRuleType.Threshold, "", 1, 5,
                SiemSeverity.Critical, "T1059", "Command and Scripting Interpreter", "Execution"),
            R("Suspicious script interpreter launched", "process.name:powershell.exe", SiemRuleType.GroupThreshold, "host.name", 20, 5,
                SiemSeverity.Low, "T1059.001", "PowerShell", "Execution"),

            // ── Persistence ──
            R("New service installed", "winlog.event_id:7045", SiemRuleType.Threshold, "", 1, 30,
                SiemSeverity.Medium, "T1543.003", "Windows Service", "Persistence"),
            R("New user account created", "winlog.event_id:4720", SiemRuleType.Threshold, "", 1, 30,
                SiemSeverity.Medium, "T1136", "Create Account", "Persistence"),

            // ── Privilege Escalation ──
            R("Account added to privileged group", "winlog.event_id:4728", SiemRuleType.Threshold, "", 1, 30,
                SiemSeverity.High, "T1098", "Account Manipulation", "Privilege Escalation"),
            R("Special privileges assigned at logon", "winlog.event_id:4672", SiemRuleType.GroupThreshold, "user.name", 5, 10,
                SiemSeverity.Medium, "T1078", "Valid Accounts", "Privilege Escalation"),

            // ── Defense Evasion ──
            R("Audit log cleared", "winlog.event_id:1102", SiemRuleType.Threshold, "", 1, 60,
                SiemSeverity.High, "T1070.001", "Clear Windows Event Logs", "Defense Evasion"),

            // ── Credential Access ──
            R("Brute force — failed logons from one source", "event.action:logon event.outcome:failure", SiemRuleType.GroupThreshold, "source.ip", 10, 5,
                SiemSeverity.High, "T1110", "Brute Force", "Credential Access"),
            R("Password spraying — one source, sustained failures", "event.action:logon event.outcome:failure", SiemRuleType.GroupThreshold, "source.ip", 20, 15,
                SiemSeverity.High, "T1110.003", "Password Spraying", "Credential Access"),
            R("Account lockout burst", "winlog.event_id:4740", SiemRuleType.Threshold, "", 3, 10,
                SiemSeverity.High, "T1110", "Brute Force", "Credential Access"),

            // ── Discovery ──
            R("Account enumeration via explicit credentials", "winlog.event_id:4648", SiemRuleType.GroupThreshold, "user.name", 10, 10,
                SiemSeverity.Medium, "T1087", "Account Discovery", "Discovery"),

            // ── Credential Access (correlation) ──
            new SiemRule
            {
                Name = "Successful logon after brute force (sequence)",
                Query = "event.action:logon event.outcome:failure",
                SecondQuery = "event.action:logon event.outcome:success",
                Type = SiemRuleType.Sequence, GroupBy = "source.ip",
                Threshold = 5, WindowMinutes = 10, Severity = SiemSeverity.Critical,
                MitreId = "T1110", MitreName = "Brute Force", MitreTactic = "Credential Access",
            },

            // ── Lateral Movement ──
            R("Remote interactive logon surge", "logon.type:10 RemoteInteractive", SiemRuleType.GroupThreshold, "source.ip", 5, 10,
                SiemSeverity.Medium, "T1021", "Remote Services", "Lateral Movement"),

            // ── Command and Control ──
            R("Beaconing to suspicious destination", "category:network", SiemRuleType.GroupThreshold, "destination.ip", 50, 5,
                SiemSeverity.Medium, "T1071", "Application Layer Protocol", "Command and Control"),

            // ── Impact ──
            R("HTTP server errors spike", "http.response.status_code:500", SiemRuleType.Threshold, "", 15, 5,
                SiemSeverity.Low, "T1499", "Endpoint Denial of Service", "Impact"),
        };

        private static SiemRule R(string name, string query, SiemRuleType type, string groupBy, int threshold,
            int windowMin, SiemSeverity sev, string mitreId, string mitreName, string tactic) => new()
        {
            Name = name, Query = query, Type = type, GroupBy = groupBy, Threshold = threshold,
            WindowMinutes = windowMin, Severity = sev, MitreId = mitreId, MitreName = mitreName, MitreTactic = tactic,
        };

        /// <summary>A fresh copy with a new Id so the same template can be added multiple times.</summary>
        public static SiemRule Clone(SiemRule t) => new()
        {
            Name = t.Name, Query = t.Query, SecondQuery = t.SecondQuery, ExcludeQuery = t.ExcludeQuery, Type = t.Type, GroupBy = t.GroupBy,
            Threshold = t.Threshold, WindowMinutes = t.WindowMinutes, Severity = t.Severity,
            MitreId = t.MitreId, MitreName = t.MitreName, MitreTactic = t.MitreTactic, WebhookUrl = t.WebhookUrl, Enabled = true,
        };
    }
}
