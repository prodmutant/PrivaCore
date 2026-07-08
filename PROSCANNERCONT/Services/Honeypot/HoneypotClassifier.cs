using System;
using System.Collections.Generic;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Honeypot
{
    /// <summary>
    /// Turns a raw honeypot interaction into intel: detects the attack technique(s) used and
    /// escalates severity accordingly. Runs on every recorded hit so the dashboard/SIEM show
    /// *what kind* of attack it was, not just that a connection happened.
    /// </summary>
    public static class HoneypotClassifier
    {
        // (username, password) pairs that are classic brute-force/default guesses.
        private static readonly HashSet<string> DefaultCreds = new(StringComparer.OrdinalIgnoreCase)
        {
            "admin:admin", "admin:password", "admin:admin123", "admin:1234", "admin:",
            "root:root", "root:toor", "root:password", "root:123456", "root:",
            "user:user", "guest:guest", "pi:raspberry", "administrator:administrator",
            "sa:sa", "oracle:oracle", "postgres:postgres", "test:test",
        };

        private static readonly (string tag, string sev, string[] needles)[] Rules =
        {
            ("RCE",           "Critical", new[] { "wget ", "curl ", "$(", "`", "chmod +x", "/bin/sh", "nc -e", "|sh", "|bash", ";sh", "bash -i",
                                                 "config set", "slaveof", "replicaof", "module load" }),   // incl. Redis RCE tricks
            ("Log4Shell",     "Critical", new[] { "${jndi:" }),
            ("Shellshock",    "Critical", new[] { "() {" }),
            ("SQLi",          "High",     new[] { "' or ", "\" or ", " or 1=1", "union select", "sleep(", "'--", "waitfor delay", "information_schema", "@@version" }),
            ("PathTraversal", "High",     new[] { "../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow", "boot.ini", "/proc/self" }),
            ("XSS",           "Medium",   new[] { "<script", "onerror=", "javascript:" }),
            ("Scanner",       "Medium",   new[] { "sqlmap", "nikto", "masscan", "zgrab", "nmap", "hydra", "gobuster", " dirb", "wpscan", "python-requests", "go-http-client", "curl/", "nuclei" }),
        };

        private static readonly string[] SevOrder = { "Info", "Low", "Medium", "High", "Critical" };

        /// <summary>Detect techniques and escalate severity in place.</summary>
        public static void Apply(HoneypotHit hit)
        {
            if (hit == null) return;
            var hay = string.Join(" ", new[] { hit.Summary, hit.Data, hit.Username, hit.Password }
                .Where(s => !string.IsNullOrEmpty(s))).ToLowerInvariant();

            var tags = new List<string>();
            string sev = hit.Severity;

            foreach (var (tag, ruleSev, needles) in Rules)
                if (needles.Any(n => hay.Contains(n)))
                {
                    tags.Add(tag);
                    sev = Max(sev, ruleSev);
                }

            if (hit.HasCredentials && DefaultCreds.Contains($"{hit.Username}:{hit.Password}"))
            {
                tags.Add("DefaultCreds");
                sev = Max(sev, "High");
            }

            if (tags.Count > 0)
            {
                hit.Tags = hit.Tags.Concat(tags).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                hit.Severity = sev;
            }
        }

        private static string Max(string a, string b)
            => Array.IndexOf(SevOrder, b) > Array.IndexOf(SevOrder, a) ? b : a;
    }
}
