using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    /// <summary>The MITRE ATT&amp;CK enterprise tactics, in kill-chain order (for the coverage matrix).</summary>
    public static class SiemMitre
    {
        public static readonly string[] Tactics =
        {
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        };

        /// <summary>Short label for a tactic chip (some are long).</summary>
        public static string Short(string tactic) => tactic switch
        {
            "Resource Development" => "Resource Dev",
            "Privilege Escalation" => "Priv Esc",
            "Command and Control" => "C2",
            _ => tactic,
        };
    }
}
