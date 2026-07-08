using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Parses Snort/Suricata .rules files into IDSRule objects.
    /// Handles the most common directives: msg, content, pcre, sid, classtype, priority, rev.
    /// </summary>
    public static class SnortRuleParser
    {
        private static readonly Regex _ruleRegex = new(
            @"^(alert|log|pass|drop|reject|sdrop)\s+(\w+)\s+(\S+)\s+(\S+)\s+(-?>|<>)\s+(\S+)\s+(\S+)\s+\((.+)\)\s*$",
            RegexOptions.Singleline | RegexOptions.Compiled);

        private static readonly Regex _optionRegex = new(
            @"(\w[\w-]*)(?:\s*:\s*((?:[^;""\\]|""(?:[^""\\]|\\.)*""|\\.)*))?;",
            RegexOptions.Compiled);

        public static (List<IDSRule> rules, List<string> errors) ParseFile(string content)
        {
            var rules  = new List<IDSRule>();
            var errors = new List<string>();
            int lineNo = 0;

            foreach (var rawLine in content.Split('\n'))
            {
                lineNo++;
                var line = rawLine.Trim();

                // Skip comments and blank lines
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
                // Handle line continuations (Snort allows backslash continuation)
                if (line.StartsWith("$")) continue; // variable definitions

                try
                {
                    var rule = ParseLine(line);
                    if (rule != null) rules.Add(rule);
                }
                catch (Exception ex)
                {
                    errors.Add($"Line {lineNo}: {ex.Message} — {line[..Math.Min(60, line.Length)]}");
                }
            }

            return (rules, errors);
        }

        private static IDSRule? ParseLine(string line)
        {
            var m = _ruleRegex.Match(line);
            if (!m.Success) return null;

            string proto    = m.Groups[2].Value.ToUpper();
            string srcIp    = m.Groups[3].Value;
            string srcPort  = m.Groups[4].Value;
            string dstIp    = m.Groups[6].Value;
            string dstPort  = m.Groups[7].Value;
            string optStr   = m.Groups[8].Value;

            var opts = ParseOptions(optStr);

            // Require a msg and sid at minimum
            if (!opts.TryGetValue("msg",  out var msg) || string.IsNullOrWhiteSpace(msg))  return null;
            if (!opts.TryGetValue("sid",  out var sid) || string.IsNullOrWhiteSpace(sid))  return null;

            opts.TryGetValue("classtype", out var classtype);
            opts.TryGetValue("priority",  out var priority);
            opts.TryGetValue("content",   out var content);
            opts.TryGetValue("pcre",      out var pcre);
            opts.TryGetValue("rev",       out var rev);

            string pattern = BuildPattern(content, pcre);
            IDSAlertSeverity sev = ClasstypeToSeverity(classtype, priority);
            string category = ClasstypeToCategory(classtype);

            // Normalise Snort variable placeholders ($HOME_NET etc.) to "any"
            string normSrc = NormaliseIp(srcIp);
            string normDst = NormaliseIp(dstIp);
            string normSrcPort = NormalisePort(srcPort);
            string normDstPort = NormalisePort(dstPort);
            string normProto = proto == "IP" ? "any" : proto;

            return new IDSRule
            {
                Id             = Guid.NewGuid(),
                RuleId         = $"SNORT-{sid.Trim()}",
                Name           = msg.Trim('"', ' '),
                Description    = $"Imported from Snort/Suricata (sid:{sid.Trim()} rev:{(rev ?? "1").Trim()})",
                IsEnabled      = true,
                Severity       = sev,
                Protocol       = normProto,
                SourceIP       = normSrc,
                DestinationIP  = normDst,
                SourcePort     = normSrcPort,
                DestinationPort = normDstPort,
                Pattern        = pattern,
                AttackCategory = category,
                RuleKind       = RuleKind.Signature,
                CreatedDate    = DateTime.Now,
                ModifiedDate   = DateTime.Now
            };
        }

        private static Dictionary<string, string> ParseOptions(string optStr)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in _optionRegex.Matches(optStr))
            {
                string key = m.Groups[1].Value;
                string val = m.Groups[2].Success ? m.Groups[2].Value.Trim() : "";
                // Keep last value if duplicate (e.g. multiple content keywords — just take last for now)
                dict[key] = val;
            }
            return dict;
        }

        private static string BuildPattern(string? content, string? pcre)
        {
            // Prefer PCRE over content if both present
            if (!string.IsNullOrWhiteSpace(pcre))
            {
                // pcre looks like "/pattern/flags" — extract inner pattern
                var stripped = pcre.Trim();
                if (stripped.StartsWith('"') && stripped.EndsWith('"'))
                    stripped = stripped[1..^1];
                // Remove outer /.../ delimiters
                var innerMatch = Regex.Match(stripped, @"^/(.+)/([gimsI]*)$");
                if (innerMatch.Success) return innerMatch.Groups[1].Value;
                return stripped;
            }
            if (!string.IsNullOrWhiteSpace(content))
            {
                var stripped = content.Trim().Trim('"');
                // Escape regex metacharacters in the literal Snort content string
                return Regex.Escape(stripped);
            }
            return "";
        }

        private static IDSAlertSeverity ClasstypeToSeverity(string? classtype, string? priority)
        {
            if (int.TryParse(priority, out int p))
            {
                return p switch { 1 => IDSAlertSeverity.Critical, 2 => IDSAlertSeverity.High, 3 => IDSAlertSeverity.Medium, _ => IDSAlertSeverity.Low };
            }
            return (classtype?.ToLower()) switch
            {
                "attempted-admin"        => IDSAlertSeverity.Critical,
                "successful-admin"       => IDSAlertSeverity.Critical,
                "shellcode-detect"       => IDSAlertSeverity.Critical,
                "trojan-activity"        => IDSAlertSeverity.Critical,
                "successful-dos"         => IDSAlertSeverity.Critical,
                "web-application-attack" => IDSAlertSeverity.High,
                "attempted-user"         => IDSAlertSeverity.High,
                "attempted-dos"          => IDSAlertSeverity.High,
                "denial-of-service"      => IDSAlertSeverity.High,
                "network-scan"           => IDSAlertSeverity.Medium,
                "misc-attack"            => IDSAlertSeverity.Medium,
                "bad-unknown"            => IDSAlertSeverity.Medium,
                "policy-violation"       => IDSAlertSeverity.Low,
                _                        => IDSAlertSeverity.Medium
            };
        }

        private static string ClasstypeToCategory(string? classtype) =>
            (classtype?.ToLower()) switch
            {
                "attempted-admin" or "successful-admin"         => "Exploit",
                "shellcode-detect" or "trojan-activity"         => "Malware/C2",
                "web-application-attack" or "attempted-user"    => "Web Attack",
                "attempted-dos" or "denial-of-service" or "successful-dos" => "DoS/DDoS",
                "network-scan"                                  => "Reconnaissance",
                "policy-violation"                              => "Suspicious Access",
                _                                               => "Misc"
            };

        private static string NormaliseIp(string ip)
        {
            if (ip.StartsWith('$') || ip == "any" || ip == "!any") return "any";
            // Handle negation and groups — simplify to "any" for now
            if (ip.StartsWith('!') || ip.StartsWith('[')) return "any";
            return ip;
        }

        private static string NormalisePort(string port)
        {
            if (port.StartsWith('$') || port == "any" || port == "!any") return "any";
            if (port.StartsWith('!') || port.StartsWith('[')) return "any";
            // Convert Snort range 1024:65535 to our range format 1024:65535 (compatible)
            return port;
        }
    }
}
