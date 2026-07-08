using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public sealed class EmailReconResult
    {
        public string Domain { get; set; } = "";
        public List<string> Mx { get; } = new();
        public string? Spf { get; set; }
        public string? Dmarc { get; set; }
        public string? MtaSts { get; set; }
        public List<string> Findings { get; } = new();
    }

    /// <summary>
    /// Pulls SPF / DMARC / MTA-STS / MX records for a domain via `nslookup`
    /// (shell-out; no DNS library dependency, works on every Windows install).
    /// Used to assess email-spoofing posture for a target — every pentest
    /// engagement gets this question, and now we answer it in one click.
    /// </summary>
    public sealed class EmailReconService
    {
        public async Task<EmailReconResult> ScanAsync(string domain)
        {
            var r = new EmailReconResult { Domain = domain };

            // MX
            var mxText = await NsLookup($"-type=mx {domain}");
            foreach (Match m in Regex.Matches(mxText, @"mail exchanger\s*=\s*(\S+)", RegexOptions.IgnoreCase))
                r.Mx.Add(m.Groups[1].Value.TrimEnd('.'));

            // SPF (lives in TXT records)
            var txt = await NsLookup($"-type=txt {domain}");
            r.Spf = ExtractTxt(txt, @"v=spf1\s+[^""]+");
            if (r.Spf == null) r.Findings.Add("HIGH: No SPF record found — domain spoofable.");
            else if (r.Spf.Contains("+all"))    r.Findings.Add("CRITICAL: SPF +all (allow everyone) — domain wide-open.");
            else if (r.Spf.Contains("~all"))    r.Findings.Add("MEDIUM: SPF ~all (soft-fail) — recipients may still accept spoofed mail.");
            else if (r.Spf.Contains("?all"))    r.Findings.Add("MEDIUM: SPF ?all (neutral) — no enforcement.");

            // DMARC
            var dmarcTxt = await NsLookup($"-type=txt _dmarc.{domain}");
            r.Dmarc = ExtractTxt(dmarcTxt, @"v=DMARC1[^""]+");
            if (r.Dmarc == null) r.Findings.Add("HIGH: No DMARC record found.");
            else
            {
                if (r.Dmarc.Contains("p=none"))       r.Findings.Add("MEDIUM: DMARC p=none — monitoring only, no enforcement.");
                else if (r.Dmarc.Contains("p=quarantine")) r.Findings.Add("INFO: DMARC p=quarantine.");
                else if (r.Dmarc.Contains("p=reject"))     r.Findings.Add("INFO: DMARC p=reject — strong enforcement.");
            }

            // MTA-STS
            var mtaTxt = await NsLookup($"-type=txt _mta-sts.{domain}");
            r.MtaSts = ExtractTxt(mtaTxt, @"v=STSv1[^""]+");
            if (r.MtaSts == null) r.Findings.Add("LOW: No MTA-STS — TLS to MX cannot be enforced cryptographically.");

            return r;
        }

        private static async Task<string> NsLookup(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("nslookup", args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var p = Process.Start(psi)!;
                var stdout = await p.StandardOutput.ReadToEndAsync();
                await p.WaitForExitAsync();
                return stdout;
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Email] nslookup failed"); return ""; }
        }

        private static string? ExtractTxt(string nslookupOutput, string pattern)
        {
            var m = Regex.Match(nslookupOutput, pattern, RegexOptions.IgnoreCase);
            return m.Success ? m.Value.Trim() : null;
        }
    }
}
