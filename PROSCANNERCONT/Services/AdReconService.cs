using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public sealed class AdUser
    {
        public string SamAccountName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime? LastLogon { get; set; }
        public DateTime? PwdLastSet { get; set; }
        public int UAC { get; set; }
        public List<string> SpNs { get; } = new();
        public bool AsRepRoastable => (UAC & 0x400000) != 0; // DONT_REQ_PREAUTH
        public bool Disabled       => (UAC & 0x0002)   != 0;
        public bool PwdNeverExpires=> (UAC & 0x10000)  != 0;
        public bool Kerberoastable => SpNs.Count > 0 && !Disabled;
    }

    public sealed class AdComputer
    {
        public string SamAccountName { get; set; } = "";
        public string DnsHostName { get; set; } = "";
        public string Os { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public DateTime? PwdLastSet { get; set; }
    }

    public sealed class AdReconReport
    {
        public string Domain { get; set; } = "";
        public List<AdUser> Users { get; } = new();
        public List<AdComputer> Computers { get; } = new();
        public List<string> DomainAdmins { get; } = new();
        public List<string> Findings { get; } = new();
    }

    /// <summary>
    /// Active Directory passive recon via LDAP. Read-only — enumerates users,
    /// computers, group memberships, and flags Kerberoastable / AS-REP-roastable
    /// accounts plus weak password policy and stale-credential indicators.
    ///
    /// Requires either domain-joined run-as or supplied credentials. Use the
    /// CredentialVault to keep AD creds out of memory longer than needed.
    /// </summary>
    public sealed class AdReconService
    {
        public async Task<AdReconReport> EnumerateAsync(
            string ldapServer,
            string domainDn,
            string? username = null,
            string? password = null)
        {
            var report = new AdReconReport { Domain = domainDn };

            await Task.Run(() =>
            {
                var identifier = new LdapDirectoryIdentifier(ldapServer, 389);
                using var conn = string.IsNullOrEmpty(username)
                    ? new LdapConnection(identifier)
                    : new LdapConnection(identifier, new NetworkCredential(username, password));
                conn.SessionOptions.ProtocolVersion = 3;
                conn.Bind();

                // Users
                var userReq = new SearchRequest(domainDn,
                    "(&(objectCategory=person)(objectClass=user))",
                    SearchScope.Subtree,
                    "sAMAccountName", "displayName", "description", "lastLogon",
                    "pwdLastSet", "userAccountControl", "servicePrincipalName");
                userReq.Controls.Add(new PageResultRequestControl(1000));

                var resp = (SearchResponse)conn.SendRequest(userReq);
                foreach (SearchResultEntry e in resp.Entries)
                {
                    var u = new AdUser
                    {
                        SamAccountName = e.Attr("sAMAccountName"),
                        DisplayName    = e.Attr("displayName"),
                        Description    = e.Attr("description"),
                        UAC            = int.TryParse(e.Attr("userAccountControl"), out var uac) ? uac : 0,
                    };
                    if (long.TryParse(e.Attr("lastLogon"), out var ll) && ll > 0)
                        u.LastLogon = DateTime.FromFileTimeUtc(ll);
                    if (long.TryParse(e.Attr("pwdLastSet"), out var pls) && pls > 0)
                        u.PwdLastSet = DateTime.FromFileTimeUtc(pls);
                    foreach (string spn in e.AttrAll("servicePrincipalName")) u.SpNs.Add(spn);
                    report.Users.Add(u);
                }

                // Computers
                var compReq = new SearchRequest(domainDn,
                    "(objectCategory=computer)", SearchScope.Subtree,
                    "sAMAccountName", "dNSHostName", "operatingSystem",
                    "operatingSystemVersion", "pwdLastSet");
                compReq.Controls.Add(new PageResultRequestControl(1000));
                var crsp = (SearchResponse)conn.SendRequest(compReq);
                foreach (SearchResultEntry e in crsp.Entries)
                {
                    var c = new AdComputer
                    {
                        SamAccountName = e.Attr("sAMAccountName"),
                        DnsHostName    = e.Attr("dNSHostName"),
                        Os             = e.Attr("operatingSystem"),
                        OsVersion      = e.Attr("operatingSystemVersion"),
                    };
                    if (long.TryParse(e.Attr("pwdLastSet"), out var pls) && pls > 0)
                        c.PwdLastSet = DateTime.FromFileTimeUtc(pls);
                    report.Computers.Add(c);
                }

                // Domain Admins (members of well-known group)
                var daReq = new SearchRequest(domainDn,
                    "(&(objectClass=group)(cn=Domain Admins))", SearchScope.Subtree, "member");
                var daResp = (SearchResponse)conn.SendRequest(daReq);
                foreach (SearchResultEntry e in daResp.Entries)
                    foreach (string m in e.AttrAll("member")) report.DomainAdmins.Add(m);

                // Findings
                int roast = report.Users.Count(u => u.Kerberoastable);
                int asrep = report.Users.Count(u => u.AsRepRoastable);
                int oldPw = report.Users.Count(u => u.PwdLastSet < DateTime.UtcNow.AddDays(-365));
                int oldComp = report.Computers.Count(c => c.PwdLastSet < DateTime.UtcNow.AddDays(-90));
                int legacyOs = report.Computers.Count(c => c.Os?.Contains("2003") == true
                                                         || c.Os?.Contains("XP") == true
                                                         || c.Os?.Contains("2008") == true);

                if (roast > 0) report.Findings.Add($"HIGH: {roast} Kerberoastable user accounts (have SPNs).");
                if (asrep > 0) report.Findings.Add($"HIGH: {asrep} AS-REP roastable accounts (DONT_REQ_PREAUTH set).");
                if (report.DomainAdmins.Count > 20)
                    report.Findings.Add($"MEDIUM: {report.DomainAdmins.Count} Domain Admin members — review for overprivilege.");
                if (oldPw > 0)
                    report.Findings.Add($"MEDIUM: {oldPw} users haven't rotated password in >365 days.");
                if (oldComp > 0)
                    report.Findings.Add($"MEDIUM: {oldComp} computer accounts haven't rotated password in >90 days (stale).");
                if (legacyOs > 0)
                    report.Findings.Add($"CRITICAL: {legacyOs} computers running legacy OS (XP/2003/2008).");
            });

            return report;
        }
    }

    internal static class LdapEntryExtensions
    {
        public static string Attr(this SearchResultEntry e, string name)
        {
            if (e.Attributes.Contains(name) && e.Attributes[name].Count > 0)
                return e.Attributes[name][0]?.ToString() ?? "";
            return "";
        }
        public static IEnumerable<string> AttrAll(this SearchResultEntry e, string name)
        {
            if (!e.Attributes.Contains(name)) yield break;
            foreach (var v in e.Attributes[name].GetValues(typeof(string)))
                yield return v?.ToString() ?? "";
        }
    }
}
