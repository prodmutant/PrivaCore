using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    /// <summary>The kind of decoy service an attacker interacted with.</summary>
    public enum HoneypotServiceKind
    {
        Telnet,   // plaintext login prompt + fake shell — captures username/password/commands
        Http,     // fake web service / custom site — captures method/path/headers/credentials
        Ssh,      // SSH banner exchange — captures client version + probe
        Ftp,      // plaintext FTP — captures USER/PASS
        Raw,      // generic TCP — captures the first bytes sent
        Redis,    // Redis (RESP) — captures commands (CONFIG SET / SLAVEOF RCE, AUTH)
        Smtp,     // SMTP — captures AUTH credentials + MAIL/RCPT relay attempts
        Mysql,    // MySQL handshake — captures the login username
        Rdp,      // RDP — captures the mstshash username from the connection request
    }

    /// <summary>
    /// One recorded interaction with a decoy service: who connected, to what, and what they tried.
    /// This is the payload a real honeypot exists to produce (the previous dashboard never recorded any).
    /// </summary>
    public sealed class HoneypotHit
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public HoneypotServiceKind Service { get; set; }
        public string ServiceName => Service.ToString().ToUpperInvariant();
        public int Port { get; set; }

        public string SourceIp { get; set; } = "";
        public int SourcePort { get; set; }

        /// <summary>Short human summary, e.g. "login admin/123456" or "GET /admin".</summary>
        public string Summary { get; set; } = "";

        public string? Username { get; set; }
        public string? Password { get; set; }

        /// <summary>Captured payload / banner / request (already truncated for safety).</summary>
        public string? Data { get; set; }

        /// <summary>Info | Low | Medium | High | Critical — maps to SiemSeverity when bridged.</summary>
        public string Severity { get; set; } = "Medium";

        /// <summary>Attack techniques detected in this interaction (set by HoneypotClassifier).</summary>
        public List<string> Tags { get; set; } = new();

        /// <summary>True when the hit carried credentials (the most valuable signal).</summary>
        public bool HasCredentials => !string.IsNullOrEmpty(Username) || !string.IsNullOrEmpty(Password);

        public string TimeText => Timestamp.ToString("HH:mm:ss");
        public string TagsText => Tags.Count == 0 ? "" : string.Join(", ", Tags);
    }
}
