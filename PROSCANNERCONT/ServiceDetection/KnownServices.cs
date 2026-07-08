using System.Collections.Generic;

namespace PROSCANNERCONT.ServiceDetection
{
    /// <summary>
    /// Canonical port-to-service mapping used throughout the app.
    /// Replaces ad-hoc switch statements that mapped ports to service names.
    /// </summary>
    public static class KnownServices
    {
        public static readonly IReadOnlyDictionary<int, string> PortToService =
            new Dictionary<int, string>
            {
                [20]   = "FTP-Data",
                [21]   = "FTP",
                [22]   = "SSH",
                [23]   = "Telnet",
                [25]   = "SMTP",
                [53]   = "DNS",
                [67]   = "DHCP",
                [68]   = "DHCP",
                [69]   = "TFTP",
                [80]   = "HTTP",
                [110]  = "POP3",
                [111]  = "RPC",
                [119]  = "NNTP",
                [123]  = "NTP",
                [135]  = "MSRPC",
                [137]  = "NetBIOS-NS",
                [138]  = "NetBIOS-DGM",
                [139]  = "NetBIOS-SSN",
                [143]  = "IMAP",
                [161]  = "SNMP",
                [162]  = "SNMP-Trap",
                [389]  = "LDAP",
                [443]  = "HTTPS",
                [445]  = "SMB",
                [465]  = "SMTPS",
                [514]  = "Syslog",
                [587]  = "SMTP-Submission",
                [636]  = "LDAPS",
                [993]  = "IMAPS",
                [995]  = "POP3S",
                [1080] = "SOCKS",
                [1433] = "MSSQL",
                [1521] = "Oracle",
                [2049] = "NFS",
                [3306] = "MySQL",
                [3389] = "RDP",
                [5432] = "PostgreSQL",
                [5900] = "VNC",
                [5901] = "VNC",
                [5985] = "WinRM-HTTP",
                [5986] = "WinRM-HTTPS",
                [6379] = "Redis",
                [8080] = "HTTP-Alt",
                [8443] = "HTTPS-Alt",
                [9200] = "Elasticsearch",
                [27017]= "MongoDB",
            };

        /// <summary>
        /// Returns the well-known service name for <paramref name="port"/>,
        /// or <c>"Unknown(port)"</c> if not in the map.
        /// </summary>
        public static string GetServiceName(int port) =>
            PortToService.TryGetValue(port, out var name) ? name : $"Unknown({port})";

        /// <summary>
        /// Returns true when the port is a known service that transmits data unencrypted
        /// and is therefore worth flagging as a risk.
        /// </summary>
        public static bool IsUnencryptedService(int port) =>
            port == 21 || port == 23 || port == 25 || port == 80 ||
            port == 110 || port == 143 || port == 389 || port == 514;
    }
}
