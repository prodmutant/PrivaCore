using System;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Types of honeypot profiles/configurations
    /// Determines what services and configurations are deployed
    /// </summary>
    public enum HoneypotProfileType
    {
        /// <summary>
        /// Basic honeypot with minimal services
        /// </summary>
        Basic,

        /// <summary>
        /// SSH honeypot (port 22)
        /// </summary>
        SSH,

        /// <summary>
        /// Web server honeypot (HTTP/HTTPS - ports 80, 443)
        /// </summary>
        WebServer,

        /// <summary>
        /// FTP server honeypot (port 21)
        /// </summary>
        FTP,

        /// <summary>
        /// Database honeypot (MySQL, PostgreSQL, MongoDB)
        /// </summary>
        Database,

        /// <summary>
        /// SMB/CIFS file server honeypot (port 445)
        /// </summary>
        FileServer,

        /// <summary>
        /// RDP honeypot (port 3389)
        /// </summary>
        RDP,

        /// <summary>
        /// Mail server honeypot (SMTP, POP3, IMAP)
        /// </summary>
        MailServer,

        /// <summary>
        /// Telnet honeypot (port 23)
        /// </summary>
        Telnet,

        /// <summary>
        /// DNS server honeypot (port 53)
        /// </summary>
        DNS,

        /// <summary>
        /// Custom configuration
        /// </summary>
        Custom,

        /// <summary>
        /// Full stack - all services enabled
        /// </summary>
        FullStack
    }
}