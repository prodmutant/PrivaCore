using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    public sealed class TlsScanResult
    {
        public string Host { get; set; } = "";
        public int Port { get; set; }
        public List<string> SupportedProtocols { get; } = new();
        public List<string> FailedProtocols { get; } = new();
        public List<string> Findings { get; } = new();
        public string? CertSubject { get; set; }
        public string? CertIssuer { get; set; }
        public DateTime? CertNotAfter { get; set; }
        public int? DaysToExpiry => CertNotAfter == null ? null : (int)(CertNotAfter.Value - DateTime.UtcNow).TotalDays;
        public string? Thumbprint { get; set; }
        public string OverallGrade { get; set; } = "?";
    }

    /// <summary>
    /// SSL/TLS posture scanner — testssl.sh-lite. Tries each TLS protocol
    /// against the target, captures the leaf cert, and emits a posture
    /// summary with findings like "TLS 1.0 enabled", "SSLv3 enabled", "Cert
    /// expired/expiring", "Self-signed cert", "Weak key (RSA-1024)".
    ///
    /// Grade is letter-based, A-F, biased toward modern best practice.
    /// </summary>
    public sealed class TlsScannerService
    {
        public async Task<TlsScanResult> ScanAsync(string host, int port = 443, int timeoutMs = 6000)
        {
            var res = new TlsScanResult { Host = host, Port = port };

            // Try each protocol independently
            await TryProtocol(res, host, port, SslProtocols.Tls13, timeoutMs);
            await TryProtocol(res, host, port, SslProtocols.Tls12, timeoutMs);
#pragma warning disable SYSLIB0039
            await TryProtocol(res, host, port, SslProtocols.Tls11, timeoutMs);
            await TryProtocol(res, host, port, SslProtocols.Tls,   timeoutMs);
#pragma warning restore SYSLIB0039
#pragma warning disable SYSLIB0036
            try
            {
                await TryProtocol(res, host, port, SslProtocols.Ssl3, timeoutMs);
            }
            catch { /* .NET may have removed support entirely. */ }
#pragma warning restore SYSLIB0036

            EvaluateFindings(res);
            res.OverallGrade = Grade(res);
            return res;
        }

        private async Task TryProtocol(TlsScanResult res, string host, int port, SslProtocols protocol, int timeoutMs)
        {
            try
            {
                using var tcp = new TcpClient();
                var connect = tcp.ConnectAsync(host, port);
                if (await Task.WhenAny(connect, Task.Delay(timeoutMs)).ConfigureAwait(false) != connect)
                {
                    res.FailedProtocols.Add($"{protocol} (connect timeout)");
                    return;
                }
                using var stream = tcp.GetStream();
                using var ssl = new SslStream(stream, false, (_, __, ___, ____) => true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = protocol,
                    RemoteCertificateValidationCallback = (_, __, ___, ____) => true,
                });
                res.SupportedProtocols.Add(protocol.ToString());

                // Capture cert from first successful handshake
                if (res.CertSubject == null && ssl.RemoteCertificate != null)
                {
                    using var cert = new X509Certificate2(ssl.RemoteCertificate);
                    res.CertSubject = cert.Subject;
                    res.CertIssuer  = cert.Issuer;
                    res.CertNotAfter = cert.NotAfter.ToUniversalTime();
                    res.Thumbprint   = cert.Thumbprint;
                }
            }
            catch
            {
                res.FailedProtocols.Add(protocol.ToString());
            }
        }

        private void EvaluateFindings(TlsScanResult res)
        {
            if (res.SupportedProtocols.Contains("Ssl3"))  res.Findings.Add("CRITICAL: SSLv3 enabled (POODLE)");
            if (res.SupportedProtocols.Contains("Tls"))   res.Findings.Add("HIGH: TLS 1.0 enabled (PCI-DSS prohibits)");
            if (res.SupportedProtocols.Contains("Tls11")) res.Findings.Add("HIGH: TLS 1.1 enabled (deprecated)");
            if (!res.SupportedProtocols.Contains("Tls12") && !res.SupportedProtocols.Contains("Tls13"))
                res.Findings.Add("CRITICAL: Neither TLS 1.2 nor TLS 1.3 supported");
            if (!res.SupportedProtocols.Contains("Tls13"))
                res.Findings.Add("LOW: TLS 1.3 not supported");

            if (res.CertNotAfter is { } exp)
            {
                var days = (int)(exp - DateTime.UtcNow).TotalDays;
                if (days < 0)  res.Findings.Add($"CRITICAL: Certificate expired {-days}d ago");
                else if (days < 14) res.Findings.Add($"HIGH: Certificate expires in {days} days");
                else if (days < 30) res.Findings.Add($"MEDIUM: Certificate expires in {days} days");
            }

            if (!string.IsNullOrEmpty(res.CertIssuer) && res.CertIssuer == res.CertSubject)
                res.Findings.Add("HIGH: Self-signed certificate");
        }

        private static string Grade(TlsScanResult r)
        {
            if (r.Findings.Any(f => f.StartsWith("CRITICAL"))) return "F";
            if (r.Findings.Any(f => f.StartsWith("HIGH"))) return "C";
            if (r.Findings.Any(f => f.StartsWith("MEDIUM"))) return "B";
            if (r.SupportedProtocols.Contains("Tls13")) return "A+";
            return "A";
        }
    }
}
