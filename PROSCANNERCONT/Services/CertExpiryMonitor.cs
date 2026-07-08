using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public sealed record CertObservation(
        string Host,
        int Port,
        string Subject,
        string Issuer,
        DateTime NotBefore,
        DateTime NotAfter,
        string Thumbprint,
        DateTime ObservedAt)
    {
        public int DaysToExpiry => (int)(NotAfter - DateTime.UtcNow).TotalDays;
        public bool IsExpired   => DaysToExpiry < 0;
        public bool IsExpiringSoon => DaysToExpiry >= 0 && DaysToExpiry <= 30;
    }

    /// <summary>
    /// Pulls the TLS leaf certificate from a host:port, persists what it sees,
    /// and surfaces a "expiring within 30 days" view for the Dashboard widget.
    /// Hosts are seeded automatically from PortScannerService when port 443
    /// is found, and from TrafficCaptureService when a TLS handshake is parsed.
    /// </summary>
    public sealed class CertExpiryMonitor
    {
        private static readonly Lazy<CertExpiryMonitor> _instance = new(() => new CertExpiryMonitor());
        public static CertExpiryMonitor Instance => _instance.Value;

        private readonly string _path = Path.Combine(
            AppConstants.Paths.ConfigDir, "cert_observations.json");

        private readonly ConcurrentDictionary<string, CertObservation> _obs = new(StringComparer.OrdinalIgnoreCase);

        public IEnumerable<CertObservation> All => _obs.Values;
        public IEnumerable<CertObservation> ExpiringSoon =>
            _obs.Values.Where(c => c.IsExpiringSoon || c.IsExpired)
                       .OrderBy(c => c.NotAfter);

        private CertExpiryMonitor() => Load();

        /// <summary>Connect to host:port, do a TLS handshake, capture the leaf cert.</summary>
        public async Task<CertObservation?> ProbeAsync(string host, int port = 443, int timeoutMs = 5000)
        {
            try
            {
                using var tcp = new TcpClient();
                var connect = tcp.ConnectAsync(host, port);
                if (await Task.WhenAny(connect, Task.Delay(timeoutMs)).ConfigureAwait(false) != connect)
                    return null;

                using var stream = tcp.GetStream();
                using var ssl = new SslStream(stream, false,
                    (_, __, ___, ____) => true); // accept any — we just want the cert

                await ssl.AuthenticateAsClientAsync(host).ConfigureAwait(false);
                var raw = ssl.RemoteCertificate;
                if (raw == null) return null;
                using var cert = new X509Certificate2(raw);

                var key = $"{host}:{port}";
                var obs = new CertObservation(
                    host, port, cert.Subject, cert.Issuer,
                    cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime(),
                    cert.Thumbprint, DateTime.UtcNow);

                _obs[key] = obs;
                Save();
                AppLogger.Log.Information("[CertMon] {Host}:{Port} expires {Days}d ({NotAfter:yyyy-MM-dd})",
                    host, port, obs.DaysToExpiry, obs.NotAfter);
                return obs;
            }
            catch (Exception ex)
            {
                AppLogger.Log.Debug(ex, "[CertMon] probe failed {Host}:{Port}", host, port);
                return null;
            }
        }

        public Task RefreshAllAsync()
        {
            var tasks = _obs.Values.Select(o => ProbeAsync(o.Host, o.Port)).ToList();
            return Task.WhenAll(tasks);
        }

        // ── Persistence ────────────────────────────────────────────────────
        private void Save()
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                var json = JsonSerializer.Serialize(_obs.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_path, json);
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[CertMon] save failed"); }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_path)) return;
                var list = JsonSerializer.Deserialize<List<CertObservation>>(File.ReadAllText(_path)) ?? new();
                foreach (var o in list) _obs[$"{o.Host}:{o.Port}"] = o;
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[CertMon] load failed"); }
        }
    }
}
