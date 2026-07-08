using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Mail;
using System.Text.Json;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public enum NotificationChannel { Slack, Discord, Teams, Generic, Email }

    public sealed class NotificationSink
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = "";
        public NotificationChannel Channel { get; set; }
        public string Endpoint { get; set; } = ""; // webhook URL or smtp host
        public string? Username { get; set; }       // SMTP auth
        public string? PasswordSecretKey { get; set; } // key into SecretsManager
        public int? SmtpPort { get; set; }
        public string? FromAddress { get; set; }
        public string? ToAddress { get; set; }
        public bool Enabled { get; set; } = true;
        /// <summary>Only fire for severity ≥ this value.</summary>
        public IDSAlertSeverity MinSeverity { get; set; } = IDSAlertSeverity.High;
        /// <summary>If set, only fire when alert's MitreTactic matches.</summary>
        public string? FilterTactic { get; set; }
    }

    /// <summary>
    /// Fan-out alert dispatcher for Slack/Discord/Teams/generic-JSON webhooks
    /// and SMTP email. Subscribes to IDSManager.Engine.AlertGenerated and
    /// filters per sink. All sinks share a single HttpClient and use simple
    /// per-channel JSON payload templates — no provider SDKs required.
    /// </summary>
    public sealed class NotificationDispatcher
    {
        private static readonly Lazy<NotificationDispatcher> _instance =
            new(() => new NotificationDispatcher());
        public static NotificationDispatcher Instance => _instance.Value;

        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
        private readonly string _path = Path.Combine(AppConstants.Paths.ConfigDir, "notification_sinks.json");
        private readonly object _lock = new();
        private List<NotificationSink> _sinks = new();

        private NotificationDispatcher()
        {
            Load();
            // Wire to IDS alert stream
            try
            {
                IDSManager.Engine.AlertGenerated += (_, alert) => _ = DispatchAsync(alert);
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Notify] IDS hook failed"); }
        }

        public IReadOnlyList<NotificationSink> Sinks
        {
            get { lock (_lock) return _sinks.ToList(); }
        }

        public void AddOrUpdate(NotificationSink s)
        {
            lock (_lock)
            {
                var i = _sinks.FindIndex(x => x.Id == s.Id);
                if (i >= 0) _sinks[i] = s; else _sinks.Add(s);
                Save();
            }
        }

        public void Remove(Guid id)
        {
            lock (_lock) { _sinks.RemoveAll(s => s.Id == id); Save(); }
        }

        public async Task DispatchAsync(IDSAlert alert)
        {
            List<NotificationSink> sinks;
            lock (_lock) sinks = _sinks.Where(s => s.Enabled && (int)alert.Severity >= (int)s.MinSeverity).ToList();
            if (sinks.Count == 0) return;

            foreach (var sink in sinks)
            {
                if (!string.IsNullOrEmpty(sink.FilterTactic)
                 && !string.Equals(sink.FilterTactic, alert.MitreTactic, StringComparison.OrdinalIgnoreCase))
                    continue;
                try { await SendOne(sink, alert).ConfigureAwait(false); }
                catch (Exception ex) { AppLogger.Log.Warning(ex, "[Notify] {Channel} send failed", sink.Channel); }
            }
        }

        private async Task SendOne(NotificationSink s, IDSAlert a)
        {
            string title = $"[PrivaCore] {a.Severity}: {a.AlertType}";
            string body  = $"{a.Description}\nSource: {a.SourceIP}:{a.SourcePort}\nDest: {a.DestinationIP}:{a.DestinationPort}" +
                           (string.IsNullOrEmpty(a.MitreTechniqueId) ? "" : $"\nMITRE: {a.MitreTechniqueId} ({a.MitreTactic})") +
                           (string.IsNullOrEmpty(a.ThreatIntelTags)  ? "" : $"\nThreat-Intel: {a.ThreatIntelTags}");

            switch (s.Channel)
            {
                case NotificationChannel.Slack:
                    await _http.PostAsJsonAsync(s.Endpoint, new { text = $"*{title}*\n{body}" }).ConfigureAwait(false);
                    break;
                case NotificationChannel.Discord:
                    await _http.PostAsJsonAsync(s.Endpoint, new { content = $"**{title}**\n{body}" }).ConfigureAwait(false);
                    break;
                case NotificationChannel.Teams:
                    await _http.PostAsJsonAsync(s.Endpoint, new {
                        type = "message",
                        text = $"**{title}**\n\n{body}"
                    }).ConfigureAwait(false);
                    break;
                case NotificationChannel.Generic:
                    await _http.PostAsJsonAsync(s.Endpoint, new {
                        title, body,
                        severity = a.Severity.ToString(),
                        sourceIp = a.SourceIP, destIp = a.DestinationIP, port = a.DestinationPort,
                        mitre = a.MitreTechniqueId, tactic = a.MitreTactic,
                        threatIntel = a.ThreatIntelTags,
                        timestamp = a.Timestamp,
                    }).ConfigureAwait(false);
                    break;
                case NotificationChannel.Email:
                    await SendEmail(s, title, body).ConfigureAwait(false);
                    break;
            }
        }

        private async Task SendEmail(NotificationSink s, string subject, string body)
        {
            if (string.IsNullOrEmpty(s.Endpoint) || string.IsNullOrEmpty(s.FromAddress) || string.IsNullOrEmpty(s.ToAddress))
                return;

            using var client = new SmtpClient(s.Endpoint, s.SmtpPort ?? 587) { EnableSsl = true };
            if (!string.IsNullOrEmpty(s.Username) && !string.IsNullOrEmpty(s.PasswordSecretKey))
                client.Credentials = new System.Net.NetworkCredential(
                    s.Username, SecretsManager.Get(s.PasswordSecretKey));

            using var msg = new MailMessage(s.FromAddress!, s.ToAddress!) { Subject = subject, Body = body };
            await client.SendMailAsync(msg).ConfigureAwait(false);
        }

        // ── Persistence ────────────────────────────────────────────────────
        private void Save()
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                File.WriteAllText(_path,
                    JsonSerializer.Serialize(_sinks, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Notify] save failed"); }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_path)) return;
                _sinks = JsonSerializer.Deserialize<List<NotificationSink>>(File.ReadAllText(_path)) ?? new();
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Notify] load failed"); }
        }
    }
}
