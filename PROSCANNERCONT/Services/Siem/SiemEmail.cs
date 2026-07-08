using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>Persisted SMTP settings for email alert notifications (the collector's outbound mail config).</summary>
    public sealed class SiemEmailSettings
    {
        public bool Enabled { get; set; }
        public string Host { get; set; } = "";
        public int Port { get; set; } = 587;
        public bool UseSsl { get; set; } = true;
        public string From { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";

        public bool IsConfigured => Enabled && !string.IsNullOrWhiteSpace(Host) && !string.IsNullOrWhiteSpace(From);

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_email.json");

        private static SiemEmailSettings? _current;
        public static SiemEmailSettings Current => _current ??= Load();

        public static SiemEmailSettings Load()
        {
            try { if (File.Exists(Path_)) return JsonSerializer.Deserialize<SiemEmailSettings>(File.ReadAllText(Path_)) ?? new(); }
            catch { }
            return new SiemEmailSettings();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
                _current = this;
            }
            catch { }
        }
    }

    /// <summary>
    /// Alerting action: email a fired alert over SMTP (the #1 real-world alert channel, alongside the
    /// webhook connector). Message-building is pure/testable; the actual send is fire-and-forget and never throws.
    /// </summary>
    public static class SiemEmail
    {
        /// <summary>Build the email subject + body for an alert (pure, unit-testable).</summary>
        public static (string subject, string body) BuildMessage(SiemAlert a)
        {
            var subject = $"[PrivaCore SIEM] {a.SeverityText.ToUpperInvariant()}: {a.RuleName}";
            var body =
                $"{a.RuleName}\n\n{a.Message}\n\n" +
                $"Severity : {a.SeverityText}\n" +
                $"Risk     : {a.RiskScore}\n" +
                $"Count    : {a.Count}\n" +
                (string.IsNullOrEmpty(a.GroupValue) ? "" : $"Entity   : {a.GroupValue}\n") +
                (string.IsNullOrEmpty(a.MitreId) ? "" : $"MITRE    : {a.MitreText}{(string.IsNullOrEmpty(a.MitreTactic) ? "" : $" / {a.MitreTactic}")}\n") +
                $"Time     : {a.Timestamp:u}\n\n— PrivaCore SIEM";
            return (subject, body);
        }

        /// <summary>Fire-and-forget email of an alert to one or more (comma-separated) recipients. Never throws.</summary>
        public static void Send(SiemEmailSettings cfg, string to, SiemAlert a)
        {
            if (cfg == null || !cfg.IsConfigured || string.IsNullOrWhiteSpace(to)) return;
            var (subject, body) = BuildMessage(a);
            _ = System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    using var msg = new MailMessage { From = new MailAddress(cfg.From), Subject = subject, Body = body };
                    foreach (var r in to.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                        msg.To.Add(r.Trim());
                    using var client = new SmtpClient(cfg.Host, cfg.Port) { EnableSsl = cfg.UseSsl };
                    if (!string.IsNullOrEmpty(cfg.Username)) client.Credentials = new NetworkCredential(cfg.Username, cfg.Password);
                    client.Send(msg);
                }
                catch { /* alerting must never break the engine */ }
            });
        }
    }
}
