using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Alerting action: POST a fired alert to a webhook (Slack/Teams/generic JSON connector).
    /// Payload includes a Slack/Teams-friendly "text" field plus structured alert fields.
    /// </summary>
    public static class SiemWebhook
    {
        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

        /// <summary>Build the JSON payload for an alert (pure, unit-testable).</summary>
        public static string BuildPayload(SiemAlert a)
        {
            var text = $"[{a.SeverityText.ToUpperInvariant()}] {a.RuleName} — {a.Message}"
                       + (string.IsNullOrEmpty(a.MitreId) ? "" : $" ({a.MitreText})");
            var payload = new
            {
                text,                                   // Slack / Teams compatible
                rule = a.RuleName,
                severity = a.SeverityText,
                message = a.Message,
                count = a.Count,
                mitre = a.MitreId,
                tactic = a.MitreTactic,
                timestamp = a.Timestamp.ToString("o"),
                source = "PrivaCore SIEM",
            };
            return JsonSerializer.Serialize(payload);
        }

        /// <summary>Fire-and-forget POST of an alert to a webhook URL. Never throws.</summary>
        public static void Send(string url, SiemAlert a)
        {
            if (string.IsNullOrWhiteSpace(url)) return;
            var json = BuildPayload(a);
            _ = System.Threading.Tasks.Task.Run(async () =>
            {
                try
                {
                    using var content = new StringContent(json, Encoding.UTF8, "application/json");
                    await _http.PostAsync(url, content);
                }
                catch { /* alerting must never break the engine */ }
            });
        }
    }
}
