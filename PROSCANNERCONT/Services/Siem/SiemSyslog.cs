using System;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Parses syslog lines into <see cref="SiemEvent"/>s. Handles both RFC3164 ("&lt;PRI&gt;message")
    /// and RFC5424 ("&lt;PRI&gt;VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG"). Static + pure so
    /// it's unit-testable independent of the UDP/TCP transport.
    /// </summary>
    public static class SiemSyslog
    {
        public static SiemEvent Parse(string text, string fromIp)
        {
            text = (text ?? "").TrimEnd('\r', '\n', '\0');
            int priority = 0;
            string rest = text;

            // <PRI>
            if (text.StartsWith("<"))
            {
                int gt = text.IndexOf('>');
                if (gt > 1 && int.TryParse(text[1..gt], out priority))
                    rest = text[(gt + 1)..];
            }

            var sev = (priority % 8) switch
            {
                0 or 1 or 2 => SiemSeverity.Critical,
                3 => SiemSeverity.High,
                4 => SiemSeverity.Medium,
                5 => SiemSeverity.Low,
                _ => SiemSeverity.Info,
            };

            string host = fromIp, app = "", msg = rest;
            DateTime ts = DateTime.Now;
            bool rfc5424 = false;

            // RFC5424: first token after PRI is a version (1-2 digits) followed by a space
            int sp = rest.IndexOf(' ');
            if (sp > 0 && sp <= 2 && int.TryParse(rest[..sp], out _))
            {
                rfc5424 = true;
                var parts = rest.Split(' ', 7, StringSplitOptions.None);
                // [0]=version [1]=timestamp [2]=host [3]=app [4]=procid [5]=msgid [6]=SD + MSG
                if (parts.Length >= 7)
                {
                    if (DateTime.TryParse(parts[1], out var pts)) ts = pts;
                    if (parts[2] != "-") host = parts[2];
                    if (parts[3] != "-") app = parts[3];
                    msg = StripStructuredData(parts[6]);
                }
            }

            var e = new SiemEvent
            {
                Timestamp = ts,
                Source = fromIp,
                Host = host,
                Severity = sev,
                Category = "syslog",
                EventType = rfc5424 ? "syslog (rfc5424)" : "syslog",
                Message = msg.Trim(),
                Raw = text,
            };
            e.Fields["host.name"] = host;
            e.Fields["source.ip"] = fromIp;
            e.Fields["log.syslog.priority"] = priority.ToString();
            e.Fields["log.syslog.facility.code"] = (priority / 8).ToString();
            e.Fields["log.syslog.severity.code"] = (priority % 8).ToString();
            e.Fields["event.dataset"] = "syslog";
            if (app.Length > 0) e.Fields["process.name"] = app;
            return e;
        }

        /// <summary>Drop the RFC5424 STRUCTURED-DATA block ("-" or one/more "[...]") and return the message.</summary>
        private static string StripStructuredData(string tail)
        {
            tail = tail.TrimStart();
            if (tail.StartsWith("-")) return tail.Length > 1 ? tail[1..].TrimStart() : "";
            if (!tail.StartsWith("[")) return tail;
            int depth = 0;
            for (int i = 0; i < tail.Length; i++)
            {
                if (tail[i] == '[') depth++;
                else if (tail[i] == ']')
                {
                    depth--;
                    if (depth == 0 && (i + 1 >= tail.Length || tail[i + 1] == ' '))
                        return i + 1 < tail.Length ? tail[(i + 1)..].TrimStart() : "";
                }
            }
            return tail;
        }
    }
}
