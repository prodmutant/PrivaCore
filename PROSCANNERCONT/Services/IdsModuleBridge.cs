using System;
using System.Collections.Generic;
using System.Text.Json;
using PROSCANNERCONT.Models;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Two-way IDS control bridge shared by the sensor (host) and the console (client).
    /// Maps IDS alerts/state to the module data-flow channel and wires commands both ways
    /// so Start/Stop and rule edits reflect instantly on both sides.
    /// </summary>
    public static class IdsModuleBridge
    {
        // module -> console events
        public const string AlertEvent = "ids.alert";
        public const string EvtState   = "ids.state";
        public const string EvtRules   = "ids.rules";
        public const string EvtInterfaces = "ids.interfaces";
        // console -> module commands
        public const string CmdStart      = "ids.start";
        public const string CmdStop       = "ids.stop";
        public const string CmdRuleAdd    = "ids.rule.add";
        public const string CmdRuleUpdate = "ids.rule.update";
        public const string CmdRuleDelete = "ids.rule.delete";
        public const string CmdRuleToggle = "ids.rule.toggle";

        // ── alert mapping ──
        public static Dictionary<string, object> ToEventData(IDSAlert a) => new()
        {
            ["severity"] = a.Severity.ToString(),
            ["alertType"] = a.AlertType ?? "",
            ["source"] = a.SourceIP ?? "",
            ["dest"] = a.DestinationIP ?? "",
            ["protocol"] = a.Protocol ?? "",
            ["description"] = a.Description ?? "",
            ["ts"] = a.Timestamp.ToString("o"),
        };

        public static IDSAlert FromEvent(ModuleMessage m) => new()
        {
            AlertId = Guid.NewGuid(),
            Timestamp = DateTime.TryParse(m.Str("ts"), out var t) ? t : DateTime.Now,
            Severity = Enum.TryParse<IDSAlertSeverity>(m.Str("severity"), out var s) ? s : IDSAlertSeverity.Info,
            AlertType = string.IsNullOrEmpty(m.Str("alertType")) ? "Remote alert" : m.Str("alertType")!,
            SourceIP = m.Str("source") ?? "",
            DestinationIP = m.Str("dest") ?? "",
            Protocol = m.Str("protocol") ?? "",
            Description = m.Str("description") ?? "",
        };

        private static IDSRule? DeserRule(string? json)
        {
            try { return json == null ? null : JsonSerializer.Deserialize<IDSRule>(json); }
            catch { return null; }
        }

        /// <summary>Sensor side: apply console commands to the local engine and stream state out.</summary>
        public static void AttachHost(ModuleHost host)
        {
            var eng = IDSManager.Engine;

            host.CommandReceived += (conn, msg) =>
            {
                switch (msg.EventName)
                {
                    case CmdStart: try { eng.StartCapture(int.TryParse(msg.Str("device"), out var di) ? di : 0); } catch { } break;
                    case CmdStop: eng.StopCapture(); break;
                    case CmdRuleAdd: { var r = DeserRule(msg.Str("rule")); if (r != null) eng.AddRule(r); } break;
                    case CmdRuleUpdate: { var r = DeserRule(msg.Str("rule")); if (r != null) eng.UpdateRule(r); } break;
                    case CmdRuleDelete: if (Guid.TryParse(msg.Str("id"), out var d)) eng.DeleteRule(d); break;
                    case CmdRuleToggle: if (Guid.TryParse(msg.Str("id"), out var tg)) eng.ToggleRule(tg, bool.TryParse(msg.Str("en"), out var en) && en); break;
                }
            };

            eng.RunningChanged += (_, _) => host.Broadcast(EvtState, new() { ["running"] = eng.IsRunning });
            eng.RulesChanged += (_, _) => host.Broadcast(EvtRules, new() { ["rules"] = eng.ExportRulesJson() });
            eng.AlertGenerated += (_, a) => host.Broadcast(AlertEvent, ToEventData(a));
            // Push current state whenever a controller connects/disconnects.
            host.ClientsChanged += () =>
            {
                host.Broadcast(EvtState, new() { ["running"] = eng.IsRunning });
                host.Broadcast(EvtRules, new() { ["rules"] = eng.ExportRulesJson() });
                host.Broadcast(EvtInterfaces, new() { ["ifaces"] = JsonSerializer.Serialize(eng.LocalInterfaces()) });
            };
        }

        /// <summary>
        /// Console side: route local IDS-page actions to the remote sensor and apply the
        /// state the sensor streams back. <paramref name="post"/> marshals to the UI thread.
        /// </summary>
        public static void AttachConsole(ModuleClient client, Action<Action> post)
        {
            var eng = IDSManager.Engine;
            eng.RemoteControl = (cmd, data) => { _ = client.SendCommandAsync(cmd, data); return true; };
            client.Disconnected += () => post(DetachConsole);

            client.EventReceived += msg => post(() =>
            {
                switch (msg.EventName)
                {
                    case AlertEvent: eng.IngestExternalAlert(FromEvent(msg)); break;
                    case EvtState: eng.ApplyRemoteRunning(bool.TryParse(msg.Str("running"), out var b) && b); break;
                    case EvtRules: { var j = msg.Str("rules"); if (j != null) eng.ApplyRemoteRules(j); } break;
                    case EvtInterfaces:
                        {
                            var j = msg.Str("ifaces");
                            var list = j == null ? null : JsonSerializer.Deserialize<List<string>>(j);
                            if (list != null) eng.ApplyRemoteInterfaces(list);
                        }
                        break;
                }
            });
        }

        public static void DetachConsole() => IDSManager.Engine.RemoteControl = null;
    }
}
