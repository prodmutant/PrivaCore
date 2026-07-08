using System;
using System.Collections.Generic;
using System.Text.Json;
using PROSCANNERCONT.Models;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Services.Honeypot
{
    /// <summary>
    /// Streams captured honeypot interactions from a sensor (host) to the console (client) over the
    /// module channel — the same pattern as the IDS/SIEM bridges. Sensor side broadcasts every hit;
    /// console side injects received hits into its local capture service so the same UI renders them.
    /// SIEM-free so the standalone honeypot module stays lean.
    /// </summary>
    public static class HoneypotModuleBridge
    {
        public const string EvtHit = "honeypot.hit";

        /// <summary>Sensor side: broadcast every captured hit to connected controllers.</summary>
        public static void AttachHost(ModuleHost host)
        {
            HoneypotCaptureService.Instance.HitRecorded += hit =>
                host.Broadcast(EvtHit, new Dictionary<string, object> { ["hit"] = JsonSerializer.Serialize(hit) });
        }

        private static Action<ModuleMessage>? _handler;
        private static ModuleClient? _client;

        /// <summary>Console side: inject hits streamed from the remote sensor into the local capture service.</summary>
        public static void AttachConsole(ModuleClient client)
        {
            DetachConsole();
            _client = client;
            _handler = m =>
            {
                if (m.EventName != EvtHit) return;
                var j = m.Str("hit");
                if (j == null) return;
                try
                {
                    var hit = JsonSerializer.Deserialize<HoneypotHit>(j);
                    if (hit != null) HoneypotCaptureService.Instance.InjectRemote(hit);
                }
                catch { }
            };
            client.EventReceived += _handler;
        }

        public static void DetachConsole()
        {
            if (_client != null && _handler != null) _client.EventReceived -= _handler;
            _client = null; _handler = null;
        }
    }
}
