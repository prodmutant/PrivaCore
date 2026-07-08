using System;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Streams SIEM events from a sensor (host) to the console (client) over the module channel.
    /// Sensor side: every ingested event is broadcast. Console side: received events flow into
    /// the local SiemStore so the same dashboard renders them.
    /// </summary>
    public static class SiemModuleBridge
    {
        public const string EvtEvent = "siem.event";
        public const string CmdClear = "siem.clear";
        public const string CmdIngest = "siem.ingest";   // agent → collector: push one event

        public static void AttachHost(ModuleHost host)
        {
            SiemStoreProvider.Current.EventAdded += (_, e) =>
                host.Broadcast(EvtEvent, new() { ["ev"] = JsonSerializer.Serialize(e) });

            // Fleet: keep the agent inventory in step with live connections.
            SiemAgentRegistry.Instance.AttachHost(host);
            host.ClientsChanged += () => SiemAgentRegistry.Instance.Reconcile(host.Connections.Select(c => c.Id));

            host.CommandReceived += (conn, m) =>
            {
                switch (m.EventName)
                {
                    case CmdClear:
                        SiemStoreProvider.Current.Clear();
                        break;
                    case AgentProtocol.CmdEnroll:
                        try
                        {
                            var info = JsonSerializer.Deserialize<AgentEnrollInfo>(m.Str("info") ?? "{}") ?? new();
                            SiemAgentRegistry.Instance.Enroll(conn, info);
                        }
                        catch { }
                        break;
                    case AgentProtocol.CmdCheckin:
                        long.TryParse(m.Str("sent"), out var sent);
                        SiemAgentRegistry.Instance.Checkin(conn, sent);
                        break;
                    case CmdIngest:
                        var j = m.Str("ev");
                        if (j == null) return;
                        try
                        {
                            var e = JsonSerializer.Deserialize<SiemEvent>(j);
                            if (e == null) return;
                            // Stamp the transport origin so an agent can't fully spoof which box it came from.
                            if (string.IsNullOrEmpty(e.Source)) e.Source = conn.Remote;
                            e.Fields["_agent"] = conn.Remote;
                            SiemIngestQueue.Instance.Enqueue(e);   // bounded intake → drains into the store (runs the pipeline)
                        }
                        catch { }
                        break;
                }
            };
        }

        private static Action<ModuleMessage>? _handler;
        private static ModuleClient? _client;

        public static void AttachConsole(ModuleClient client)
        {
            DetachConsole();
            _client = client;
            _handler = m =>
            {
                if (m.EventName != EvtEvent) return;
                var j = m.Str("ev");
                if (j == null) return;
                try { var e = JsonSerializer.Deserialize<SiemEvent>(j); if (e != null) SiemStoreProvider.Current.Add(e, applyPipeline: false); }
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
