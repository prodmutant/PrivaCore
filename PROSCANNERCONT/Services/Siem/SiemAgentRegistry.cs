using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>A managed agent in the Fleet inventory (one connected/enrolled PrivaCore agent).</summary>
    public sealed class AgentInfo
    {
        public Guid ConnId { get; set; }
        public string Name { get; set; } = "";
        public string Host { get; set; } = "";
        public string Os { get; set; } = "";
        public string Version { get; set; } = "";
        public string Remote { get; set; } = "";
        public string Sources { get; set; } = "";
        public DateTime EnrolledUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastCheckinUtc { get; set; } = DateTime.UtcNow;
        public long EventsSent { get; set; }
        public bool Online { get; set; } = true;
        public AgentPolicy Policy { get; set; } = new();

        internal ModuleConnection? Conn;

        public string StatusText => Online ? "ONLINE" : "OFFLINE";
        public string StatusColor => Online ? "#56D364" : "#6E7681";
        public string EventsText => EventsSent.ToString("N0");
        public string OsShort => Os.Length > 40 ? Os[..40] + "…" : Os;
        public string LastSeenText
        {
            get
            {
                var ago = DateTime.UtcNow - LastCheckinUtc;
                if (ago.TotalSeconds < 60) return $"{(int)ago.TotalSeconds}s ago";
                if (ago.TotalMinutes < 60) return $"{(int)ago.TotalMinutes}m ago";
                if (ago.TotalHours < 24) return $"{(int)ago.TotalHours}h ago";
                return LastCheckinUtc.ToLocalTime().ToString("MM-dd HH:mm");
            }
        }
    }

    /// <summary>
    /// The Fleet inventory (collector side): tracks enrolled agents, their check-ins and status, and
    /// pushes policy down to a chosen agent. Singleton; the SIEM module bridge feeds it.
    /// </summary>
    public sealed class SiemAgentRegistry
    {
        public static SiemAgentRegistry Instance { get; } = new();

        private readonly ConcurrentDictionary<Guid, AgentInfo> _agents = new();
        private ModuleHost? _host;

        public event Action? Changed;

        public void AttachHost(ModuleHost host) => _host = host;

        public List<AgentInfo> All() => _agents.Values.OrderByDescending(a => a.Online).ThenBy(a => a.Name).ToList();
        public int OnlineCount => _agents.Values.Count(a => a.Online);

        public void Enroll(ModuleConnection conn, AgentEnrollInfo info)
        {
            var a = _agents.GetOrAdd(conn.Id, _ => new AgentInfo { ConnId = conn.Id, EnrolledUtc = DateTime.UtcNow });
            a.Conn = conn;
            a.Name = string.IsNullOrWhiteSpace(info.Name) ? conn.Remote : info.Name;
            a.Host = info.Host; a.Os = info.Os; a.Version = info.Version; a.Sources = info.Sources;
            a.Remote = conn.Remote;
            a.LastCheckinUtc = DateTime.UtcNow;
            a.Online = true;
            Changed?.Invoke();
        }

        public void Checkin(ModuleConnection conn, long eventsSent)
        {
            if (_agents.TryGetValue(conn.Id, out var a))
            {
                a.LastCheckinUtc = DateTime.UtcNow; a.EventsSent = eventsSent; a.Online = true;
                Changed?.Invoke();
            }
        }

        /// <summary>Reconcile against the host's live connections: anything not present is now offline.</summary>
        public void Reconcile(IEnumerable<Guid> liveConnIds)
        {
            var live = new HashSet<Guid>(liveConnIds);
            bool changed = false;
            foreach (var a in _agents.Values)
            {
                bool online = live.Contains(a.ConnId);
                if (a.Online != online) { a.Online = online; changed = true; }
            }
            if (changed) Changed?.Invoke();
        }

        /// <summary>Push a policy to a managed agent (collector → agent). Returns false if not reachable.</summary>
        public bool PushPolicy(AgentInfo agent, AgentPolicy policy)
        {
            agent.Policy = policy;
            if (_host == null || agent.Conn == null || !agent.Online) return false;
            _host.SendTo(agent.Conn, AgentProtocol.EvtPolicy,
                new() { ["policy"] = JsonSerializer.Serialize(policy) });
            Changed?.Invoke();
            return true;
        }

        /// <summary>For tests.</summary>
        public void ResetForTests() { _agents.Clear(); _host = null; }
    }
}
