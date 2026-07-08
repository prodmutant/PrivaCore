using System;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Agent connection status (kept for backward compatibility)
    /// </summary>
    public enum AgentConnectionStatus
    {
        Disconnected,
        Connected,
        Error
    }

    /// <summary>
    /// Represents a honeypot agent running inside a VM
    /// NOTE: This class is kept for backward compatibility but is no longer used in SSH-based system
    /// </summary>
    public class HoneypotAgent
    {
        public string AgentId { get; set; } = string.Empty;
        public string VMId { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public AgentConnectionStatus ConnectionStatus { get; set; }
        public DateTime LastHeartbeat { get; set; }
        public string IPAddress { get; set; } = string.Empty;
        public string OperatingSystem { get; set; } = string.Empty;
        public string OSVersion { get; set; } = string.Empty;
        public string Architecture { get; set; } = string.Empty;
        public int OpenPorts { get; set; }
        public int ConnectionAttempts { get; set; }

        public string LastHeartbeatText
        {
            get
            {
                if (LastHeartbeat == DateTime.MinValue)
                    return "Never";
                var elapsed = DateTime.Now - LastHeartbeat;
                if (elapsed.TotalSeconds < 10)
                    return "Just now";
                if (elapsed.TotalSeconds < 60)
                    return $"{(int)elapsed.TotalSeconds}s ago";
                if (elapsed.TotalMinutes < 60)
                    return $"{(int)elapsed.TotalMinutes}m ago";
                if (elapsed.TotalHours < 24)
                    return $"{(int)elapsed.TotalHours}h ago";
                return $"{(int)elapsed.TotalDays}d ago";
            }
        }

        public bool IsConnected => ConnectionStatus == AgentConnectionStatus.Connected;

        public bool IsHeartbeatRecent
        {
            get
            {
                if (LastHeartbeat == DateTime.MinValue)
                    return false;
                return (DateTime.Now - LastHeartbeat).TotalSeconds < 30;
            }
        }

        public string StatusIcon => ConnectionStatus switch
        {
            AgentConnectionStatus.Connected => "🟢",
            AgentConnectionStatus.Disconnected => "🔴",
            AgentConnectionStatus.Error => "🟠",
            _ => "⚪"
        };

        public HoneypotAgent()
        {
            ConnectionStatus = AgentConnectionStatus.Disconnected;
            LastHeartbeat = DateTime.MinValue;
            OpenPorts = 0;
            ConnectionAttempts = 0;
        }

        public override string ToString()
        {
            return $"Agent {AgentId} (VM: {VMId}) - {ConnectionStatus}";
        }
    }
}