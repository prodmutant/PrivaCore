using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Messages exchanged between orchestrator and agents
    /// </summary>
    public class OrchestratorMessage
    {
        public string AgentId { get; set; }

        [JsonProperty("type")]
        public MessageType Type { get; set; }

        [JsonProperty("message_id")]
        public string MessageId { get; set; }

        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonProperty("payload")]
        public Dictionary<string, object> Payload { get; set; }

        public OrchestratorMessage()
        {
            MessageId = Guid.NewGuid().ToString();
            Timestamp = DateTime.UtcNow;
            Payload = new Dictionary<string, object>();
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static OrchestratorMessage FromJson(string json)
        {
            return JsonConvert.DeserializeObject<OrchestratorMessage>(json);
        }
    }

    /// <summary>
    /// Defines message types exchanged between orchestrator and agents
    /// Serialized as STRING values instead of integers
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum MessageType
    {
        // Agent → Orchestrator
        Heartbeat,
        AgentInfo,
        LogEntry,
        ConnectionAttempt,
        Alert,
        Statistics,

        // Orchestrator → Agent
        Command,
        ConfigUpdate,
        CommandResult,
        OpenPort,
        ClosePort,
        InstallService,
        UninstallService,
        GetStatus,
        Shutdown
    }

    /// <summary>
    /// Command sent from orchestrator to agent
    /// </summary>
    public class AgentCommand
    {
        public string CommandType { get; set; }
        public Dictionary<string, string> Parameters { get; set; }

        public AgentCommand()
        {
            Parameters = new Dictionary<string, string>();
        }
    }
}
