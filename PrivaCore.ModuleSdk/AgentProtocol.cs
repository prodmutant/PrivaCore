namespace PrivaCore.ModuleSdk;

/// <summary>
/// Wire vocabulary for Fleet-style agent management, shared by the agent and the collector.
/// Agents enroll + check in over the command channel; the collector pushes a policy as an event.
/// </summary>
public static class AgentProtocol
{
    public const string CmdEnroll = "agent.enroll";    // agent → collector (command);   Data["info"] = AgentEnrollInfo json
    public const string CmdCheckin = "agent.checkin";  // agent → collector (command);   Data["sent"] = events shipped
    public const string EvtPolicy = "agent.policy";    // collector → agent (event);      Data["policy"] = AgentPolicy json
}

/// <summary>The desired configuration a collector can push to a managed agent.</summary>
public sealed class AgentPolicy
{
    public bool Heartbeat { get; set; } = true;
    public int HeartbeatSeconds { get; set; } = 30;
    public bool DemoGenerator { get; set; }
    public List<string> TailFiles { get; set; } = new();
}

/// <summary>Identity an agent reports when it enrolls.</summary>
public sealed class AgentEnrollInfo
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public string Os { get; set; } = "";
    public string Version { get; set; } = "";
    public string Sources { get; set; } = "";   // human-readable summary of what it's shipping
}
