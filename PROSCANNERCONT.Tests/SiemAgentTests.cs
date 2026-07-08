using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Services.Siem;
using PrivaCore.ModuleSdk;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Fleet agent registry: enrollment, check-in, online/offline reconcile + policy DTO.</summary>
public class SiemAgentTests
{
    private static ModuleConnection Conn(string remote) => new() { Username = "agent", Remote = remote };

    [Fact]
    public void Enroll_adds_agent_to_inventory()
    {
        var reg = SiemAgentRegistry.Instance; reg.ResetForTests();
        var c = Conn("10.0.0.5:5000");
        reg.Enroll(c, new AgentEnrollInfo { Name = "WEB01", Host = "WEB01", Os = "Ubuntu 22.04", Version = "1.0" });

        var all = reg.All();
        all.Should().ContainSingle();
        all[0].Name.Should().Be("WEB01");
        all[0].Online.Should().BeTrue();
        reg.OnlineCount.Should().Be(1);
    }

    [Fact]
    public void Checkin_updates_events_sent()
    {
        var reg = SiemAgentRegistry.Instance; reg.ResetForTests();
        var c = Conn("10.0.0.5:5000");
        reg.Enroll(c, new AgentEnrollInfo { Name = "WEB01" });
        reg.Checkin(c, 1234);
        reg.All().Single().EventsSent.Should().Be(1234);
    }

    [Fact]
    public void Reconcile_marks_missing_connections_offline()
    {
        var reg = SiemAgentRegistry.Instance; reg.ResetForTests();
        var a = Conn("10.0.0.1:1"); var b = Conn("10.0.0.2:2");
        reg.Enroll(a, new AgentEnrollInfo { Name = "A" });
        reg.Enroll(b, new AgentEnrollInfo { Name = "B" });

        reg.Reconcile(new[] { a.Id });   // only A still connected

        reg.All().Single(x => x.Name == "A").Online.Should().BeTrue();
        reg.All().Single(x => x.Name == "B").Online.Should().BeFalse();
        reg.OnlineCount.Should().Be(1);
    }

    [Fact]
    public void Push_policy_to_offline_agent_returns_false_but_stores_policy()
    {
        var reg = SiemAgentRegistry.Instance; reg.ResetForTests();
        var c = Conn("10.0.0.5:5000");
        reg.Enroll(c, new AgentEnrollInfo { Name = "WEB01" });
        reg.Reconcile(System.Array.Empty<System.Guid>());   // now offline (no host attached anyway)

        var policy = new AgentPolicy { DemoGenerator = true, HeartbeatSeconds = 15, TailFiles = { "/var/log/auth.log" } };
        reg.PushPolicy(reg.All().Single(), policy).Should().BeFalse();   // not deliverable
        reg.All().Single().Policy.DemoGenerator.Should().BeTrue();       // but desired policy is stored
    }

    [Fact]
    public void Agent_policy_round_trips_through_json()
    {
        var p = new AgentPolicy { Heartbeat = true, HeartbeatSeconds = 20, DemoGenerator = true, TailFiles = { "a.log", "b.log" } };
        var json = System.Text.Json.JsonSerializer.Serialize(p);
        var back = System.Text.Json.JsonSerializer.Deserialize<AgentPolicy>(json)!;
        back.HeartbeatSeconds.Should().Be(20);
        back.TailFiles.Should().HaveCount(2);
    }
}
