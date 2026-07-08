using System;
using System.Collections.Generic;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class IdsTwoWayTests
{
    [Fact]
    public void Console_mode_forwards_control_actions_to_remote_instead_of_running_locally()
    {
        var eng = IDSManager.Engine;
        string? cmd = null;
        Dictionary<string, object>? data = null;
        try
        {
            eng.RemoteControl = (c, d) => { cmd = c; data = d; return true; };

            eng.StartCapture();
            cmd.Should().Be(IdsModuleBridge.CmdStart);

            eng.StopCapture();
            cmd.Should().Be(IdsModuleBridge.CmdStop);

            var rule = new IDSRule { Id = Guid.NewGuid(), Name = "two-way-test-rule" };
            eng.AddRule(rule);
            cmd.Should().Be(IdsModuleBridge.CmdRuleAdd);
            data!["rule"].ToString().Should().Contain("two-way-test-rule");

            eng.ToggleRule(rule.Id, false);
            cmd.Should().Be(IdsModuleBridge.CmdRuleToggle);
            data!["id"].ToString().Should().Be(rule.Id.ToString());
        }
        finally { eng.RemoteControl = null; }
    }

    [Fact]
    public void Remote_running_state_applies_and_raises_change()
    {
        var eng = IDSManager.Engine;
        bool changed = false;
        EventHandler h = (_, _) => changed = true;
        eng.RunningChanged += h;
        try
        {
            eng.ApplyRemoteRunning(true);
            eng.IsRunning.Should().BeTrue();
            changed.Should().BeTrue();
        }
        finally { eng.RunningChanged -= h; eng.ApplyRemoteRunning(false); }
    }

    [Fact]
    public void Console_shows_the_remote_sensor_interfaces_not_local()
    {
        var eng = IDSManager.Engine;
        try
        {
            eng.RemoteControl = (_, _) => true;
            eng.ApplyRemoteInterfaces(new List<string> { "remote-eth0", "remote-wlan0" });
            eng.GetInterfaces().Should().BeEquivalentTo(new[] { "remote-eth0", "remote-wlan0" });
        }
        finally { eng.RemoteControl = null; eng.RemoteInterfaces = null; }
    }
}
