using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Email alert channel: message composition + SMTP-config validity gating.</summary>
public class SiemEmailTests
{
    [Fact]
    public void BuildMessage_includes_rule_severity_and_mitre()
    {
        var a = new SiemAlert
        {
            RuleName = "Brute force", Severity = SiemSeverity.High, Message = "10 from 1.2.3.4",
            Count = 10, RiskScore = 73, GroupValue = "1.2.3.4", MitreId = "T1110", MitreName = "Brute Force", MitreTactic = "Credential Access",
        };
        var (subject, body) = SiemEmail.BuildMessage(a);

        subject.Should().Contain("HIGH").And.Contain("Brute force");
        body.Should().Contain("10 from 1.2.3.4");
        body.Should().Contain("Credential Access");
        body.Should().Contain("1.2.3.4");
        body.Should().Contain("73");
    }

    [Fact]
    public void IsConfigured_requires_enabled_host_and_from()
    {
        new SiemEmailSettings { Enabled = true, Host = "smtp.x", From = "a@x" }.IsConfigured.Should().BeTrue();
        new SiemEmailSettings { Enabled = false, Host = "smtp.x", From = "a@x" }.IsConfigured.Should().BeFalse();
        new SiemEmailSettings { Enabled = true, Host = "", From = "a@x" }.IsConfigured.Should().BeFalse();
        new SiemEmailSettings { Enabled = true, Host = "smtp.x", From = "" }.IsConfigured.Should().BeFalse();
    }

    [Fact]
    public void Send_is_a_safe_noop_when_unconfigured()
    {
        var a = new SiemAlert { RuleName = "r", Severity = SiemSeverity.Low, Message = "m" };
        var act = () => SiemEmail.Send(new SiemEmailSettings(), "ops@x", a);   // disabled → must not throw
        act.Should().NotThrow();
    }
}
