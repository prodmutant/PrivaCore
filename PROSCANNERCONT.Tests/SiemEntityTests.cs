using System;
using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Entity analytics: per-host / per-user roll-ups and severity-weighted risk scoring.</summary>
[Collection("Siem singleton")]
public class SiemEntityTests : IDisposable
{
    private readonly SiemStore _store = SiemStore.Instance;
    public SiemEntityTests() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }
    public void Dispose() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }

    private SiemEvent Ev(string host, SiemSeverity sev, string? user = null)
    {
        var e = new SiemEvent { Host = host, Source = host, Severity = sev, Category = "x", EventType = "x" };
        if (user != null) e.Fields["user.name"] = user;
        return e;
    }

    [Fact]
    public void Hosts_roll_up_with_counts()
    {
        _store.Add(Ev("DC01", SiemSeverity.Critical));
        _store.Add(Ev("DC01", SiemSeverity.High));
        _store.Add(Ev("WEB02", SiemSeverity.Low));

        var hosts = SiemEntityRisk.Hosts(null);
        hosts.Should().HaveCount(2);
        var dc = hosts.Single(h => h.Name == "DC01");
        dc.Events.Should().Be(2);
        dc.Critical.Should().Be(1);
        dc.High.Should().Be(1);
    }

    [Fact]
    public void Risk_score_is_severity_weighted_and_ranked()
    {
        _store.Add(Ev("DC01", SiemSeverity.Critical));   // weight 30
        _store.Add(Ev("WEB02", SiemSeverity.Low));       // weight 1

        var hosts = SiemEntityRisk.Hosts(null);
        hosts[0].Name.Should().Be("DC01");               // highest risk first
        hosts[0].RiskScore.Should().BeGreaterThan(hosts[1].RiskScore);
        hosts.Single(h => h.Name == "DC01").RiskLevel.Should().Be("Medium");   // 30 → Medium band
    }

    [Fact]
    public void Risk_score_is_capped_at_100()
    {
        for (int i = 0; i < 10; i++) _store.Add(Ev("DC01", SiemSeverity.Critical));   // 300 raw
        SiemEntityRisk.Hosts(null).Single().RiskScore.Should().Be(100);
    }

    [Fact]
    public void Users_are_grouped_by_user_name_field()
    {
        _store.Add(Ev("DC01", SiemSeverity.High, user: "admin"));
        _store.Add(Ev("WEB02", SiemSeverity.High, user: "admin"));
        _store.Add(Ev("DC01", SiemSeverity.Low, user: "jdoe"));

        var users = SiemEntityRisk.Users(null);
        users.Should().HaveCount(2);
        users.Single(u => u.Name == "admin").Events.Should().Be(2);
    }

    [Fact]
    public void Alert_events_are_excluded_from_entities()
    {
        var alert = new SiemEvent { Host = "SIEM", Severity = SiemSeverity.Critical, Category = "alert" };
        alert.Fields["event.kind"] = "alert";
        _store.Add(alert, applyPipeline: false);
        _store.Add(Ev("DC01", SiemSeverity.High));

        var hosts = SiemEntityRisk.Hosts(null);
        hosts.Should().ContainSingle().Which.Name.Should().Be("DC01");
    }
}
