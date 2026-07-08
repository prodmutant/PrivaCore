using System;
using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>SIEM detection engine: threshold + grouped rules, alert events, and cooldown.</summary>
[Collection("Siem singleton")]
public class SiemRuleTests : IDisposable
{
    private readonly SiemStore _store = SiemStore.Instance;
    private readonly SiemRuleEngine _engine = SiemRuleEngine.Instance;

    public SiemRuleTests()
    {
        _store.Clear(); _store.Pipeline = new SiemPipeline();
        _engine.Reset();
    }
    public void Dispose()
    {
        _store.Clear(); _store.Pipeline = new SiemPipeline();
        _engine.Reset();
    }

    private SiemEvent Logon(string srcIp, string outcome = "failure")
    {
        var e = new SiemEvent { Severity = SiemSeverity.Medium, Category = "authentication", EventType = "logon", Source = srcIp, Host = "DC01" };
        e.Fields["event.action"] = "logon";
        e.Fields["event.outcome"] = outcome;
        e.Fields["source.ip"] = srcIp;
        return e;
    }

    [Fact]
    public void Threshold_rule_fires_when_count_reached()
    {
        SiemAlert? raised = null;
        void H(object? s, SiemAlert a) => raised = a;
        _engine.AlertRaised += H;
        try
        {
            _engine.Rules.Add(new SiemRule
            {
                Name = "Failed logons", Query = "event.outcome:failure",
                Type = SiemRuleType.Threshold, Threshold = 3, WindowMinutes = 5, Severity = SiemSeverity.High,
            });
            for (int i = 0; i < 3; i++) _store.Add(Logon("10.0.0.5"));

            _engine.Evaluate();

            raised.Should().NotBeNull();
            raised!.Count.Should().BeGreaterThanOrEqualTo(3);
            raised.Severity.Should().Be(SiemSeverity.High);
        }
        finally { _engine.AlertRaised -= H; }
    }

    [Fact]
    public void Threshold_rule_does_not_fire_below_threshold()
    {
        _engine.Rules.Add(new SiemRule { Name = "x", Query = "event.outcome:failure", Threshold = 5, WindowMinutes = 5 });
        for (int i = 0; i < 2; i++) _store.Add(Logon("10.0.0.5"));

        _engine.Evaluate();

        _engine.Alerts().Should().BeEmpty();
    }

    [Fact]
    public void Group_threshold_counts_per_distinct_value()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "Brute force", Query = "event.outcome:failure",
            Type = SiemRuleType.GroupThreshold, GroupBy = "source.ip",
            Threshold = 3, WindowMinutes = 5,
        });
        // 3 from one IP (should fire), 1 from another (should not)
        for (int i = 0; i < 3; i++) _store.Add(Logon("10.0.0.5"));
        _store.Add(Logon("10.0.0.9"));

        _engine.Evaluate();

        var alerts = _engine.Alerts();
        alerts.Should().ContainSingle();
        alerts[0].GroupValue.Should().Be("10.0.0.5");
    }

    [Fact]
    public void New_terms_rule_fires_only_for_unseen_values()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "New source IP", Query = "", Type = SiemRuleType.NewTerms,
            GroupBy = "source.ip", Threshold = 1, WindowMinutes = 5,
        });
        // historical value (older than the window) — known, must NOT fire
        var old = Logon("10.0.0.1"); old.Timestamp = DateTime.Now.AddMinutes(-30);
        _store.Add(old);
        // recent values: 10.0.0.1 is known; 10.0.0.99 is brand new
        _store.Add(Logon("10.0.0.1"));
        _store.Add(Logon("10.0.0.99"));

        _engine.Evaluate();

        var alerts = _engine.Alerts();
        alerts.Should().ContainSingle();
        alerts[0].GroupValue.Should().Be("10.0.0.99");
    }

    [Fact]
    public void Sequence_rule_fires_on_A_then_B_from_same_group()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "Success after brute force", Type = SiemRuleType.Sequence,
            Query = "event.outcome:failure", SecondQuery = "event.outcome:success",
            GroupBy = "source.ip", Threshold = 3, WindowMinutes = 10, Severity = SiemSeverity.Critical,
        });
        // 3 failures then a success from the same IP → fires
        for (int i = 0; i < 3; i++) _store.Add(Logon("10.0.0.5", "failure"));
        _store.Add(Logon("10.0.0.5", "success"));
        // another IP only fails → must not fire
        for (int i = 0; i < 3; i++) _store.Add(Logon("10.0.0.9", "failure"));

        _engine.Evaluate();

        var alerts = _engine.Alerts();
        alerts.Should().ContainSingle();
        alerts[0].GroupValue.Should().Be("10.0.0.5");
    }

    [Fact]
    public void Sequence_maxspan_requires_step_B_within_the_span()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "fast success", Type = SiemRuleType.Sequence,
            Query = "event.outcome:failure", SecondQuery = "event.outcome:success",
            GroupBy = "source.ip", Threshold = 2, WindowMinutes = 60, MaxSpanMinutes = 5,
        });
        var now = DateTime.Now;
        // 2 failures, then a success 20 minutes later → outside maxspan → no fire
        var f1 = Logon("10.0.0.5", "failure"); f1.Timestamp = now.AddMinutes(-30);
        var f2 = Logon("10.0.0.5", "failure"); f2.Timestamp = now.AddMinutes(-29);
        var sLate = Logon("10.0.0.5", "success"); sLate.Timestamp = now.AddMinutes(-9);
        _store.Add(f1); _store.Add(f2); _store.Add(sLate);
        _engine.Evaluate();
        _engine.Alerts().Should().BeEmpty();

        // another IP: 2 failures then a success 1 minute later → within maxspan → fires
        var g1 = Logon("10.0.0.6", "failure"); g1.Timestamp = now.AddMinutes(-10);
        var g2 = Logon("10.0.0.6", "failure"); g2.Timestamp = now.AddMinutes(-10);
        var sFast = Logon("10.0.0.6", "success"); sFast.Timestamp = now.AddMinutes(-9);
        _store.Add(g1); _store.Add(g2); _store.Add(sFast);
        _engine.Evaluate();
        _engine.Alerts().Should().ContainSingle(a => a.GroupValue == "10.0.0.6");
    }

    [Fact]
    public void Group_threshold_supports_a_composite_key()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "per ip+user", Query = "event.outcome:failure",
            Type = SiemRuleType.GroupThreshold, GroupBy = "source.ip,user.name",
            Threshold = 3, WindowMinutes = 5,
        });
        // 3 from (10.0.0.5, jdoe) → fires;  spread across users from same IP → no single key reaches 3
        for (int i = 0; i < 3; i++) { var e = Logon("10.0.0.5"); e.Fields["user.name"] = "jdoe"; _store.Add(e); }
        for (int i = 0; i < 2; i++) { var e = Logon("10.0.0.9"); e.Fields["user.name"] = "alice"; _store.Add(e); }
        _store.Add(Logon("10.0.0.9"));   // no user.name → composite key incomplete → skipped

        _engine.Evaluate();

        var alerts = _engine.Alerts();
        alerts.Should().ContainSingle();
        alerts[0].GroupValue.Should().Be("10.0.0.5|jdoe");
    }

    [Fact]
    public void Sequence_does_not_fire_without_step_B()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "seq", Type = SiemRuleType.Sequence,
            Query = "event.outcome:failure", SecondQuery = "event.outcome:success",
            GroupBy = "source.ip", Threshold = 2, WindowMinutes = 10,
        });
        for (int i = 0; i < 5; i++) _store.Add(Logon("10.0.0.5", "failure"));   // no success
        _engine.Evaluate();
        _engine.Alerts().Should().BeEmpty();
    }

    [Fact]
    public void Exception_query_allowlists_events()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "Failed logons", Query = "event.outcome:failure",
            ExcludeQuery = "user.name:svc_backup", Threshold = 3, WindowMinutes = 5,
        });
        // 3 failures from an allowlisted service account → excluded → no alert
        for (int i = 0; i < 3; i++) { var e = Logon("10.0.0.5"); e.Fields["user.name"] = "svc_backup"; _store.Add(e); }
        _engine.Evaluate();
        _engine.Alerts().Should().BeEmpty();

        // 3 failures from a normal user → fires
        for (int i = 0; i < 3; i++) { var e = Logon("10.0.0.6"); e.Fields["user.name"] = "jdoe"; _store.Add(e); }
        _engine.Evaluate();
        _engine.Alerts().Should().NotBeEmpty();
    }

    [Fact]
    public void Cooldown_prevents_duplicate_alerts_within_window()
    {
        _engine.Rules.Add(new SiemRule { Name = "x", Query = "event.outcome:failure", Threshold = 2, WindowMinutes = 5 });
        for (int i = 0; i < 2; i++) _store.Add(Logon("10.0.0.5"));

        _engine.Evaluate();
        _engine.Evaluate();   // immediately again — must be suppressed by cooldown

        _engine.Alerts().Count(a => a.RuleName == "x").Should().Be(1);
    }

    [Fact]
    public void Firing_a_rule_emits_an_alert_event()
    {
        _engine.Rules.Add(new SiemRule { Name = "x", Query = "event.outcome:failure", Threshold = 1, WindowMinutes = 5, MitreId = "T1110", MitreName = "Brute Force" });
        _store.Add(Logon("10.0.0.5"));

        _engine.Evaluate();

        var alertEvent = _store.Snapshot().FirstOrDefault(e => e.Category == "alert");
        alertEvent.Should().NotBeNull();
        alertEvent!.Fields["event.kind"].Should().Be("alert");
        alertEvent.Fields["threat.technique.id"].Should().Be("T1110");
    }

    [Fact]
    public void Alert_events_are_not_counted_by_rules()
    {
        // a rule matching everything must not feed on its own alert events (no runaway loop)
        _engine.Rules.Add(new SiemRule { Name = "all", Query = "", Threshold = 1, WindowMinutes = 5 });
        _store.Add(Logon("10.0.0.5"));

        _engine.Evaluate();
        int afterFirst = _store.Snapshot().Count(e => e.Category == "alert");
        _engine.Evaluate();   // cooldown also guards, but alert events must be excluded regardless
        int afterSecond = _store.Snapshot().Count(e => e.Category == "alert");

        afterFirst.Should().Be(1);
        afterSecond.Should().Be(1);
    }

    [Fact]
    public void Webhook_payload_includes_alert_fields()
    {
        var a = new SiemAlert { RuleName = "Brute force", Severity = SiemSeverity.High, Message = "10 from 1.2.3.4", Count = 10, MitreId = "T1110", MitreTactic = "Credential Access" };
        var json = SiemWebhook.BuildPayload(a);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;
        root.GetProperty("rule").GetString().Should().Be("Brute force");
        root.GetProperty("severity").GetString().Should().Be("High");
        root.GetProperty("count").GetInt32().Should().Be(10);
        root.GetProperty("mitre").GetString().Should().Be("T1110");
        root.GetProperty("text").GetString().Should().Contain("Brute force");
    }

    [Fact]
    public void Alert_carries_risk_score_derived_from_severity()
    {
        _engine.Rules.Add(new SiemRule { Name = "crit", Query = "event.outcome:failure", Threshold = 1, WindowMinutes = 5, Severity = SiemSeverity.Critical });
        _store.Add(Logon("10.0.0.5"));
        _engine.Evaluate();

        var a = _engine.Alerts().Single();
        a.RiskScore.Should().BeGreaterThanOrEqualTo(95);   // critical base risk
        a.RiskScore.Should().BeLessThanOrEqualTo(100);
    }

    [Fact]
    public void Explicit_rule_risk_score_overrides_severity_mapping()
    {
        _engine.Rules.Add(new SiemRule { Name = "r", Query = "event.outcome:failure", Threshold = 1, WindowMinutes = 5, Severity = SiemSeverity.Low, RiskScore = 40 });
        _store.Add(Logon("10.0.0.5"));
        _engine.Evaluate();

        _engine.Alerts().Single().RiskScore.Should().BeGreaterThanOrEqualTo(40);
    }

    [Fact]
    public void Risk_score_increases_when_count_overshoots_threshold()
    {
        _engine.Rules.Add(new SiemRule { Name = "r", Query = "event.outcome:failure", Threshold = 2, WindowMinutes = 5, Severity = SiemSeverity.Medium });
        for (int i = 0; i < 40; i++) _store.Add(Logon("10.0.0.5"));
        _engine.Evaluate();

        var a = _engine.Alerts().Single();
        a.RiskScore.Should().BeGreaterThan(new SiemRule { Severity = SiemSeverity.Medium }.EffectiveRisk);
    }

    [Fact]
    public void Suppress_minutes_dedupes_repeat_alerts()
    {
        // window is tiny so a fresh evaluation would normally fire again; suppression holds it back
        _engine.Rules.Add(new SiemRule { Name = "s", Query = "event.outcome:failure", Threshold = 2, WindowMinutes = 1, SuppressMinutes = 60 });
        for (int i = 0; i < 2; i++) _store.Add(Logon("10.0.0.5"));

        _engine.Evaluate();
        _engine.Evaluate();

        _engine.Alerts().Count(a => a.RuleName == "s").Should().Be(1);
    }

    [Fact]
    public void Anomaly_rule_fires_on_a_spike_above_baseline()
    {
        // baseline of ~2/window for 6 windows of 1 minute, then a spike of 30 in the current window
        _engine.Rules.Add(new SiemRule
        {
            Name = "Rate anomaly", Query = "event.outcome:failure", Type = SiemRuleType.Anomaly,
            Threshold = 3, WindowMinutes = 1, BaselineWindows = 6, Severity = SiemSeverity.High,
        });
        var now = DateTime.Now;
        for (int w = 1; w <= 6; w++)
            for (int i = 0; i < 2; i++) { var e = Logon("10.0.0.5"); e.Timestamp = now.AddMinutes(-w).AddSeconds(-i); _store.Add(e); }
        for (int i = 0; i < 30; i++) _store.Add(Logon("10.0.0.5"));   // current-window spike

        _engine.Evaluate();

        _engine.Alerts().Should().ContainSingle(a => a.RuleName == "Rate anomaly");
    }

    [Fact]
    public void Anomaly_rule_quiet_when_rate_is_steady()
    {
        _engine.Rules.Add(new SiemRule
        {
            Name = "steady", Query = "event.outcome:failure", Type = SiemRuleType.Anomaly,
            Threshold = 3, WindowMinutes = 1, BaselineWindows = 6,
        });
        var now = DateTime.Now;
        for (int w = 0; w <= 6; w++)
            for (int i = 0; i < 8; i++) { var e = Logon("10.0.0.5"); e.Timestamp = now.AddMinutes(-w).AddSeconds(-i); _store.Add(e); }

        _engine.Evaluate();

        _engine.Alerts().Should().BeEmpty();
    }

    [Fact]
    public void Indicator_match_rule_fires_on_an_observable_hitting_an_ioc()
    {
        var orig = _engine.IndicatorSource;
        _engine.IndicatorSource = () => new[]
        {
            new SiemIndicator { Value = "203.0.113.7", Type = "ip", Source = "feed-x" },
        };
        try
        {
            _engine.Rules.Add(new SiemRule
            {
                Name = "Known-bad IP", Query = "", Type = SiemRuleType.IndicatorMatch,
                Threshold = 1, WindowMinutes = 5, Severity = SiemSeverity.Critical,
            });
            _store.Add(Logon("203.0.113.7"));   // source.ip hits the indicator
            _store.Add(Logon("10.0.0.9"));      // benign

            _engine.Evaluate();

            var alerts = _engine.Alerts();
            alerts.Should().ContainSingle();
            alerts[0].GroupValue.Should().Be("203.0.113.7");
            alerts[0].Severity.Should().Be(SiemSeverity.Critical);

            var ev = _store.Snapshot().First(e => e.Category == "alert");
            ev.Fields["threat.matched"].Should().Be("true");
            ev.Fields["threat.indicator"].Should().Be("203.0.113.7");
        }
        finally { _engine.IndicatorSource = orig; }
    }

    [Fact]
    public void Indicator_match_quiet_when_no_observable_matches()
    {
        var orig = _engine.IndicatorSource;
        _engine.IndicatorSource = () => new[] { new SiemIndicator { Value = "203.0.113.7", Type = "ip" } };
        try
        {
            _engine.Rules.Add(new SiemRule { Name = "ioc", Type = SiemRuleType.IndicatorMatch, Threshold = 1, WindowMinutes = 5 });
            for (int i = 0; i < 5; i++) _store.Add(Logon("10.0.0.5"));
            _engine.Evaluate();
            _engine.Alerts().Should().BeEmpty();
        }
        finally { _engine.IndicatorSource = orig; }
    }

    [Fact]
    public void Indicator_match_restricts_to_groupby_field_when_set()
    {
        var orig = _engine.IndicatorSource;
        _engine.IndicatorSource = () => new[] { new SiemIndicator { Value = "evil", Type = "user" } };
        try
        {
            _engine.Rules.Add(new SiemRule
            {
                Name = "bad user", Type = SiemRuleType.IndicatorMatch, GroupBy = "user.name",
                Threshold = 1, WindowMinutes = 5,
            });
            var e1 = Logon("10.0.0.5"); e1.Fields["user.name"] = "evil"; _store.Add(e1);   // hits via user.name
            var e2 = Logon("evil");      // "evil" only in source.ip, but rule checks user.name only → ignored
            _store.Add(e2);

            _engine.Evaluate();

            var alerts = _engine.Alerts();
            alerts.Should().ContainSingle();
            alerts[0].GroupValue.Should().Be("evil");
        }
        finally { _engine.IndicatorSource = orig; }
    }

    [Fact]
    public void Preview_reports_hits_without_side_effects()
    {
        for (int i = 0; i < 6; i++) _store.Add(Logon("10.0.0.5"));
        var rule = new SiemRule { Name = "bf", Query = "event.outcome:failure", Type = SiemRuleType.GroupThreshold, GroupBy = "source.ip", Threshold = 3, WindowMinutes = 5 };

        var hits = _engine.Preview(rule, 1440);

        hits.Should().ContainSingle();
        hits[0].Group.Should().Be("10.0.0.5");
        hits[0].Count.Should().BeGreaterThanOrEqualTo(6);
        // preview must NOT raise real alerts or write alert events
        _engine.Alerts().Should().BeEmpty();
        _store.Snapshot().Should().NotContain(e => e.Category == "alert");
    }

    [Fact]
    public void Preview_returns_empty_when_rule_would_not_fire()
    {
        for (int i = 0; i < 2; i++) _store.Add(Logon("10.0.0.5"));
        var rule = new SiemRule { Name = "x", Query = "event.outcome:failure", Threshold = 50, WindowMinutes = 5 };
        _engine.Preview(rule, 1440).Should().BeEmpty();
    }

    [Fact]
    public void Library_provides_ready_made_rules()
    {
        SiemRuleLibrary.All().Should().NotBeEmpty();
        SiemRuleLibrary.All().Should().OnlyContain(r => !string.IsNullOrWhiteSpace(r.Name));
        var clone = SiemRuleLibrary.Clone(SiemRuleLibrary.All()[0]);
        clone.Id.Should().NotBe(SiemRuleLibrary.All()[0].Id);
    }

    [Fact]
    public void Library_rules_are_tagged_with_known_mitre_tactics()
    {
        var rules = SiemRuleLibrary.All();
        // every library rule carries a technique and a recognised tactic
        rules.Should().OnlyContain(r => !string.IsNullOrEmpty(r.MitreId) && !string.IsNullOrEmpty(r.MitreTactic));
        rules.Should().OnlyContain(r => SiemMitre.Tactics.Contains(r.MitreTactic));
        // the library should span a broad range of the ATT&CK kill chain
        rules.Select(r => r.MitreTactic).Distinct().Count().Should().BeGreaterThanOrEqualTo(8);
    }

    [Fact]
    public void Clone_preserves_mitre_tactic()
    {
        var t = SiemRuleLibrary.All().First(r => r.MitreTactic == "Credential Access");
        SiemRuleLibrary.Clone(t).MitreTactic.Should().Be("Credential Access");
    }
}
