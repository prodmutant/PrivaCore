using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Managed threat-intel indicators (G10) + their wiring into IndicatorMatch.</summary>
[Collection("Siem singleton")]
public class SiemIndicatorTests
{
    [Fact]
    public void Indicator_store_add_and_remove()
    {
        var store = SiemIndicatorStore.Instance;
        store.Clear();
        store.Add(new SiemIndicator { Value = "9.9.9.9", Type = "ip" });
        store.Add(new SiemIndicator { Value = "evil.test", Type = "domain" });
        store.All().Should().HaveCount(2);

        store.Remove(new SiemIndicator { Value = "9.9.9.9" });
        store.All().Should().ContainSingle(i => i.Value == "evil.test");
        store.Clear();
    }

    [Fact]
    public void IndicatorMatch_consults_the_central_store()
    {
        var store = SiemIndicatorStore.Instance;
        store.Clear();
        store.Add(new SiemIndicator { Value = "6.6.6.6", Type = "ip" });

        // a processor with NO inline indicators still matches via the global source
        var proc = new SiemProcessor { Type = SiemProcessorType.IndicatorMatch, Field = "source.ip", Arg = "" };
        var e = new SiemEvent { Severity = SiemSeverity.Low };
        e.Fields["source.ip"] = "6.6.6.6";
        proc.ApplyIndicatorMatch(e);

        e.Fields.Should().ContainKey("threat.matched");
        e.Fields["threat.indicator"].Should().Be("6.6.6.6");
        e.Severity.Should().Be(SiemSeverity.High);   // escalated
        store.Clear();
    }
}
