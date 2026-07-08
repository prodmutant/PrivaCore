using System;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Investigation Timeline store: pin, chronological order, clear.</summary>
public class SiemTimelineTests
{
    [Fact]
    public void Entries_are_returned_in_chronological_order()
    {
        SiemTimelineStore.ResetForTests();
        SiemTimelineStore.Add(new SiemTimelineEntry { Time = new DateTime(2026, 1, 1, 12, 0, 0), Label = "newer" });
        SiemTimelineStore.Add(new SiemTimelineEntry { Time = new DateTime(2026, 1, 1, 9, 0, 0), Label = "older" });

        var chrono = SiemTimelineStore.Chronological();
        chrono.Should().HaveCount(2);
        chrono[0].Label.Should().Be("older");   // oldest first
        chrono[1].Label.Should().Be("newer");
    }

    [Fact]
    public void Remove_and_clear()
    {
        SiemTimelineStore.ResetForTests();
        var e = new SiemTimelineEntry { Label = "x" };
        SiemTimelineStore.Add(e);
        SiemTimelineStore.Remove(e);
        SiemTimelineStore.All().Should().BeEmpty();

        SiemTimelineStore.Add(new SiemTimelineEntry());
        SiemTimelineStore.Clear();
        SiemTimelineStore.All().Should().BeEmpty();
    }

    [Fact]
    public void Severity_color_maps_by_name()
    {
        new SiemTimelineEntry { Severity = "Critical" }.SeverityColor.Should().Be("#F85149");
        new SiemTimelineEntry { Severity = "Info" }.SeverityColor.Should().Be("#8B949E");
    }
}
