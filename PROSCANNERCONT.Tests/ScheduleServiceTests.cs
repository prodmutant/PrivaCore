using System;
using FluentAssertions;
using PROSCANNERCONT.Services;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class ScheduleServiceTests
{
    [Fact]
    public void NextOccurrence_every_minute()
    {
        var t = new DateTime(2026, 5, 17, 10, 30, 12, DateTimeKind.Utc);
        var next = ScheduleService.NextOccurrence("* * * * *", t);
        next.Should().BeAfter(t);
        (next - t).TotalSeconds.Should().BeLessThan(120);
    }

    [Fact]
    public void NextOccurrence_every_six_hours_step()
    {
        var t = new DateTime(2026, 5, 17, 1, 0, 0, DateTimeKind.Utc);
        var next = ScheduleService.NextOccurrence("0 */6 * * *", t);
        next.Hour.Should().BeOneOf(0, 6, 12, 18);
        next.Minute.Should().Be(0);
    }

    [Fact]
    public void NextOccurrence_specific_hour()
    {
        var t = new DateTime(2026, 5, 17, 8, 0, 0, DateTimeKind.Utc);
        var next = ScheduleService.NextOccurrence("30 14 * * *", t);
        next.Hour.Should().Be(14);
        next.Minute.Should().Be(30);
    }
}
