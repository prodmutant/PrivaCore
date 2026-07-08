using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>SOC cases: model behaviour + in-memory store.</summary>
public class SiemCaseTests
{
    [Fact]
    public void Store_add_and_remove()
    {
        SiemCaseStore.ResetForTests();
        var c = SiemCaseStore.Add(new SiemCase { Title = "Intrusion" });
        SiemCaseStore.All().Should().ContainSingle().Which.Title.Should().Be("Intrusion");
        SiemCaseStore.Remove(c);
        SiemCaseStore.All().Should().BeEmpty();
    }

    [Fact]
    public void Status_and_severity_have_display_metadata()
    {
        var c = new SiemCase { Status = SiemCaseStatus.InProgress, Severity = SiemSeverity.Critical };
        c.StatusText.Should().Be("In progress");
        c.SeverityText.Should().Be("Critical");
        c.StatusColor.Should().NotBeNullOrEmpty();
        c.SeverityColor.Should().Be("#F85149");
    }

    [Fact]
    public void Attaching_items_and_comments_updates_summary()
    {
        var c = new SiemCase { Title = "X" };
        c.Items.Add(new SiemCaseItem { RuleName = "Brute force", Severity = "High", Summary = "10 fails" });
        c.Comments.Add(new SiemCaseComment { Text = "looking into it" });
        c.SummaryLine.Should().Contain("1 item(s)");
        c.SummaryLine.Should().Contain("1 comment(s)");
    }
}
