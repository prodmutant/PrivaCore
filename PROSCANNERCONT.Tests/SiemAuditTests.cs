using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The SIEM audit trail: actions are recorded newest-first with the acting user.</summary>
[Collection("Siem singleton")]
public class SiemAuditTests
{
    [Fact]
    public void Logged_actions_are_returned_newest_first()
    {
        var audit = SiemAudit.Instance;
        audit.Clear();

        audit.Log("Rule", "Created rule", "Brute force");
        audit.Log("Alert", "Closed alert", "Brute force");

        var recent = audit.Recent(10);
        recent.Should().HaveCountGreaterThanOrEqualTo(2);
        recent[0].Action.Should().Be("Closed alert");
        recent[0].Category.Should().Be("Alert");
        recent[0].User.Should().NotBeNullOrEmpty();
        recent[1].Action.Should().Be("Created rule");
    }

    [Fact]
    public void Clear_empties_the_trail()
    {
        var audit = SiemAudit.Instance;
        audit.Log("Index", "Cleared entire index", "1 document");
        audit.Clear();
        audit.Recent(10).Should().BeEmpty();
    }
}
