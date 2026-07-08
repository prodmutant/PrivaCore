using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class ScopeGuardTests
{
    [Fact]
    public void Inactive_engagement_allows_all_targets()
    {
        // Default state — no engagement loaded.
        var r = ScopeGuard.Check("8.8.8.8");
        r.Allowed.Should().BeTrue();
    }

    [Fact]
    public void In_scope_target_passes()
    {
        var eng = new Engagement
        {
            Name = "test",
            InScopeCidrs = { "10.0.0.0/8" },
            ForbidPublicTargets = false,
        };
        EngagementService.Instance.Update(eng);
        EngagementService.Instance.SetActive(eng.Id);
        try
        {
            ScopeGuard.Check("10.1.2.3").Allowed.Should().BeTrue();
        }
        finally
        {
            EngagementService.Instance.Delete(eng.Id);
        }
    }

    [Fact]
    public void Out_of_scope_block_wins_over_in_scope()
    {
        var eng = EngagementService.Instance.Create("test-out-of-scope", "client");
        eng.InScopeCidrs.Add("10.0.0.0/8");
        eng.OutOfScopeCidrs.Add("10.99.0.0/16");
        eng.ForbidPublicTargets = false;
        EngagementService.Instance.Update(eng);
        try
        {
            ScopeGuard.Check("10.99.5.5").Allowed.Should().BeFalse();
            ScopeGuard.Check("10.1.5.5").Allowed.Should().BeTrue();
        }
        finally
        {
            EngagementService.Instance.Delete(eng.Id);
        }
    }
}
