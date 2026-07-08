using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// A pentesting engagement: groups scan results, alerts, and reports under
    /// a client + project name with an explicit in-scope CIDR list. The scope
    /// guard refuses out-of-scope scans unless explicitly overridden — this is
    /// the difference between "I clicked the wrong network" and "I just spent
    /// my Sunday explaining to a client why their backup server was scanned".
    /// </summary>
    public sealed class Engagement
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = "";
        public string Client { get; set; } = "";
        public string Contact { get; set; } = "";
        public string Notes { get; set; } = "";

        public DateTime StartDate { get; set; } = DateTime.UtcNow;
        public DateTime? EndDate { get; set; }

        /// <summary>List of CIDR ranges or single IPs that are in scope.</summary>
        public List<string> InScopeCidrs { get; set; } = new();
        /// <summary>Explicit out-of-scope ranges (override of an inclusive parent).</summary>
        public List<string> OutOfScopeCidrs { get; set; } = new();
        /// <summary>Domains explicitly authorised for testing.</summary>
        public List<string> InScopeDomains { get; set; } = new();

        /// <summary>Block all scans of public IPs unless override is on.</summary>
        public bool ForbidPublicTargets { get; set; } = true;

        /// <summary>One-shot override required to scan outside scope.</summary>
        public bool ScopeOverrideActive { get; set; } = false;

        public DateTime LastModified { get; set; } = DateTime.UtcNow;
    }
}
