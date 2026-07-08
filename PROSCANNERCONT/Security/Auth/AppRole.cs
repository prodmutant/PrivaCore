using System.Collections.Generic;

namespace PROSCANNERCONT.Security.Auth
{
    /// <summary>
    /// Built-in console roles, ordered least → most privileged. Roles are presets over the
    /// <see cref="Permission"/> primitive (see <see cref="RolePolicy"/>), so custom roles can be
    /// layered on later without changing any enforcement site.
    /// </summary>
    public enum AppRole
    {
        Viewer = 0,          // read-only
        Analyst = 1,         // L1 — day-to-day triage + scans
        SeniorAnalyst = 2,   // L2 — tuning, deletion, module management
        Admin = 3,           // full control incl. users + settings
    }

    /// <summary>
    /// A single capability that can be granted. Enforcement checks a Permission, never a role
    /// directly, so re-mapping roles (or adding custom ones) never touches call sites.
    /// </summary>
    public enum Permission
    {
        ViewDashboards,      // see pages / dashboards (baseline)
        Search,              // run Discover / SIEM searches
        TriageAlerts,        // ack/assign/close alerts, cases, timeline
        RunScans,            // port/vuln/network/traffic scanners
        ManageIdsRules,      // add/update/delete IDS + SIEM detection rules
        EditPipeline,        // edit SIEM ingest pipeline
        DeleteEvents,        // delete-by-query / clear the store
        ManageRetention,     // capacity / max-age / snapshot / restore
        AddRemoveModules,    // add or remove remote modules
        ImportExportConfig,  // saved-objects / config bundle import & export
        ManageSettings,      // application settings
        ManageUsers,         // create/edit/disable users + assign roles
    }

    /// <summary>Maps each role to the permissions it grants. The single source of truth for RBAC.</summary>
    public static class RolePolicy
    {
        private static readonly Dictionary<AppRole, HashSet<Permission>> Map = Build();

        /// <summary>True if <paramref name="role"/> grants <paramref name="permission"/>.</summary>
        public static bool Grants(AppRole role, Permission permission)
            => Map.TryGetValue(role, out var set) && set.Contains(permission);

        public static IReadOnlyCollection<Permission> PermissionsFor(AppRole role)
            => Map.TryGetValue(role, out var set) ? set : new HashSet<Permission>();

        private static Dictionary<AppRole, HashSet<Permission>> Build()
        {
            var viewer = new HashSet<Permission>
            {
                Permission.ViewDashboards,
                Permission.Search,
            };

            // Analyst (L1) = viewer + day-to-day triage and scanning.
            var analyst = new HashSet<Permission>(viewer)
            {
                Permission.TriageAlerts,
                Permission.RunScans,
            };

            // Senior analyst (L2) = analyst + tuning / destructive data ops / module management.
            var senior = new HashSet<Permission>(analyst)
            {
                Permission.ManageIdsRules,
                Permission.EditPipeline,
                Permission.DeleteEvents,
                Permission.ManageRetention,
                Permission.AddRemoveModules,
            };

            // Admin = everything (senior + config/settings/users).
            var admin = new HashSet<Permission>(senior)
            {
                Permission.ImportExportConfig,
                Permission.ManageSettings,
                Permission.ManageUsers,
            };

            return new Dictionary<AppRole, HashSet<Permission>>
            {
                [AppRole.Viewer] = viewer,
                [AppRole.Analyst] = analyst,
                [AppRole.SeniorAnalyst] = senior,
                [AppRole.Admin] = admin,
            };
        }
    }
}
