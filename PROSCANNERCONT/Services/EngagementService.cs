using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public sealed class EngagementService
    {
        private static readonly Lazy<EngagementService> _instance = new(() => new EngagementService());
        public static EngagementService Instance => _instance.Value;

        private readonly string _path = Path.Combine(AppConstants.Paths.ConfigDir, "engagements.json");
        private readonly object _lock = new();
        private List<Engagement> _engagements = new();
        private Guid? _activeId;

        public event EventHandler? ActiveChanged;

        public IReadOnlyList<Engagement> All
        {
            get { lock (_lock) return _engagements.ToList(); }
        }

        public Engagement? Active
        {
            get
            {
                lock (_lock)
                {
                    if (_activeId == null) return null;
                    return _engagements.FirstOrDefault(e => e.Id == _activeId.Value);
                }
            }
        }

        private EngagementService() => Load();

        public Engagement Create(string name, string client)
        {
            var e = new Engagement { Name = name, Client = client };
            lock (_lock) { _engagements.Add(e); _activeId = e.Id; Save(); }
            ActiveChanged?.Invoke(this, EventArgs.Empty);
            return e;
        }

        public void SetActive(Guid id)
        {
            lock (_lock)
            {
                if (_engagements.Any(e => e.Id == id))
                {
                    _activeId = id;
                    Save();
                }
            }
            ActiveChanged?.Invoke(this, EventArgs.Empty);
        }

        public void Update(Engagement e)
        {
            lock (_lock)
            {
                e.LastModified = DateTime.UtcNow;
                var idx = _engagements.FindIndex(x => x.Id == e.Id);
                if (idx >= 0) _engagements[idx] = e;
                Save();
            }
        }

        public void Delete(Guid id)
        {
            lock (_lock)
            {
                _engagements.RemoveAll(e => e.Id == id);
                if (_activeId == id) _activeId = null;
                Save();
            }
            ActiveChanged?.Invoke(this, EventArgs.Empty);
        }

        // ── Persistence ────────────────────────────────────────────────────
        private void Save()
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                var data = new SaveBlob { Engagements = _engagements, ActiveId = _activeId };
                File.WriteAllText(_path, JsonSerializer.Serialize(data,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Engagement] save failed"); }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_path)) return;
                var data = JsonSerializer.Deserialize<SaveBlob>(File.ReadAllText(_path));
                if (data != null)
                {
                    _engagements = data.Engagements ?? new();
                    _activeId    = data.ActiveId;
                }
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Engagement] load failed"); }
        }

        private sealed class SaveBlob
        {
            public List<Engagement>? Engagements { get; set; }
            public Guid? ActiveId { get; set; }
        }
    }

    /// <summary>
    /// Scope-guard: validates a scan target against the active engagement's
    /// in-scope / out-of-scope lists. Defence-in-depth control to prevent
    /// accidental scans of out-of-contract systems — the most common cause of
    /// a "we got a nasty letter from their legal team" Monday morning.
    /// </summary>
    public static class ScopeGuard
    {
        public sealed record ScopeCheckResult(bool Allowed, string Reason);

        public static ScopeCheckResult Check(string target)
        {
            var eng = EngagementService.Instance.Active;
            if (eng == null) return new(true, "No active engagement — scope guard inactive.");

            if (eng.ScopeOverrideActive) return new(true, "Manual scope-override active.");

            // Out-of-scope wins.
            foreach (var cidr in eng.OutOfScopeCidrs)
                if (CidrMatch(cidr, target))
                    return new(false, $"Target {target} is in OUT-OF-SCOPE block {cidr}.");

            // In-scope check.
            bool inAnyScope = eng.InScopeCidrs.Count == 0
                           || eng.InScopeCidrs.Any(c => CidrMatch(c, target))
                           || eng.InScopeDomains.Any(d => target.EndsWith(d, StringComparison.OrdinalIgnoreCase));

            if (!inAnyScope)
                return new(false, $"Target {target} is not in any engagement-scope CIDR.");

            if (eng.ForbidPublicTargets && IsPublicIp(target))
                return new(false, $"Target {target} is a public IP and engagement forbids public targets.");

            return new(true, "OK");
        }

        private static bool CidrMatch(string pattern, string ipStr)
        {
            try
            {
                if (!pattern.Contains('/'))
                    return string.Equals(pattern, ipStr, StringComparison.OrdinalIgnoreCase);

                var parts = pattern.Split('/');
                if (!IPAddress.TryParse(parts[0], out var net) ||
                    !IPAddress.TryParse(ipStr,    out var ip) ||
                    !int.TryParse(parts[1], out var prefix)) return false;

                if (net.AddressFamily != ip.AddressFamily) return false;
                byte[] nb = net.GetAddressBytes(), ib = ip.GetAddressBytes();
                int fullBytes = prefix / 8;
                int remBits   = prefix % 8;
                for (int i = 0; i < fullBytes; i++) if (nb[i] != ib[i]) return false;
                if (remBits == 0) return true;
                int mask = (byte)(0xFF << (8 - remBits));
                return (nb[fullBytes] & mask) == (ib[fullBytes] & mask);
            }
            catch { return false; }
        }

        private static bool IsPublicIp(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return false;
            var b = ip.GetAddressBytes();
            if (b.Length != 4) return false; // IPv6 left to operator policy.
            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false; // CGNAT
            return true;
        }
    }
}
