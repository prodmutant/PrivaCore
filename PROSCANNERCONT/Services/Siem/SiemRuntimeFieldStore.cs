using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// The managed runtime-field list (ECS runtime fields). Persists to %APPDATA% and registers
    /// <see cref="SiemEvent.RuntimeFieldResolver"/> + <see cref="SiemEvent.RuntimeFieldNames"/> so the
    /// fields are computed at read time everywhere (Discover columns, KQL queries, aggregations). Singleton.
    /// </summary>
    public sealed class SiemRuntimeFieldStore
    {
        public static SiemRuntimeFieldStore Instance { get; } = new();

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_runtime_fields.json");

        private readonly object _lock = new();
        private List<SiemRuntimeField> _items;
        private Dictionary<string, SiemRuntimeField> _byName;

        // guards against a runtime field whose template references itself (directly or via a cycle)
        [ThreadStatic] private static HashSet<string>? _active;

        public event Action? Changed;

        private SiemRuntimeFieldStore()
        {
            _items = LoadFromDisk();
            _byName = BuildIndex(_items);
            SiemEvent.RuntimeFieldResolver = Resolve;
            SiemEvent.RuntimeFieldNames = Names;
        }

        public List<SiemRuntimeField> All() { lock (_lock) return _items.ToList(); }
        public int Count { get { lock (_lock) return _items.Count; } }

        public IReadOnlyCollection<string> Names()
        {
            lock (_lock) return _items.Where(f => f.Enabled && f.Name.Length > 0).Select(f => f.Name).ToList();
        }

        /// <summary>Compute a runtime field for an event, or null if there's no such (enabled) field. Cycle-safe.</summary>
        public string? Resolve(SiemEvent e, string name)
        {
            SiemRuntimeField? rf;
            lock (_lock) { if (!_byName.TryGetValue(name, out rf) || !rf.Enabled) return null; }
            _active ??= new(StringComparer.OrdinalIgnoreCase);
            if (!_active.Add(name)) return null;   // re-entrant on the same field → break the cycle
            try { return rf.Compute(e); }
            finally { _active.Remove(name); }
        }

        public void AddOrUpdate(SiemRuntimeField f)
        {
            if (string.IsNullOrWhiteSpace(f.Name)) return;
            f.Name = f.Name.Trim();
            lock (_lock)
            {
                _items.RemoveAll(x => string.Equals(x.Name, f.Name, StringComparison.OrdinalIgnoreCase));
                _items.Insert(0, f);
                _byName = BuildIndex(_items);
            }
            Save(); Changed?.Invoke();
        }

        public void Remove(SiemRuntimeField f)
        {
            lock (_lock) { _items.RemoveAll(x => string.Equals(x.Name, f.Name, StringComparison.OrdinalIgnoreCase)); _byName = BuildIndex(_items); }
            Save(); Changed?.Invoke();
        }

        private static Dictionary<string, SiemRuntimeField> BuildIndex(IEnumerable<SiemRuntimeField> items)
        {
            var d = new Dictionary<string, SiemRuntimeField>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in items) if (f.Name.Length > 0) d[f.Name] = f;
            return d;
        }

        private static List<SiemRuntimeField> LoadFromDisk()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var list = JsonSerializer.Deserialize<List<SiemRuntimeField>>(File.ReadAllText(Path_));
                    if (list != null) return list;
                }
            }
            catch { }
            return new List<SiemRuntimeField>();
        }

        private void Save()
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                List<SiemRuntimeField> snap; lock (_lock) snap = _items.ToList();
                File.WriteAllText(Path_, JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }
}
