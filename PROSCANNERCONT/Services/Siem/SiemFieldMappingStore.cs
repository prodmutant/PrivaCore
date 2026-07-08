using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// User-pinned field type mappings (the Elasticsearch "mappings" override): forces a field to a
    /// chosen <see cref="SiemFieldType"/> instead of the dynamic inference. Persists to %APPDATA% and
    /// registers <see cref="SiemFieldTypes.Override"/> so a mapping applies everywhere. Singleton.
    /// </summary>
    public sealed class SiemFieldMappingStore
    {
        public static SiemFieldMappingStore Instance { get; } = new();

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_field_mappings.json");

        private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

        private readonly object _lock = new();
        private Dictionary<string, SiemFieldType> _map;

        public event Action? Changed;

        private SiemFieldMappingStore()
        {
            _map = LoadFromDisk();
            SiemFieldTypes.Override = name =>
            {
                lock (_lock) return _map.TryGetValue(name, out var t) ? t : (SiemFieldType?)null;
            };
        }

        public int Count { get { lock (_lock) return _map.Count; } }
        public List<KeyValuePair<string, SiemFieldType>> All() { lock (_lock) return _map.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase).ToList(); }
        public SiemFieldType? Get(string field) { lock (_lock) return _map.TryGetValue(field, out var t) ? t : (SiemFieldType?)null; }

        public void Set(string field, SiemFieldType type)
        {
            if (string.IsNullOrWhiteSpace(field)) return;
            lock (_lock) _map[field.Trim()] = type;
            Save(); Changed?.Invoke();
        }

        public void Remove(string field)
        {
            lock (_lock) _map.Remove(field);
            Save(); Changed?.Invoke();
        }

        private static Dictionary<string, SiemFieldType> LoadFromDisk()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var d = JsonSerializer.Deserialize<Dictionary<string, SiemFieldType>>(File.ReadAllText(Path_), JsonOpts);
                    if (d != null) return new Dictionary<string, SiemFieldType>(d, StringComparer.OrdinalIgnoreCase);
                }
            }
            catch { }
            return new Dictionary<string, SiemFieldType>(StringComparer.OrdinalIgnoreCase);
        }

        private void Save()
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                Dictionary<string, SiemFieldType> snap; lock (_lock) snap = new(_map);
                File.WriteAllText(Path_, JsonSerializer.Serialize(snap, JsonOpts));
            }
            catch { }
        }
    }
}
