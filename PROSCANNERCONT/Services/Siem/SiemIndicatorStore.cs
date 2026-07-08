using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>One managed threat-intel indicator (IOC) — an Elastic Security indicator record.</summary>
    public sealed class SiemIndicator
    {
        public string Value { get; set; } = "";       // the IOC (ip / domain / hash / user)
        public string Type { get; set; } = "ip";       // ip | domain | hash | user | url | other
        public string Source { get; set; } = "manual"; // feed / analyst
        public string Note { get; set; } = "";
        public DateTime Added { get; set; } = DateTime.Now;

        public string AddedText => Added.ToString("MMM dd, HH:mm");
        public string TypeColor => Type switch
        {
            "ip" => "#58A6FF", "domain" or "url" => "#A371F7", "hash" => "#E3B341", "user" => "#39C5CF", _ => "#8B949E",
        };
    }

    /// <summary>
    /// The managed threat-intel indicator list (the Elastic Security "Indicators" / indicator-match
    /// source). Persists to %APPDATA% and exposes the values to the pipeline's IndicatorMatch processor
    /// via <see cref="SiemProcessor.GlobalIndicatorSource"/>. Singleton.
    /// </summary>
    public sealed class SiemIndicatorStore
    {
        public static SiemIndicatorStore Instance { get; } = new();

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "siem_indicators.json");

        private readonly object _lock = new();
        private List<SiemIndicator> _items;
        private HashSet<string> _values;

        public event Action? Changed;

        private SiemIndicatorStore()
        {
            _items = LoadFromDisk();
            _values = BuildSet(_items);
            // wire the pipeline's indicator-match to consult this central list
            SiemProcessor.GlobalIndicatorSource = () => { lock (_lock) return _values; };
        }

        public List<SiemIndicator> All() { lock (_lock) return _items.ToList(); }
        public int Count { get { lock (_lock) return _items.Count; } }

        public void Add(SiemIndicator i)
        {
            if (string.IsNullOrWhiteSpace(i.Value)) return;
            i.Value = i.Value.Trim();
            lock (_lock)
            {
                _items.RemoveAll(x => string.Equals(x.Value, i.Value, StringComparison.OrdinalIgnoreCase));
                _items.Insert(0, i);
                _values = BuildSet(_items);
            }
            Save(); Changed?.Invoke();
        }

        public void Remove(SiemIndicator i)
        {
            lock (_lock) { _items.RemoveAll(x => string.Equals(x.Value, i.Value, StringComparison.OrdinalIgnoreCase)); _values = BuildSet(_items); }
            Save(); Changed?.Invoke();
        }

        public void Clear()
        {
            lock (_lock) { _items.Clear(); _values = new(StringComparer.OrdinalIgnoreCase); }
            Save(); Changed?.Invoke();
        }

        private static HashSet<string> BuildSet(IEnumerable<SiemIndicator> items)
            => new(items.Select(i => i.Value), StringComparer.OrdinalIgnoreCase);

        private static List<SiemIndicator> LoadFromDisk()
        {
            try
            {
                if (File.Exists(Path_))
                {
                    var list = JsonSerializer.Deserialize<List<SiemIndicator>>(File.ReadAllText(Path_));
                    if (list != null) return list;
                }
            }
            catch { }
            return new List<SiemIndicator>();
        }

        private void Save()
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                List<SiemIndicator> snap; lock (_lock) snap = _items.ToList();
                File.WriteAllText(Path_, JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }
}
