using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Tracks the remote modules the user has added to their nav and persists them.
    /// The main app is a pure controller/client now — standalone module apps host
    /// themselves, so there is no in-app host here.
    /// </summary>
    public sealed class ModuleRegistry
    {
        public static ModuleRegistry Instance { get; } = new();

        public ObservableCollection<ManagedModule> Modules { get; } = new();

        private readonly string _path;

        private ModuleRegistry()
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore");
            Directory.CreateDirectory(dir);
            _path = Path.Combine(dir, "managed_modules.json");
            Load();
        }

        public bool Contains(string key) => Modules.Any(m => m.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

        public ManagedModule Add(ModuleDescriptor d)
        {
            // The same module type can be added multiple times (e.g. several sensors).
            int count = Modules.Count(m => m.Key.Equals(d.Key, StringComparison.OrdinalIgnoreCase));
            var m = new ManagedModule
            {
                InstanceId = Guid.NewGuid(),
                Key = d.Key,
                DisplayName = count == 0 ? d.DisplayName : $"{d.DisplayName} ({count + 1})",
                Icon = d.Icon,
                PageName = d.PageName,
                Host = "127.0.0.1",
                Port = d.DefaultPort,
            };
            Modules.Add(m);
            Save();
            return m;
        }

        public void Remove(ManagedModule m) { Modules.Remove(m); Save(); }

        private void Load()
        {
            Modules.Clear();
            if (!File.Exists(_path)) return;
            try
            {
                var saved = JsonSerializer.Deserialize<List<ManagedModule>>(File.ReadAllText(_path)) ?? new();
                foreach (var m in saved) Modules.Add(m);
            }
            catch { }
        }

        private void Save()
        {
            try { File.WriteAllText(_path, JsonSerializer.Serialize(Modules.ToList(), new JsonSerializerOptions { WriteIndented = true })); }
            catch { }
        }
    }
}
