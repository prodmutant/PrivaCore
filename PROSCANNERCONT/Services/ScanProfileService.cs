using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public class ScanProfileService
    {
        private static readonly string _profilesPath = Path.Combine(
            AppConstants.Paths.ConfigDir, "scan_profiles.json");

        private List<ScanProfile> _profiles = new();

        public IReadOnlyList<ScanProfile> Profiles => _profiles.AsReadOnly();

        public void Load()
        {
            try
            {
                if (!File.Exists(_profilesPath)) { _profiles = new List<ScanProfile>(); return; }
                var json = File.ReadAllText(_profilesPath);
                _profiles = JsonSerializer.Deserialize<List<ScanProfile>>(json) ?? new List<ScanProfile>();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ScanProfileService.Load] {ex.Message}");
                _profiles = new List<ScanProfile>();
            }
        }

        public void Save(ScanProfile profile)
        {
            Load();
            var existing = _profiles.FirstOrDefault(p => p.Id == profile.Id);
            if (existing != null)
                _profiles[_profiles.IndexOf(existing)] = profile;
            else
                _profiles.Add(profile);
            Persist();
        }

        public void Delete(string profileId)
        {
            Load();
            _profiles.RemoveAll(p => p.Id == profileId);
            Persist();
        }

        public void MarkUsed(string profileId)
        {
            Load();
            var profile = _profiles.FirstOrDefault(p => p.Id == profileId);
            if (profile == null) return;
            profile.LastUsed = DateTime.Now;
            profile.TimesUsed++;
            Persist();
        }

        private void Persist()
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                File.WriteAllText(_profilesPath, JsonSerializer.Serialize(_profiles,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ScanProfileService.Persist] {ex.Message}");
            }
        }
    }
}
