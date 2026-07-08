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
    public class AssetInventoryService
    {
        private static readonly string _inventoryPath = Path.Combine(
            AppConstants.Paths.ConfigDir, "asset_inventory.json");

        private List<AssetRecord> _assets = new();

        public IReadOnlyList<AssetRecord> Assets => _assets.AsReadOnly();

        public static AssetInventoryService Instance { get; } = new();

        private AssetInventoryService() => Load();

        public void Load()
        {
            try
            {
                if (!File.Exists(_inventoryPath)) { _assets = new(); return; }
                var json = File.ReadAllText(_inventoryPath);
                _assets = JsonSerializer.Deserialize<List<AssetRecord>>(json) ?? new();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AssetInventoryService.Load] {ex.Message}");
                _assets = new();
            }
        }

        // Called after a network scan â€” returns change summary
        public NetworkChangeSummary UpdateFromScan(List<NetworkDevice> scannedDevices)
        {
            var summary = new NetworkChangeSummary();
            var now = DateTime.Now;

            foreach (var device in scannedDevices)
            {
                var existing = _assets.FirstOrDefault(a =>
                    a.IPAddress == device.IPAddress ||
                    (!string.IsNullOrEmpty(a.MacAddress) && a.MacAddress == device.MACAddress));

                if (existing == null)
                {
                    // New device
                    var record = new AssetRecord
                    {
                        IPAddress = device.IPAddress,
                        Hostname = device.Hostname,
                        MacAddress = device.MACAddress,
                        OS = device.OS,
                        DeviceType = device.DeviceType,
                        IsOnline = device.IsOnline,
                        FirstSeen = now,
                        LastSeen = now,
                    };
                    record.History.Add(new AssetEvent { EventType = "FirstSeen", Detail = $"First discovered at {device.IPAddress}" });
                    _assets.Add(record);
                    summary.NewDevices.Add($"{device.IPAddress} ({device.Hostname})");
                }
                else
                {
                    // Existing device â€” track changes
                    if (!existing.IsOnline && device.IsOnline)
                    {
                        existing.History.Add(new AssetEvent { EventType = "Online", Detail = "Device came back online" });
                    }
                    else if (existing.IsOnline && !device.IsOnline)
                    {
                        existing.History.Add(new AssetEvent { EventType = "Offline", Detail = "Device went offline" });
                        summary.DisappearedDevices.Add($"{device.IPAddress} ({device.Hostname})");
                    }

                    if (existing.OS != device.OS && !string.IsNullOrEmpty(device.OS))
                    {
                        existing.History.Add(new AssetEvent { EventType = "ServiceChanged", Detail = $"OS changed from '{existing.OS}' to '{device.OS}'" });
                        summary.ServiceChanges.Add($"{device.IPAddress}: OS {existing.OS} â†’ {device.OS}");
                        existing.OS = device.OS;
                    }

                    existing.Hostname = device.Hostname;
                    existing.IsOnline = device.IsOnline;
                    existing.LastSeen = now;
                    existing.TimesDiscovered++;

                    // Trim history to last 100 events
                    if (existing.History.Count > 100)
                        existing.History = existing.History.TakeLast(100).ToList();
                }
            }

            // Check for devices that disappeared since last scan
            var scannedIps = scannedDevices.Select(d => d.IPAddress).ToHashSet();
            foreach (var asset in _assets.Where(a => a.IsOnline && !scannedIps.Contains(a.IPAddress)))
            {
                summary.DisappearedDevices.Add($"{asset.IPAddress} ({asset.Hostname})");
                asset.IsOnline = false;
                asset.History.Add(new AssetEvent { EventType = "Offline", Detail = "Not found in latest scan" });
            }

            Persist();
            return summary;
        }

        // Called after a port scan â€” tracks port/service changes per device
        public void UpdatePortsForDevice(string ipAddress, List<PortScanResult> openPorts)
        {
            var asset = _assets.FirstOrDefault(a => a.IPAddress == ipAddress);
            if (asset == null) return;

            var newPorts = openPorts.Where(p => p.IsOpen).Select(p => p.Port).ToList();
            var newServices = openPorts.Where(p => p.IsOpen && !string.IsNullOrEmpty(p.Service))
                .Select(p => $"{p.Port}/{p.Service}").ToList();

            foreach (var port in newPorts.Except(asset.KnownOpenPorts))
            {
                var svc = openPorts.FirstOrDefault(p => p.Port == port)?.Service ?? "";
                asset.History.Add(new AssetEvent { EventType = "NewPort", Detail = $"New open port: {port} ({svc})" });
            }
            foreach (var port in asset.KnownOpenPorts.Except(newPorts))
            {
                asset.History.Add(new AssetEvent { EventType = "PortClosed", Detail = $"Port closed: {port}" });
            }

            asset.KnownOpenPorts = newPorts;
            asset.KnownServices = newServices;
            asset.LastSeen = DateTime.Now;

            if (asset.History.Count > 100)
                asset.History = asset.History.TakeLast(100).ToList();

            Persist();
        }

        public void SetNotes(string ipAddress, string notes)
        {
            var asset = _assets.FirstOrDefault(a => a.IPAddress == ipAddress);
            if (asset == null) return;
            asset.Notes = notes;
            Persist();
        }

        public void SetRisk(string ipAddress, AssetRisk risk)
        {
            var asset = _assets.FirstOrDefault(a => a.IPAddress == ipAddress);
            if (asset == null) return;
            asset.RiskRating = risk;
            Persist();
        }

        public AssetRecord? GetByIp(string ip) => _assets.FirstOrDefault(a => a.IPAddress == ip);

        public List<AssetRecord> Search(string query)
        {
            query = query.ToLowerInvariant();
            return _assets.Where(a =>
                a.IPAddress.Contains(query) ||
                a.Hostname.ToLowerInvariant().Contains(query) ||
                a.OS.ToLowerInvariant().Contains(query) ||
                a.DeviceType.ToLowerInvariant().Contains(query) ||
                a.Notes.ToLowerInvariant().Contains(query)).ToList();
        }

        private void Persist()
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                File.WriteAllText(_inventoryPath, JsonSerializer.Serialize(_assets,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AssetInventoryService.Persist] {ex.Message}");
            }
        }
    }
}
