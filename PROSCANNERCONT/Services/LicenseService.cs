using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public class LicenseService
    {
        // HMAC secret used to sign offline license keys.  Pulled from
        // SecretsManager so production builds can override it via DPAPI-encrypted
        // %APPDATA%\PrivaCore\Config\secrets.dat or the LICENSE_HMAC_SECRET env
        // var; the built-in default keeps the development flow working.
        private static string HmacSecret => SecretsManager.Get(SecretsManager.KeyLicenseHmac);
        private static readonly string _licensePath = Path.Combine(
            AppConstants.Paths.ConfigDir, "license.json");

        public static LicenseService Instance { get; } = new();
        public LicenseInfo Current { get; private set; } = LicenseInfo.CreateFree();

        private LicenseService() => LoadSaved();

        public LicenseValidationResult Activate(string licenseKey)
        {
            try
            {
                var result = Validate(licenseKey);
                if (result.IsValid)
                {
                    Current = result.License!;
                    SaveLicense(licenseKey, result.License!);
                }
                return result;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[LicenseService.Activate] {ex.Message}");
                return new LicenseValidationResult { IsValid = false, ErrorMessage = "Activation failed." };
            }
        }

        public LicenseValidationResult Validate(string rawKey)
        {
            try
            {
                // Strip formatting
                var key = rawKey.Replace("-", "").Replace(" ", "").ToUpperInvariant();
                if (key.Length < 16)
                    return Fail("Invalid key format.");

                // Split: last 8 chars = HMAC fragment, rest = payload
                var payload = key[..^8];
                var providedMac = key[^8..];
                var expectedMac = ComputeMac(payload)[..8];

                if (!string.Equals(providedMac, expectedMac, StringComparison.OrdinalIgnoreCase))
                    return Fail("Invalid license key.");

                // Decode payload: first char = tier, next 8 = expiry yyyyMMdd, rest = user hash
                if (payload.Length < 9) return Fail("Malformed key.");
                var tier = payload[0] switch { 'P' => LicenseTier.Pro, 'E' => LicenseTier.Enterprise, _ => LicenseTier.Free };
                var expiryStr = payload[1..9];
                if (!DateTime.TryParseExact(expiryStr, "yyyyMMdd",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var expiry))
                    return Fail("Could not parse expiry date.");

                if (expiry < DateTime.Today)
                    return Fail($"License expired on {expiry:yyyy-MM-dd}.");

                var license = new LicenseInfo
                {
                    LicenseKey = rawKey,
                    Tier = tier,
                    IsValid = true,
                    ActivatedAt = DateTime.Now,
                    ExpiresAt = expiry,
                    LicensedTo = "Licensed User",
                };
                return new LicenseValidationResult { IsValid = true, License = license };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[LicenseService.Validate] {ex.Message}");
                return Fail("Validation error.");
            }
        }

        private void LoadSaved()
        {
            try
            {
                if (!File.Exists(_licensePath)) return;
                var saved = JsonSerializer.Deserialize<SavedLicense>(File.ReadAllText(_licensePath));
                if (saved == null) return;
                var result = Validate(saved.Key);
                if (result.IsValid) Current = result.License!;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[LicenseService.LoadSaved] {ex.Message}");
            }
        }

        private void SaveLicense(string key, LicenseInfo info)
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                File.WriteAllText(_licensePath, JsonSerializer.Serialize(
                    new SavedLicense { Key = key, ActivatedAt = info.ActivatedAt },
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[LicenseService.SaveLicense] {ex.Message}");
            }
        }

        private string ComputeMac(string payload)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(HmacSecret));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return Convert.ToHexString(hash).ToUpperInvariant();
        }

        private static LicenseValidationResult Fail(string msg) =>
            new() { IsValid = false, ErrorMessage = msg };

        private class SavedLicense
        {
            public string Key { get; set; } = string.Empty;
            public DateTime ActivatedAt { get; set; }
        }
    }

    public class LicenseValidationResult
    {
        public bool IsValid { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public LicenseInfo? License { get; set; }
    }
}
