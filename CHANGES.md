# PrivaCore — Rework Changes

Comprehensive changelog for the rework session.  Builds with **0 errors**, all
**28** new unit tests pass.  **Honeypot subsystem** (HoneypotDashboardPage,
Vmterminalwindow, Vmsettingswindow, Sshconfigwindow, OSSelectionWindow,
HyperVManager, SSHConnectionManager, Honeypot* models) was **explicitly not
touched** per instruction.

---

## Table of contents

1. [At-a-glance](#at-a-glance)
2. [Theming overhaul — App.xaml dynamic colours](#1-theming-overhaul)
3. [Foundations](#2-foundations)
4. [Detection enhancements](#3-detection-enhancements)
5. [Workflow features](#4-workflow-features)
6. [Reporting & compliance](#5-reporting--compliance)
7. [Integrations](#6-integrations)
8. [New scanner modules](#7-new-scanner-modules)
9. [Architecture & quality](#8-architecture--quality)
10. [File-by-file map](#file-by-file-map)
11. [Build & run](#build--run)

---

## At-a-glance

| Bucket | Count | Highlights |
|---|---|---|
| Tasks delivered | 35 / 35 | All Tier-1 → Tier-6 items |
| New service files | 29 | Under `Services/` |
| New model files | 1 | `Models/Engagement.cs` |
| Modified files | 22 | App, theme, IDS engine, settings, secrets, reports, 13 views |
| New unit-test project | 1 | `PROSCANNERCONT.Tests` — 6 test classes, 28 tests |
| CI workflow | 1 | `.github/workflows/ci.yml` — build / test / format / CodeQL |
| Honeypot files touched | 0 | Excluded per instruction |

---

## 1. Theming overhaul

### What changed
- **`App.xaml`** — added contrast-aware semantic brushes that previously didn't exist:
  - `OnAccentBrush`, `OnDangerBrush`, `OnSuccessBrush`, `OnWarningBrush` — foreground colour for text/icons sitting on top of an accent/danger/success/warning fill.  Auto-picks white-on-dark or black-on-light per theme via WCAG relative-luminance.
  - `DisabledTextBrush`, `OverlayBackgroundBrush`, `ShadowColorBrush` — derive from the active theme.
  - Severity palette: `SeverityCriticalBrush`, `SeverityHighBrush`, `SeverityMediumBrush`, `SeverityLowBrush`, `SeverityInfoBrush` and matching `*BgBrush` faded backgrounds for badges and row tints.
- **`App.xaml`** — every hardcoded `White` foreground was the wrong choice on light themes.  Fixed in: `BaseButtonStyle`, `AccentButtonStyle`, `GhostButtonStyle`, `DangerButtonStyle`, `scancompleted` label, `DataGridColumnHeader`, sort arrow `Path.Fill`, toggle thumb `Border.Background`.
- **`Managers/ThemeManager.cs`** — `ApplyImmediate` now also computes and patches every brush above on each theme switch.  New helpers: `SetContrastBrush` (WCAG luminance), `MakeTintedBg` (faded severity backdrop).  `ApplyCustomColors` updated to set the same derived brushes for user-defined themes.

### XAML files swept for hardcoded colours

| File | Replaced | Approach |
|---|---|---|
| `Views/Networkidsdashboardpage.xaml` | 33 hex values | Routed every severity colour to `Severity*Brush` / `Severity*BgBrush` |
| `Views/DashboardPage.xaml` | 8 severity row-tint colours | Routed to `Severity*BgBrush` |
| `Views/VulnerabilityScannerPage.xaml` | 20 hex values | Datagrid alt rows → `HoverBrush`, headers → `SelectionBrush`, CVE badges → semantic brushes |
| `Views/MiscellaneousPage.xaml` | 9 hex values | Same pattern |
| `Views/POCExplorerPage.xaml` | 11 hex values | Script box → `Background/Success`, badges → `Critical` |
| `Views/Hostidsdashboardpage.xaml` | 5 hex values | Critical/medium/low severities |
| `Views/NetworkTopologyPage.xaml` | 2 hex values | Overlay + muted text only — device-type colours intentionally preserved |
| `Views/CVEDetailsWindow.xaml` | 4 hex values | Datagrid + icon background |
| `Views/RuleEditorWindow.xaml` | 5 hex values | Caret + error text + info chip |
| `Views/IDSSetupWizardPage.xaml` | 4 hex values | Severity medium |
| `Views/ProfilePage.xaml` | 6 hex values | Account status, stats counters |
| `Views/GalleryPage.xaml` | 1 hex value | Hover overlay |

### Deliberately preserved
| File | Why |
|---|---|
| `Views/Achievements page.xaml` | Gold/blue/green/orange/purple are achievement-category data colours, not theme colours. |
| `Views/SettingsPage.xaml` (~132 hex values) | Theme preview swatches must show the actual colour of each theme. |
| `Views/NetworkTopologyPage.xaml` (8 remaining) | Device-type semantic colours (router cyan, gateway orange, server green, workstation purple, unknown grey). |
| `Views/ScreenshotViewer.xaml` | Full-screen image viewer — always-dark canvas is a deliberate UX choice. |
| `Views/DashboardPage.xaml` (4 remaining) | `LinearGradientBrush.GradientStop.Color` needs `Color` not `Brush` — can't directly `DynamicResource`. |
| Honeypot files (HoneypotDashboardPage, Vmterminalwindow, OSSelectionWindow) | Excluded per instruction. |

---

## 2. Foundations

### `Services/SecretsManager.cs` *(new)*
DPAPI-encrypted key/value store at `%APPDATA%\PrivaCore\Config\secrets.dat`.
Lookup order: disk → environment variable → built-in default.  Replaces every
hardcoded secret in source code.

**Migrated**:
- `Security/NVDChecker.cs:15` — `NVD_API_KEY` const → property reading `SecretsManager.KeyNvdApiKey`.
- `Services/LicenseService.cs:16` — `_hmacSecret` const → property reading `SecretsManager.KeyLicenseHmac`.
- `MainWindow.xaml.cs:51-52` — `ApiKey` / `AnthropicKey` from env-var-only `static readonly` → properties reading `SecretsManager`.

### `Services/AppLogger.cs` *(new)*
Serilog facade with rolling daily file sink under `%APPDATA%\PrivaCore\logs\`,
30-day retention, 25 MB file size cap, Debug-pane mirror, enriched with App +
Version properties.  Critical for forensic post-incident review of a security
tool.

**Wired in `App.OnStartup`**:
- `AppLogger.Log.Information("=== starting ===")`
- `AppDomain.UnhandledException`, `DispatcherUnhandledException`,
  `TaskScheduler.UnobservedTaskException` all funnel into the log instead of
  crashing silently.
- `App.OnExit` calls `AppLogger.Shutdown()` to flush.

### `Services/NpcapDetector.cs` *(new)*
Probes `HKLM\SOFTWARE\WOW6432Node\Npcap` and `system32\drivers\npcap.sys`
on startup.  Shows a non-blocking dialog with the npcap.com link if missing,
instead of letting Traffic Analysis / NIDS crash on first capture.

### `Views/SettingsPage.xaml.cs`
- `SaveAPIKey_Click` now writes the OpenAI key via `SecretsManager.Set`
  (DPAPI-encrypted) instead of plaintext JSON in `appsettings.json`.
- `LoadAppSettings` performs a one-shot migration: if a legacy plaintext key
  is in `appsettings.json`, it's moved into the encrypted store and stripped
  from the JSON.
- `UpdateAIStatus` uses `SecretsManager.Has()` instead of only env-var checks.

### `App.xaml.cs`
- Builds the DI container (`ServiceContainer.Build()`) before any other init.
- Starts the threat-intel background refresh.
- Runs the Npcap detector on a worker thread.

---

## 3. Detection enhancements

### MITRE ATT&CK technique mapping
- **`Services/MitreReferenceService.cs`** *(new)* — 32 techniques across 14 tactics, each with `TechniqueInfo` (id / name / tactic / tacticId / attack.mitre.org URL).  Plus a `FromCategory()` fallback that maps the legacy `AttackCategory` strings (`"Brute Force"`, `"Port Scan"`, `"DNS Tunneling"`, etc.) onto the right technique.  `TacticColour()` returns a per-tactic colour for UI badges.
- **`Models/IDSAlert.cs`** — added `MitreTechniqueId`, `MitreTechniqueName`, `MitreTactic`, `JA4Hash`, `JA4String`, `ThreatIntelTags` fields.
- **`Models/IDSRule.cs`** — added `MitreTechniqueId`, `MitreTactic` so built-in rules can map explicitly; user rules fall back to category-derived mapping.
- **`Services/IDSManager.cs`** — `BuildAlert` and `RaiseBehavioralAlert` now call a shared `ApplyMitreMapping` helper that sets the three Mitre fields on every alert.

### JA4 fingerprinting
- **`Services/IDSManager.cs`** — added a new `Ja4Fingerprinter` static class next to the existing `Ja3Fingerprinter`.  Implements the FoxIO JA4 spec: `{proto}{ver}{sniFlag}{cipherCount}{extCount}{alpn}_{sha256-of-sorted-ciphers[:12]}_{sha256-of-sorted-extensions+sigalgos[:12]}`.  Sorted extension list resists Chrome's randomised extension-order evasion that breaks JA3.
- The packet handler now invokes both fingerprinters; alerts carry both JA3 and JA4.

### Threat-intel feeds
- **`Services/ThreatIntelService.cs`** *(new)* — singleton that ingests three free public feeds every 6 h:
  - **abuse.ch Feodo Tracker** (botnet C2 IPs)
  - **abuse.ch URLhaus** (malware delivery hosts)
  - **abuse.ch ThreatFox** (multi-platform IoCs)

  Caches raw feeds to `%APPDATA%\PrivaCore\threatintel\` and exposes a
  millisecond-fast `Lookup(indicator, kind)` over a `ConcurrentDictionary`.
- **`Services/IDSManager.cs`** — `EmitAlert` calls `ThreatIntelService.Instance.Lookup(srcIp, "ip")`; on a hit, it sets `alert.ThreatIntelTags = "feodo:c2-emotet; threatfox:lumma"` and bumps severity to High if it was lower.

### YARA-lite engine
- **`Services/YaraLiteScanner.cs`** *(new)* — subset YARA parser & scanner with no native dependency.  Supports:
  - ASCII strings (`$a = "evil"`)
  - Hex with single-byte wildcards (`$b = { 4D 5A ?? 00 }`)
  - Regex strings (`$c = /[A-Z]{8}/`)
  - Conditions: `any of them`, `all of them`, `N of them`, `$a and $b`, `$a or $b`
- Use case: scan packet payloads in NIDS and dropped files in HIDS without taking the libyara P/Invoke + licensing baggage.

### DoH / DoT detection
- **`Services/DohDetector.cs`** *(new)* — catalogue of 10 known DoH/DoT providers (Cloudflare, Google, Quad9, OpenDNS, AdGuard, NextDNS, Mullvad, CleanBrowsing) by IPv4/IPv6.  `Detect(dstIp, dstPort)` returns provider + protocol if matched.
- **`Services/IDSManager.cs`** — packet handler invokes `DohDetector.Detect` for outbound TCP/443 and TCP/853, raises a Medium severity "Encrypted DNS to {provider}" alert with `AttackCategory = "DNS Tunneling"`.  Rate-limited to one alert per source per hour.

### Kerberos attack detection
- **`Services/IDSManager.cs`** — `DetectKerberosAttacks` parses Kerberos-over-TCP messages on port 88:
  - **Kerberoasting** — counts TGS-REQ (ASN.1 tag `0x6C`) per source over a 2-min window; fires at threshold 15.
  - **AS-REP roastable** — AS-REQ (tag `0x6A`) under 200 bytes with no PA-ENC-TIMESTAMP pre-auth byte sequence.
  - **RC4 etype response** — AS-REP / TGS-REP (tags `0x6B`, `0x6D`) containing the `0x02 0x01 0x17` INTEGER pattern (etype 23 = RC4-HMAC-MD5).
- All three feed into the MITRE mapping (`T1558.003`, `T1558.004`).

### TLS certificate expiry monitor
- **`Services/CertExpiryMonitor.cs`** *(new)* — `ProbeAsync(host, port)` does a TLS handshake, captures the leaf cert, persists `(host, port, subject, issuer, notAfter, thumbprint, observedAt)` to `cert_observations.json`.  `ExpiringSoon` enumerates certs that have expired or expire within 30 days.

---

## 4. Workflow features

### Engagement workspace + scope guard
- **`Models/Engagement.cs`** *(new)* — `{ Id, Name, Client, Contact, Notes, StartDate, EndDate, InScopeCidrs[], OutOfScopeCidrs[], InScopeDomains[], ForbidPublicTargets, ScopeOverrideActive }`.
- **`Services/EngagementService.cs`** *(new)* — singleton; CRUD over engagements, persists to `engagements.json`, fires `ActiveChanged` event.
- **`Services/EngagementService.cs` → `ScopeGuard`** — `Check(target)` validates a scan target against the active engagement: out-of-scope wins over in-scope; public-IP block configurable; one-shot manual override flag.  Stops "I clicked the wrong network at 11 PM on a Friday" incidents.

### Scan diff / delta
- **`Services/ScanDiffService.cs`** *(new)* — `Compare(baseline, latest, target, baselineTime, latestTime)` returns a `ScanDiff` with `Ports` (Opened / Closed / ServiceChanged / VersionChanged) and `Cves` (New / Fixed).  Includes a `ToMarkdown(diff)` helper for export.

### Scheduled scans
- **`Services/ScheduleService.cs`** *(new)* — own 5-field cron parser (`m h dom mon dow`, supports `*`, `*/N`, `1,5,10`, `1-5`).  Fires jobs from a background loop every 30 s.  Persists to `schedule.json`.  Job types: `PortScan`, `NetworkDiscovery`, `VulnerabilityScan`, `TlsCertProbe`, `ThreatIntelRefresh`, `AssetInventoryRefresh`.  Avoids a 1.5 MB Quartz.NET dependency for the small need here.

### PCAP import & replay
- **`Services/PcapReplayService.cs`** *(new)* — wraps `SharpPcap.LibPcap.CaptureFileReaderDevice`.  Snapshots each `PacketCapture` (ref struct) into a heap-safe `ReplayedPacket` before raising the event, so handlers can run cross-thread.  Optional `RealtimePacing` honours original timestamps for demo playback.

### Credential vault
- **`Services/CredentialVault.cs`** *(new)* — DPAPI-encrypted `vault.dat`.  Entries: `{ Id, Name, Type, Host, Port, Username, Secret, Notes, Created, LastUsed }`.  Type tag drives consumer filtering (`ByType("ssh")`).  Excluded from backups by default — DPAPI keys don't roam.

### Loot collector
- **`Services/LootCollector.cs`** *(new)* — structured artifact store at `%APPDATA%\PrivaCore\loot\`.  `Ingest(source, description, name, bytes)` writes the blob, computes SHA-256, sniffs MIME from magic bytes (MZ / ELF / PK / PDF / PNG / JPEG / gzip) or extension, and records metadata in `loot.json`.  Auto-tags with the active `EngagementId`.

### Webhook notifications
- **`Services/NotificationDispatcher.cs`** *(new)* — fan-out alert dispatcher subscribed to `IDSManager.Engine.AlertGenerated`.  Channels:
  - **Slack** — `{ text }` JSON
  - **Discord** — `{ content }` JSON
  - **Teams** — Adaptive-card-friendly `{ type, text }`
  - **Generic** — full structured `{ title, body, severity, sourceIp, destIp, port, mitre, tactic, threatIntel, timestamp }`
  - **Email** — SMTP with credentials pulled from `SecretsManager`

  Per-sink filters: `MinSeverity`, `FilterTactic`.  Sinks persist to
  `notification_sinks.json`.

---

## 5. Reporting & compliance

### Compliance mapping
- **`Services/ComplianceMappingService.cs`** *(new)* — maps findings onto five frameworks:
  - **PCI-DSS 4.0** — 1.4.2, 4.2.1, 6.4.1, 11.4.1
  - **HIPAA Security Rule** — 164.312(b), 164.312(e)(1), 164.308(a)(1)(ii)(A)
  - **NIST 800-53 r5** — SC-8, SI-4, RA-5
  - **CIS Controls v8** — 4.1, 7.1, 13.1
  - **ISO 27001:2022** — A.8.7, A.8.8, A.8.16

  Each control evaluates to `{ Passed, Evidence }`.  Lets you generate a
  "PCI 11 status" page direct from a scan.

### Native PDF export
- **`Services/PdfReportExporter.cs`** *(new)* — QuestPDF (community licence).  `GeneratePortScanReport(target, results, filePath, company, logoText)` produces a multi-page A4 PDF with executive summary, open-ports table, and per-port CVE detail with severity-coloured borders.  Replaces the "open HTML in browser, print to PDF" workaround.

### DOCX export
- **`Services/DocxReportExporter.cs`** *(new)* — DocumentFormat.OpenXml SDK.  Generates an editable Word document with header, exec summary, port table, and CVE detail — the format every pentest client wants to edit before delivery.

### Light theme + branding for HTML reports
- **`Services/ReportGenerator.cs`** — added static properties `ReportTheme` (`"dark" | "light" | "auto"`), `ReportLogo`, `ReportCompany`, `ReportAccentColor`.  `HtmlHead` now delegates to `HtmlHeadInternal(theme)` which threads the bg/fg/card/border/subtle/accent palette through every CSS rule.  Existing dark theme is the default; setting `ReportTheme = "light"` flips the entire CSS.

---

## 6. Integrations

### REST API
- **`Services/RestApiServer.cs`** *(new)* — `HttpListener`-based read-only API.  Defaults to `http://127.0.0.1:8765`, localhost-only.  Auto-generates a 32-char API key on first start.  Endpoints:
  - `GET /api/health` — liveness probe
  - `GET /api/scans` — recent scan results
  - `GET /api/alerts` — last 200 IDS alerts
  - `GET /api/assets` — asset inventory snapshot
  - `GET /api/threats` — TI feed stats
  - `GET /api/engagement` — active engagement
  - `GET /api/certs/expiring` — certs expiring ≤ 30 days

  Pure HttpListener avoids the 30 MB Kestrel dependency for a small local API.

### CLI / headless mode
- **`Services/PrivaCoreCli.cs`** *(new)* — invoked when the first argv is a known subcommand (no `-` prefix).  Subcommands:
  ```
  portscan    --target IP|CIDR  [--ports 1-1024]  [--out report.html]
  netdiscover --range CIDR
  vulnscan    --target IP        [--ports 1-1024] [--out report.html]
  ti-refresh
  cert-probe  --host HOST        [--port 443]
  ```
  Every scan goes through `ScopeGuard.Check` first, so CI runs respect engagement boundaries.

### Backup / restore
- **`Services/BackupService.cs`** *(new)* — zips `%APPDATA%\PrivaCore` to a single file with optional inclusion flags for the vault, secrets, logs, and loot blobs.  `RestoreAsync` extracts back over the AppData directory.  Default profile excludes vault.dat / secrets.dat because DPAPI keys don't roam between machines.

---

## 7. New scanner modules

### TLS / SSL scanner — `Services/TlsScannerService.cs`
testssl.sh-lite.  Probes each TLS protocol version individually
(TLS 1.3 / 1.2 / 1.1 / 1.0 / SSLv3), captures the leaf cert on the first
success, then assigns an A+ → F letter grade based on:
- SSLv3 enabled → F (POODLE)
- TLS 1.0/1.1 → C (deprecated, PCI prohibited)
- No TLS 1.2 or 1.3 → F
- Cert expired / < 14 d / < 30 d → tiered alerts
- Self-signed cert → flagged
- TLS 1.3 supported and no findings → A+

### Web app scanner — `Services/WebScannerService.cs`
DAST-lite, six probes per target:
1. **Security-header audit** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.  Server / X-Powered-By disclosure.
2. **Cookie flags** — Secure / HttpOnly / SameSite checks.
3. **Directory busting** — 55-entry built-in wordlist (admin/, api, backup, .env, .git/HEAD, config, dump.sql, phpinfo.php, server-status, actuator/env, swagger.json, …), 8-way parallel.
4. **Reflected XSS canary** — `?q=<proscanxss>` echo check.
5. **SQL-error reflection** — sends `id=1'`, looks for known DB error strings.
6. **robots.txt / sitemap.xml discovery.**

Every scan validates the host against `ScopeGuard` first.

### OSINT panel — `Services/OsintService.cs`
- **crt.sh** — certificate-transparency subdomain enumeration.
- **WHOIS** — IANA → registry referral chain via raw TCP/43.
- **HaveIBeenPwned passwords** — SHA-1 k-anonymity (no full hash leaves the host).
- **Shodan host lookup** — full host record (requires `SHODAN_API_KEY`).
- **VirusTotal hash lookup** — file reputation by SHA-256 (requires `VIRUSTOTAL_API_KEY`).

All API-key-bearing services no-op gracefully when the key isn't set.

### Active Directory recon — `Services/AdReconService.cs`
LDAP read-only via `System.DirectoryServices.Protocols`:
- Users + UAC flags + SPNs + lastLogon + pwdLastSet → flags Kerberoastable (`SPN set && !disabled`) and AS-REP-roastable (`UAC & 0x400000`).
- Computers + OS + version + pwdLastSet → flags stale-credential machines and legacy OS (XP / 2003 / 2008).
- Domain Admins group membership → flags overprivilege.
- Findings auto-classified Critical / High / Medium.

### Wireless scanner — `Services/WirelessScannerService.cs`
Wraps `netsh wlan show networks mode=bssid`.  Parses SSID / BSSID / signal % /
channel / radio type / auth / encryption / WPS-enabled.  No P/Invoke
dependency — netsh is universally present.

### Container image scanner — `Services/ContainerScannerService.cs`
Wraps `trivy image --format json` if `trivy.exe` is on PATH.  Parses
vulnerabilities + misconfigurations.  Friendly install hint if trivy missing.

### Email recon — `Services/EmailReconService.cs`
SPF / DMARC / MTA-STS / MX via `nslookup` shell-out.  Flags policy weaknesses:
- No SPF → spoofable
- SPF `+all` → wide open (Critical)
- SPF `~all` / `?all` → soft enforcement
- DMARC `p=none` → monitoring-only
- No MTA-STS → no enforced TLS to MX

---

## 8. Architecture & quality

### DI container — `Services/ServiceContainer.cs`
Microsoft.Extensions.DependencyInjection composition root, built in
`App.OnStartup`.  Registers existing singletons (`StateService`,
`TrafficCaptureService`, `IDSManager.Engine`, …) so new code can take them
through constructor injection while legacy code keeps using `.Instance`.

### Unit tests — `PROSCANNERCONT.Tests/`

| File | Tests |
|---|---|
| `MitreReferenceServiceTests.cs` | 9 — category mapping, technique lookup, tactic-colour disambiguation |
| `ScopeGuardTests.cs` | 3 — inactive engagement, in-scope pass, out-of-scope block |
| `ScheduleServiceTests.cs` | 3 — every-minute, every-six-hours-step, specific-hour cron |
| `YaraLiteScannerTests.cs` | 3 — ASCII match, hex-with-wildcard, miss |
| `DohDetectorTests.cs` | 6 — Cloudflare DoH/DoT, Google, Quad9, unknown IP, non-DoH port |
| `ScanDiffServiceTests.cs` | 4 — opened, closed, service-changed |
| **Total** | **28 / 28 passing** |

`PROSCANNERCONT.sln` updated to include the test project.

### GitHub Actions CI — `.github/workflows/ci.yml`
- `build-test` job: restore → build (Release) → test → format check (non-blocking) → upload `.trx` results.
- `codeql` job: parallel CodeQL static analysis on `csharp`.
- NuGet package cache for fast subsequent builds.

---

## File-by-file map

### New files (35)

| Path | Purpose |
|---|---|
| `Services/SecretsManager.cs` | DPAPI-encrypted secrets store |
| `Services/AppLogger.cs` | Serilog facade |
| `Services/NpcapDetector.cs` | Friendly install prompt |
| `Services/MitreReferenceService.cs` | MITRE ATT&CK technique catalogue |
| `Services/ThreatIntelService.cs` | abuse.ch feed ingestion |
| `Services/YaraLiteScanner.cs` | Subset YARA engine |
| `Services/DohDetector.cs` | Known DoH/DoT provider IPs |
| `Services/CertExpiryMonitor.cs` | TLS cert expiry tracking |
| `Services/EngagementService.cs` | Pentesting workspace + ScopeGuard |
| `Services/ScanDiffService.cs` | Scan delta calculator |
| `Services/ScheduleService.cs` | Cron-style scheduler |
| `Services/PcapReplayService.cs` | PCAP import & replay |
| `Services/CredentialVault.cs` | DPAPI credential store |
| `Services/LootCollector.cs` | Artifact collector |
| `Services/NotificationDispatcher.cs` | Webhook + email fan-out |
| `Services/ComplianceMappingService.cs` | Framework-control evaluator |
| `Services/PdfReportExporter.cs` | QuestPDF report generator |
| `Services/DocxReportExporter.cs` | OpenXML report generator |
| `Services/RestApiServer.cs` | Localhost read-only API |
| `Services/PrivaCoreCli.cs` | Headless mode entrypoint |
| `Services/BackupService.cs` | Zip export / restore |
| `Services/TlsScannerService.cs` | SSL/TLS posture scanner |
| `Services/WebScannerService.cs` | DAST-lite |
| `Services/OsintService.cs` | Shodan / crt.sh / WHOIS / HIBP / VT |
| `Services/AdReconService.cs` | LDAP recon |
| `Services/WirelessScannerService.cs` | netsh wlan parser |
| `Services/ContainerScannerService.cs` | Trivy CLI wrapper |
| `Services/EmailReconService.cs` | SPF/DMARC/MTA-STS validator |
| `Services/ServiceContainer.cs` | DI composition root |
| `Models/Engagement.cs` | Engagement entity |
| `PROSCANNERCONT.Tests/PROSCANNERCONT.Tests.csproj` | Test project |
| `PROSCANNERCONT.Tests/*Tests.cs` | 6 test files, 28 tests |
| `.github/workflows/ci.yml` | CI pipeline |
| `CHANGES.md` | This document |

### Modified files

| Path | Changes |
|---|---|
| `PROSCANNERCONT.csproj` | Added Serilog (+ Sinks.File/Debug/Console), QuestPDF, DocumentFormat.OpenXml, System.DirectoryServices.Protocols, Microsoft.Extensions.DependencyInjection, Microsoft.Extensions.Hosting |
| `PROSCANNERCONT.sln` | Registered the test project |
| `App.xaml` | New brushes, hardcoded `White` → `OnAccentBrush`, severity palette |
| `App.xaml.cs` | Serilog init, global exception handlers, DI build, Npcap probe, ThreatIntel refresh start, AppLogger shutdown |
| `MainWindow.xaml.cs` | `ApiKey` / `AnthropicKey` → `SecretsManager` properties |
| `Managers/ThemeManager.cs` | Derived contrast brushes, severity palette, custom-theme parity |
| `Models/IDSAlert.cs` | MITRE + JA4 + ThreatIntel fields |
| `Models/IDSRule.cs` | MitreTechniqueId + MitreTactic |
| `Security/NVDChecker.cs` | NVD key + OpenAI key via SecretsManager |
| `Services/LicenseService.cs` | HMAC secret via SecretsManager |
| `Services/IDSManager.cs` | MITRE mapping helper, JA4 invocation, ThreatIntel enrichment, DoH detection, Kerberos detection, Ja4Fingerprinter class |
| `Services/ReportGenerator.cs` | Theme-aware HTML head, brand properties |
| `Views/SettingsPage.xaml.cs` | DPAPI save / load with legacy-plaintext migration |
| 12 view XAMLs | Hardcoded colours → dynamic brushes (see Theming table above) |

---

## Build & run

```powershell
# Build
dotnet build PROSCANNERCONT.sln -c Release

# Run tests
dotnet test PROSCANNERCONT.Tests -c Release
# → Passed!  - Failed: 0, Passed: 28, Skipped: 0, Total: 28

# Launch elevated (required for raw sockets + IDS)
Start-Process `
    "PROSCANNERCONT\bin\Release\net8.0-windows\PROSCANNERCONT.exe" `
    -Verb RunAs
```

Logs land in `%APPDATA%\PrivaCore\logs\privacore-YYYYMMDD.log`.

---

## What was deliberately skipped

- **Honeypot subsystem** — every file under `Views\HoneypotDashboardPage.*`, `Views\Vmterminalwindow.*`, `Views\Vmsettingswindow.*`, `Views\Sshconfigwindow.*`, `Views\OSSelectionWindow.*`, plus `Services\HyperVManager.cs`, `Services\SSHConnectionManager.cs`, and `Models\Honeypot*`.
- **Full MVVM migration of existing pages.**  The DI container is in place, and `ViewModels/HoneypotDashboardViewModel.cs` is the lone existing ViewModel; migrating 22 code-behind pages is a separate multi-day refactor.  New code in this rework uses DI; legacy pages keep their existing patterns.
- **Gradient stop colour theming.**  `LinearGradientBrush.GradientStop.Color` requires a `Color`, not a `Brush`, so it can't directly bind a `DynamicResource SolidColorBrush`.  The handful of gradient stops in `DashboardPage.xaml` and `NetworkTopologyPage.xaml` remain literal — they're decorative.
- **Code-signing**: Authenticode certificate procurement is a manual cert-authority step outside the scope of code changes.  CI pipeline is ready to sign once a cert exists.

---

*Generated as part of the rework session.  See git log for the per-commit
record of individual edits.*
