# PrivaCore — Changelog (checkpoint log)

> Per-feature history, newest first. Moved out of CLAUDE.md to keep that file the lean always-read core.
> CLAUDE.md §10 has the current-state summary; §14.1 has the live feature matrix.

## SIEM → full ELK completeness (workstream §14, 2026-06-20 onward)

### 2026-06-22 — detection extensions (roadmap from response.txt, item 3)
- ✅ **F5 email notification channel** — `SiemEmail` (SMTP) alongside the existing webhook connector:
  per-rule `EmailTo`; global `SiemEmailSettings` (host/port/SSL/from/credentials, persisted) configured on the
  Sources & Agents tab; the rule engine emails fired alerts when a rule has recipients and SMTP is configured.
  Message-building is pure/testable; sending is fire-and-forget and never throws. (+3 tests, 227 total)
- ✅ **Rule preview / backtest** — `SiemRuleEngine.Preview(rule, lookbackMinutes)` runs a rule against the
  events already in the store and returns the hits it *would* raise, with no cooldown / alert / store /
  webhook side-effects (via a `_previewSink` that diverts `Fire`; message-building factored into a shared
  `BuildAlertMessage`; `EvaluateRule` gained a window override). "Preview (24h)" button in the rule dialog
  shows would-fire results before you enable a rule — the best analyst-tuning / demo beat. (+2 tests, 224 total)

### 2026-06-22 — investigation pages (roadmap from response.txt)
- ✅ **E13 / G3 geo threat map** — a source-geography threat map on the Network page (roadmap item 2, the
  marquee visual). `SiemGeoMap` (dependency-free, no map tiles): ISO2 country centroids + an equirectangular
  projection; the Network page plots the top source countries (`source.geo.country_iso_code`) as bubbles sized
  by event count and coloured by intensity, with an equirectangular graticule, country labels, tooltips, and
  click-to-filter into Discover. Redraws on resize + with the Network tab refresh. Smoke-tested (collector
  launches clean). (+3 tests, 222 total)
- ✅ **G1 Security Overview landing** — new dedicated **Security** tab, now the first/landing tab: SOC-posture
  KPI strip (events / critical / high / open alerts / mean host risk / events-per-sec), events-by-severity donut,
  top alerts by rule, MITRE tactics, highest-risk hosts & users (click → entity profile), top source IPs, and a
  recent high/critical events grid. Composition over existing aggregations + the rule engine. To keep navigation
  order-independent after inserting a first tab, the brittle `Tabs.SelectedIndex` literals were converted to
  reference-based nav (`_searchTab`/`_sourcesTab`/`_pipelineTab`/`_overviewTab`/`_securityTab`). Smoke-tested
  (standalone collector launches clean).
- ✅ **G2 / G4 dedicated host & user profile pages** — double-clicking an entity in the Entities tab now opens
  a composed profile (risk + KPI strip; severity / top categories / top event types; related entities — top
  users on a host or top hosts for a user; top source IPs; alerts involving the entity; recent-events grid)
  with Back + "Investigate in Discover". Host↔user profiles pivot into each other. Pure composition over
  existing aggregations (`SiemEntityRisk`, `TopByField`, `CountBySeverity`) — no new engine. Per the
  response.txt roadmap (item 1: convert scattered tabs into an investigation narrative).

### 2026-06-22 — ingest, viz, detection, pipeline & query depth (session)
- ✅ **B11 explicit field mappings** — `SiemFieldMappingStore` lets a user pin a field to a specific
  `SiemFieldType` (keyword/text/number/ip/date/boolean/geo), persisted to %APPDATA% and wired via a new
  `SiemFieldTypes.Override` hook so the pinned type wins over inference everywhere (field icons,
  Visualize, value handling). Field-mappings manager card on the Index tab. (+3 tests, 219 total)
- ✅ **A4 collector-side file tailing** — `SiemFileTail` (Filebeat-style): offset-tracked incremental
  reads that emit only whole lines, hold a partial trailing line until its newline, and reset on
  truncation/rotation (file shorter than the offset). A poll-timer manager in `SiemIngestion`
  (`AddTailedFile`/`RemoveTailedFile`/`TailedFiles`) ingests new lines as `source=file:<name>` events
  through the ingest queue; "Tail file…" picker + removable file chips on the Sources tab. (+5 tests, 216 total)
- ✅ **D16 auto-refresh interval control** — a ⟳ menu in the top bar (Off / 1s / 5s / 10s / 30s / 1m / 5m)
  drives the dashboard's refresh timer (previously hard-wired to 1s); "Off" pauses live updates for
  investigation, the rest set the interval and refresh immediately. Manual updated.
- ✅ **A11 ingest back-pressure** — `SiemIngestQueue`: a bounded queue with a single background drain
  now fronts every collector-side receiver (syslog UDP/TCP, HTTP, agent ingest, WinEventLog, generator).
  Receivers `Enqueue` instead of writing the store directly; bursts buffer and over-capacity events are
  dropped + counted (depth / peak / processed / dropped) rather than blocking the network thread or
  exhausting memory. Internal alert events still write the store directly. Auto-starts on first enqueue
  (opt-out for tests); new "INGEST QUEUE" KPI tile with a depth/peak/dropped tooltip. (+4 tests, 211 total)
- ✅ **E10 chart types — heatmap / gauge / treemap** — three new `SiemChart` types in the Lens-style
  viz builder: **heatmap** (top field values × time buckets, intensity = count; new
  `ISiemStore.HeatmapByField` on both the in-memory and ES stores), **gauge** (single metric on a
  speedometer arc vs an auto-scaled 1/2/2.5/5×10ᵏ "nice" max), **treemap** (squarified layout via the
  pure, tested `SiemTreemap` helper, sized by count, click-to-filter). Viz dialog field/agg/top-N
  visibility updated; tiles persist like any other. (+4 tests, 207 total)
- 🟡→ **F7 EQL depth** — Sequence rules gain **`maxspan`** (`SiemRule.MaxSpanMinutes`: step-B must occur
  within N minutes of the first step-A) and **multi-field `by`** (comma-separated composite GroupBy,
  e.g. `source.ip,user.name`, all parts required) via a shared `GroupValue` helper now used by
  GroupThreshold/NewTerms/Anomaly/Sequence alike. Rule dialog gains the Max-span field + composite hint.
  (+2 tests, 203 total)
- ✅ **B12 runtime / scripted fields** — `SiemRuntimeField` (name + `{field.name}` template) computed at
  read time through new `SiemEvent.RuntimeFieldResolver`/`RuntimeFieldNames` static hooks, so a runtime
  field is immediately queryable in KQL and selectable as a Discover column with no re-indexing. Real
  fields shadow same-named runtime fields. `SiemRuntimeFieldStore` (persisted, cycle-safe via a
  [ThreadStatic] re-entrancy guard) registers the hooks; manager UI on the Index tab. (+5 tests, 201 total)
- ✅ **F8 dedicated indicator-match rule** — new `SiemRuleType.IndicatorMatch`: events in the window
  (optionally pre-filtered by Query) whose observable fields (source/dest IP, user, file hash,
  url.domain, dns.question.name, host — or an explicit GroupBy field) hit a managed IOC raise one
  alert per matched indicator value (≥Threshold hits), tagged `threat.matched`/`threat.indicator`.
  Indicator source is `SiemRuleEngine.IndicatorSource` (defaults to `SiemIndicatorStore`, overridable
  for tests). Rule dialog shows the optional field row + manual updated. (+3 tests, 196 total)
- ✅ **C9 full conditional/branching routing** — new `SiemMatchField.Query`: any processor's match
  clause can be a full KQL expression (AND/OR/NOT, ranges, wildcards, CIDR), turning
  `Drop`/`KeepOnly`/`CallPipeline` into real conditional branches/routes. Wired via a
  `SiemProcessor.QueryMatcherFactory` static seam (registered in `SiemPipelineSetStore.Load`) so the
  Models folder keeps no compile-time dependency on the query engine — important because non-SIEM
  hosts (the IDS app) glob `Models\*.cs` but don't link the SIEM services. Pipeline-stage dialog hint
  updated. (+5 tests, 193 total)
- ✅ **H9 external query API** — `SiemQueryApi` (Elasticsearch `_search`-style): pure/testable core
  that runs a KQL query over the active `ISiemStore` and returns JSON (`query`/`total`/`count`/`hits`,
  each hit an ECS `_source` via `SiemEsDocument`). Wired into the HTTP listener as
  `GET /api/search?q=<KQL>&size=<n>&minutes=<m>` (same port :9721, same opt-in ingest token).
  Lets SOAR/scripts pull data out. Sources-tab hint + manual entry + curl example. (+5 tests, 188 total)
- ✅ **A10/C5 Grok processor** — new `SiemProcessorType.Grok` + `SiemGrok` engine: expands
  Logstash-style `%{PATTERN:field}` / `%{PATTERN}` tokens into a .NET named-group regex over a
  source field (blank = message), built-in pattern library (IP/IPV4/IPV6/NUMBER/INT/WORD/USER/
  HOSTNAME/LOGLEVEL/QUOTEDSTRING/URIPATH/TIMESTAMP_ISO8601/… expanded recursively). Dotted ECS
  field names (`source.ip`) are mapped to safe synthetic groups; unknown/bad patterns degrade
  without throwing (ingestion never breaks). Wired into `SiemPipeline.Process` + the Pipeline-stage
  dialog (auto-listed, grok arg/source-field labels). Linked into the standalone SIEM app. (+9 tests,
  183 total)
- ✅ **D4 CIDR / subnet match in KQL** — `source.ip:10.0.0.0/24` (IPv4 + IPv6) in `SiemQuery`
  (`TryParseCidr`/`IpInCidr`, exact-prefix, family-checked; `/32` is an exact host match, not the
  substring fallback). Only valid CIDRs are treated as such, so `url.path:/admin/login` still falls
  back to contains. Mirrored in the ES translator (`SiemEsQueryTranslator` → `term` on the `ip`
  field) so the Elasticsearch path stays in parity. Benefits Discover **and** detection rules (both
  use `SiemQuery`). (+7 tests, 174 total)

### 2026-06-21 — ELK completeness push (session)
- ✅ **F12 risk scoring + alert suppression** — `SiemRule.RiskScore`/`SuppressMinutes`,
  `SiemAlert.RiskScore` + band colour; engine computes risk (base + overage), per-group suppression;
  Alerts grid Risk column; rule dialog fields. (+4 tests)
- ✅ **F14 alert triage** — `SiemAlert.Assignee`, "Assign to me", status filter (incl. "Assigned to me").
- ✅ **F9 ML anomaly rules** — `SiemRuleType.Anomaly`: rolling mean+σ baseline over prior windows,
  per-entity optional, fires on rate spikes; dialog Baseline-windows field. (+2 tests)
- ✅ **C8 lookup-table Enrich processor** — `key => field=value;…` keyed on any field (asset/user/DNS). (+1 test)
- ✅ **H6 audit log** — `SiemAudit` append-only NDJSON trail (rule edits, triage, retention, deletes,
  config/integration import-export); Index-tab viewer + CSV export. (+2 tests)
- ✅ **D18/D22/B11 Discover polish** — `SiemFieldTypes` ES-style type inference → field-type icons +
  type label + per-field "Visualize" shortcut; search history menu. (+10 tests)
- ✅ **A8 integrations catalog** — `SiemIntegrations` prebuilt parser bundles (sshd/nginx/apache/
  Windows Security/firewall/GeoIP); "Add integration" appends pipeline stages. (+3 tests)
- ✅ **B10 snapshot/restore** — `SiemPersistence.SnapshotTo`/`RestoreFrom` + Index-tab buttons. (+1 test)
- ✅ **E18 export/share dashboard** — Overview "Share" exports/imports a dashboard as JSON.
- ✅ **§7.1 HTTP ingest opt-in auth token** — `SiemHttpIngest.TokenAccepted` (X-Ingest-Token / Bearer,
  constant-time); default blank = unchanged posture; Sources-tab token input. (+4 tests)
- Build clean across all 6 projects; **146 tests pass** (was 119).

#### Follow-on achievable batch (same session)
- ✅ **D20 surrounding-documents** — `SiemStore.Surrounding` + "Context" toggle in the expanded
  document (N events before/after on the same host, anchor highlighted, click-to-select). (+1 test)
- ✅ **G8 process-tree / session view** — Entities → Processes tab: host → parent → child process
  TreeView from process events; click to investigate in Discover.
- ✅ **G10 threat-intel indicator management** — `SiemIndicatorStore` (persisted IOC list) + a new
  **Threat Intel** tab (add/remove indicators, recent matches, enable-matching); wired into
  IndicatorMatch via `SiemProcessor.GlobalIndicatorSource`. (+2 tests)
- ✅ **C11 multiple named pipelines + routing** — `SiemPipelineSet`/`SiemPipelineSetStore` +
  `CallPipeline` routing processor (recursion-guarded); Pipeline-tab selector to create/switch/
  delete named pipelines; legacy single-pipeline migration. (+2 tests)
- Build clean across all 6 projects; **151 tests pass**.

- ✅ **In-depth in-app manual** — replaced the one-line tab blurbs with a full **expandable user
  manual** (13 sections: deploy/agents, time range & search bar, Overview & dashboards, Discover +
  KQL, sources & ingestion w/ curl example, Fleet, Pipeline w/ every processor + regex example,
  detection rules & alerts, cases & timeline, entities & network, index/retention/saved-objects,
  tips & troubleshooting). Rendered as a themed accordion (headings / bullets / code / tips) shown in
  **both** the Setup Guide tab **and** the startup welcome overlay (scrollable, animated). `GuideSections()`
  is the single source; `BuildManualSection`/`ManualBlock` render it. Build clean, 119 tests.
- ✅ **Animated welcome tour + richer Setup Guide** — on startup the SIEM shows an animated
  **welcome overlay** (dimmed backdrop; flow strip Agents→Collector→Pipeline→Workspace with looping
  chevrons; staggered "What's inside" list explaining every tab; **Don't show again** checkbox →
  `Services/Siem/SiemWelcome.cs`; "Open Setup Guide" / "Get started"). Setup Guide gained a **Using
  the workspace** section (per-tab how-to cards), a **search cheat-sheet**, and a "replay welcome
  tour" button. Shared `WorkspaceParts()` feeds both. Build clean; verified running (overlay shows on launch).
- ✅ **A7 Fleet agent management — COMPLETE** (pt2 agent + pt3 UI). Agent sends `agent.enroll`
  (name/host/OS/version) after login, `agent.checkin` every 20s, and applies a pushed `agent.policy`
  **live** (restarts its sources). New **Managed agents (Fleet)** card on the Sources & Agents tab:
  inventory grid (status dot, name, status, OS, version, events, last check-in) + **Push policy**
  (`SiemAgentPolicyDialog`: heartbeat / interval / demo generator / tail files). **Verified
  end-to-end**: ran agent → enrolled & showed **FLEETTEST · ONLINE · Windows 10.0.19045**. (pt1 was
  the collector registry/protocol.)
- 🚧 **A7 Fleet agent management — pt1 (collector)** — shared `PrivaCore.ModuleSdk/AgentProtocol.cs`
  (`agent.enroll`/`agent.checkin` commands, `agent.policy` event; `AgentPolicy` + `AgentEnrollInfo`
  DTOs); `ModuleHost.SendTo` (per-connection push). New `Services/Siem/SiemAgentRegistry.cs` (Fleet
  inventory: enroll, check-in, online/offline reconcile on `ClientsChanged`, push-policy). Wired into
  `SiemModuleBridge.AttachHost`. **+6 tests (119 total)**, build clean. (Next: agent sends enroll/
  check-in + applies pushed policy; then the Fleet UI.)
- ✅ **C12 Pipeline dry-run** — **Test pipeline** button on the Pipeline tab runs the newest event
  through the pipeline on a `SiemEvent.Clone()` (original untouched) and shows the before/after in the
  flow card (dropped vs kept + severity/category/source/field-count changes). **+1 test (114 total)**,
  build clean, app runs.
- ✅ **F11 Rule exceptions / allowlists** — every detection rule gains an optional **Exception**
  (`ExcludeQuery`); events matching it are filtered out before evaluation across all rule types
  (threshold / group / new-terms / sequence). Engine `NotExcluded` predicate; **Exception** field in
  the rule dialog. **+1 test (113 total)**, build clean.
- ✅ **F7 Sequence (EQL-style) correlation rules** — new `SiemRuleType.Sequence`: fires when
  ≥Threshold of step-A (`Query`) are followed in time by a step-B (`SecondQuery`) event from the same
  `GroupBy` value within the window (e.g. *brute-force failures then a success from one source.ip*).
  Engine `EvaluateSequence` groups the window's events and checks ordered A→B; rule dialog gains a
  **THEN** step-B field; a ready-made sequence rule added to the library. **+2 tests (112 total)**,
  build clean, app runs.
- ✅ **C6 Real GeoIP enrichment** — new `GeoEnrich` pipeline processor adds ECS geo fields
  (`{prefix}.geo.country_name/country_iso_code`, `{prefix}.as.organization/isp`) from an IP field
  (default `source.ip`) using the existing **`GeoIpService`** (real ip-api.com lookups, cached +
  rate-limited). Enriches synchronously from cache and **warms the cache async** so it never blocks
  the ingest path. Added `TryGetCached`/`Prefetch`/`SeedCacheForTests` to `GeoIpService`; linked into
  the standalone SIEM. **+2 tests (110 total)**, build clean; verified the ip-api source resolves live
  (8.8.8.8 → US / AS15169 Google LLC).
- ✅ **C13 Date-parse processor** — `ParseTimestamp` pipeline stage sets the event `@timestamp` from a
  field (blank = message), with an optional .NET date format (else `DateTime.TryParse`). Wired into
  `PipelineStageDialog`. **+1 test (108 total)**, build clean.
- ✅ **D14 Histogram drag-to-zoom** — the Discover histogram (`BuildBrushHistogram`) now renders bars
  in a full-width uniform grid with a transparent brushing overlay: drag to select a span → maps the
  pixel fractions onto the current range and applies an **absolute** `SiemRange` (reuses the tested
  zoom path). Build clean, app runs.
- ✅ **D15 Absolute time ranges** — replaced the bare `TimeSpan?` window with a `SiemRange` type
  (rolling / **absolute from-to** / all-time; live `Contains`, implicit `TimeSpan`→rolling so existing
  call sites + the rule engine keep working). Refactored all `SiemStore` windowed methods + entity
  risk to `SiemRange?`; the range menu (⋯) gained **Absolute range (from / to)…**. This also lays the
  groundwork for histogram drag-zoom. **+6 tests (107 total)**, build clean, smoke-tested across tabs.
- ✅ **F5 Webhook alert actions** — a detection rule can carry an optional **Webhook URL**; on fire,
  `Services/Siem/SiemWebhook.cs` POSTs a Slack/Teams/generic JSON payload (text + structured rule/
  severity/message/count/MITRE/timestamp) fire-and-forget. Field added to `SiemRuleDialog`.
  **+1 test (101 total)**, build clean.
- ✅ **H5 Saved objects (export / import)** — `Services/Siem/SiemSavedObjects.cs` + `SiemBundle`
  bundle the whole config (detection rules, saved searches, dashboards, pipeline, index settings)
  into one JSON file. **Export config / Import config** buttons on the Index tab (Save/Open dialogs);
  import replaces the live stores and reloads rules + pipeline in place. **+2 tests (100 total)**, build clean.
- ✅ **C7 Threat-intel indicator matching** — new `IndicatorMatch` pipeline processor: checks a field
  (or, blank, the common IOC fields source.ip/destination.ip/user.name/file.hash.sha256/url.domain/
  dns.question.name) against a known-bad indicator list (`Arg`, comma/space separated, cached set);
  on a hit it tags `threat.matched=true` + `threat.indicator` and **escalates severity to High**.
  Compose with a Threshold rule on `threat.matched:true` for indicator-match alerting (F8). Wired into
  `PipelineStageDialog`. **+2 tests (98 total)**, build clean.
- ✅ **A3 Syslog over TCP** — `SiemIngestion` adds a newline-delimited TCP syslog listener
  (`TcpListener` :5514, per-connection reader) reusing the tested `SiemSyslog` parser; new
  **Syslog TCP** chip on the Sources tab. Build clean, **verified end-to-end** (sent an RFC5424
  line over TCP → appeared in Discover as host `tcpbox`, `event.action: syslog (rfc5424)`).
- ✅ **A2/A13 Ingestion breadth** — **RFC5424** structured-syslog parsing (host/app/message,
  STRUCTURED-DATA skip) refactored into testable `Services/Siem/SiemSyslog.cs`; new **HTTP JSON
  ingest endpoint** — `SiemIngestion` runs an `HttpListener` (port 9721, all-interfaces with
  localhost fallback) accepting `POST` of a JSON event or array, parsed by
  `Services/Siem/SiemHttpIngest.cs` (known keys → columns, rest → fields, numeric/string severity).
  New **HTTP ingest** chip on the Sources tab. **+6 tests (96 total)**, build clean, **verified
  end-to-end** (POST returned `{"ingested":1}` and the event entered the store).
- ✅ **G3 Network view** (investigation workflow pt4) — new **Network tab**: KPI line (unique source/
  destination IPs, total bytes transferred) + tiles for **top source IPs / destination IPs /
  destination ports / protocols (donut) / top talkers / top countries**, all built on the existing
  `TopByField`/`Metric` aggregations and click-to-filter into Discover. Build clean, verified running
  with live data. **Investigation workflow (Entities + Network + Cases + Timeline + risk) is now complete.**
- ✅ **G5 Timeline** (investigation workflow pt3) — investigation workspace. `Models/SiemTimeline.cs`
  + `Services/Siem/SiemTimelineStore.cs` (persists `siem_timeline.json`). New **Timeline tab**: a
  chronological rail (severity dots + connectors, oldest→newest) of pinned events, each with an
  editable **note**, plus Clear. **Pin** action added to the expanded Discover document. Also fixed
  the Case/Timeline test stores to **suppress disk writes in test mode** (no more `%APPDATA%`
  pollution) and cleaned the stray test files. **+3 tests (90 total)**, build clean, verified running.
- ✅ **G6 Cases** (investigation workflow pt2) — SOC case management. `Models/SiemCase.cs`
  (title/description/status Open→In progress→Closed/severity/items/comments) +
  `Services/Siem/SiemCaseStore.cs` (persists `siem_cases.json`). New **Cases tab**: case list +
  detail pane (clickable status pills, severity, attached-evidence list, threaded comments with an
  add box), New/Edit via `Views/SiemCaseDialog.cs`. **Alerts → "Add to case"** toolbar action
  attaches the selected alert to a new or existing case (with a confirmation toast). **+3 tests
  (87 total)**, build clean, verified running (Briefcase icon valid; tab renders).
- ✅ **G7/G2/G4 Entity analytics + Entities view** (investigation workflow pt1) — new
  `Services/Siem/SiemEntityRisk.cs` computes **severity-weighted risk scores** (0–100) per host and
  per user (Critical=30/High=12/Medium=4/Low=1, capped; alert pseudo-events excluded). New **Entities
  tab** with **Hosts / Users** sub-tabs: themed grids with a risk dot, **risk score + colored bar**,
  events/high/critical/last-seen, and **double-click → investigate in Discover** (auto-filters by
  host/user). **+5 tests (84 total)**, build clean, verified running (host risk ranks DB01 highest).
- ✅ **F10 New-terms detection rules** — third rule type `NewTerms`: fires when a `GroupBy` value
  appears in the recent window that was never seen earlier in retained history (e.g. a brand-new
  `source.ip` or `user.name`). Engine splits the matched set at the window cutoff and alerts on
  values absent from the historical set; rule dialog shows the field for NewTerms. **+1 test (79 total)**, build clean.
- ✅ **C10/C14 Pipeline depth pt2** — two more processors: **Lowercase** (normalise a field, blank =
  message) and **Dedupe** (drop repeats of a fingerprint field within a window, `Arg` = seconds;
  bounded in-memory fingerprint map). Wired into `PipelineStageDialog`. **+2 tests (78 total)**, build clean.
- ✅ **D19/D15 Discover polish** — **CSV export** of the matching result set (Discover toolbar →
  `SaveFileDialog`, honours the selected columns, RFC-4180 quoting, UTF-8 BOM) and an **extended
  time-range menu** (⋯ button → 30m/6h/12h/3d/7d/30d presets + "Custom (minutes)…" prompt; shared
  `ApplyRange` helper). Column reorder/resize already work on the Discover grid. Build clean.
  (Remaining Discover nice-to-haves: histogram drag-to-zoom D14, absolute from/to range, column
  order/width persistence.)
- ✅ **C5/C10 Pipeline depth** — three new Logstash-style processors: **ExtractRegex** (grok-like:
  a named-group regex over a source field lifts groups into new fields, bad patterns swallowed),
  **RenameField**, **RemoveField**. `SiemProcessor` gained a `Field` property; `PipelineStageDialog`
  shows a source-field input + per-type arg labels. **+3 tests (76 total)**, build clean.
- ✅ **B5–B9 Persistence + retention + index management** — new **Index** tab (ILM): live stats
  (documents / capacity %, ~size, ingested vs dropped, time span, retention summary), per-source
  document breakdown, **retention controls** (max events, max age minutes, persist-to-disk toggle →
  `SiemIndexSettings`), and a red **Danger zone** (delete-by-current-query, clear index).
  `SiemStore` gained `MaxAge`/`PurgeExpired`, `DeleteMatching` (delete-by-query), `LoadSnapshot`,
  `ApproxBytes`, `Oldest`/`Newest`. **`SiemPersistence`** snapshots the index to gzip NDJSON
  (periodic + on exit) and reloads on startup when enabled. **+5 tests (73 total)**, build clean,
  verified running (Index tab themed; controls + danger zone centered).
- ✅ **E12 Multiple saved dashboards** — `Services/Siem/SiemDashboardStore.cs` (`SiemDashboardDoc` =
  many named `SiemDashboard`s + current; persists `siem_dashboards.json`, migrates the legacy
  `siem_tiles.json` into a "Default" dashboard on first load). Overview gets a **dashboard switcher**
  (▦ name ▾) with switch / **New** / **Rename** / **Delete** (reuses `TextPromptDialog`); each
  dashboard keeps its own tiles, saved on every change. +1 test (68 total); build clean; verified
  running (switcher + migrated Default render).
- ✅ **E8/E9/E10 Visualize (Lens-style config-driven tiles)** — new `SiemWidgetType.Custom` carries
  `Field + Agg + Chart + TopN + Title`. **＋ Visualize** builder (`Views/SiemVizDialog.cs`) lets you
  pick a field + aggregation (**count / unique-count / sum / avg / min / max / top-N**) + chart
  (**metric / bar / donut / table / line**) → drops a config-driven tile on Overview; tiles are
  editable (pencil) + removable and persist via `SiemLayout`. New `SiemStore.Metric()` +
  `TopByField()`. Verified running: metric/bar/donut/table custom tiles render with live data
  alongside built-ins. **+5 tests (67 total)**, build clean. (E12 multiple dashboards = next.)
- ✅ **D3/D4 Query language depth** — `SiemQuery` rewritten as a forgiving **recursive-descent
  parser**: `AND`/`OR`/`NOT` + `-`/`!` negation, **parentheses grouping**, implicit AND between
  adjacent terms, **wildcards** (`*`/`?`), **numeric range on any field** (`network.bytes>=1000`),
  severity range, quoted phrases as field values (`message:"…"`), and the KQL `field:>=value` form.
  Malformed input never throws (falls back to free-text). Used by both Discover and the rule engine,
  so detection rules inherit the richer language. Filter pills skip boolean/paren tokens; search hint
  updated. **+12 tests (62 total)**, build clean.
- ✅ **F6 + F13 Prebuilt rule library + MITRE ATT&CK coverage** — `SiemRuleLibrary` expanded to 17
  ready-made detections spanning 11 ATT&CK tactics (recon → impact), each tagged technique + tactic;
  "Add from library" menu (per-rule or all). Rules/alerts now carry `MitreTactic`
  (`Models/SiemMitre.cs` = the 14 enterprise tactics; rule dialog has a tactic picker). New
  **ATT&CK coverage** inner tab on Alerts: a horizontal matrix of tactic columns (covered = accent
  header + technique chips; uncovered = dimmed), chips outline + badge by active-alert count/severity,
  summary "X/14 tactics covered". **+3 tests (50 total)**, build clean, verified running (live alert
  fired with T1059/Critical, badge shows, coverage tab present).
- ✅ **F1–F5 Detection & Alerting + Alerts tab** — the core SIEM correlation layer. New
  `SiemRuleEngine` (singleton timer, 15s) evaluates each enabled `SiemRule` over `SiemStore`:
  **Threshold** (total matches ≥ N in window) and **GroupThreshold** (per distinct field value,
  e.g. ≥10 failed logons from one `source.ip`). Trips raise a `SiemAlert` (with per-rule/group
  **cooldown** so it doesn't re-fire each tick) + an alert `SiemEvent` (so it shows in Discover),
  and a sliding **in-app toast**. New **Alerts tab** (inner tabs *Active alerts* / *Rules*):
  themed alerts grid (severity dot+badge, MITRE, status badge, Acknowledge/Close/Clear-closed),
  rules manager (cards w/ enable toggle, edit, delete, severity bar, MITRE chip), header
  **count badge**. Rule editor `Views/SiemRuleDialog.cs` (query+threshold+window+group+severity+MITRE,
  centered buttons). Starter `Models/SiemRuleLibrary.cs` ("Add from library"). Models
  `SiemRule`/`SiemAlert`, store `SiemRuleStore`. **+7 tests (48 total)**, build clean, verified
  running (screenshotted Alerts + Discover; buttons centered & themed).
- ✅ **D17 Saved searches** — Discover toolbar gets **Save search** + **Open** (icon+label ghost
  buttons, centered content). Save captures the query string, selected columns and time range;
  Open restores them and shows a "★ name" chip. Delete via the Open menu. New `Models/SiemSavedSearch.cs`
  + `Services/Siem/SiemSavedSearchStore.cs` (persists `siem_saved_searches.json` in `%APPDATA%\PrivaCore`),
  reusable `Views/TextPromptDialog.cs` (themed name prompt). Linked into `PrivaCore.SIEM`. Build clean, 41 tests.


---

## Earlier — SIEM v1 + IDS polish (session 2026-06-19/20)
> Newest first. Each item is committed.


> Newest first. Each item is committed.

- ✅ **SIEM Discover = full ELK/Kibana clone** (the "events don't show enough info" fix). Built
  part-by-part, each verified by running the app:
  * **Rich ECS documents** — every event now carries many dotted fields (`user.name`, `source.ip`,
    `destination.*`, `event.action/outcome`, `http.*`, `network.bytes`, `process.*`,
    `threat.technique.*`, `source.geo.*`, `file.hash.*`, `winlog.*`, `log.syslog.*`).
    `SiemEvent.AllFields()/Get()/Summary()/ToJson()`.
  * **Discover Search tab** — left FIELDS sidebar (every field + top-values popover with % bars +
    filter for/out), Time + Document columns or your chosen field columns, **click a row to expand
    the full document** (every field with filter-for / filter-out / toggle-column actions + a
    Table | JSON toggle), a results histogram, and **filter pills** (include/exclude chips,
    removable, click-to-toggle). `SiemStore.FieldNames()/TopValues()`; `SiemQuery` gained negation
    (`-field:value`) + ECS aliases.
- ✅ **Live theme sync (controller → module)** — the console pushes its active colour theme to
  every module it controls; the module applies it **live** and shows a **“Theme: X”** indicator in
  its status strip. `ThemeManager` now tracks `CurrentThemeName`, raises `ThemeChanged`, and can
  capture/replay the full palette. `Services/ModuleThemeSync.cs` (linked into both standalone apps)
  does the send (console) / apply (module). Standalone apps also honour the local saved theme on
  startup. Verified running: SIEM shows “Theme: Crimson Void”.
- ✅ **SIEM tables reworked to IDS quality** (the “tables feel empty/dead” fix): severity **dot +
  colored badge** columns, Consolas data, taller rows, themed header bar, solid `SecondaryBackground`
  panels (no more transparent/dead look), live status dot + LIVE/IDLE + colored High/Critical on the
  machines table, and friendly **empty-states** everywhere. Verified running — Search/Machines now
  look full and alive.
- ✅ **Verified by running the app** (`privacore-siem.exe`) and screenshotting Overview / Search /
  Sources / Setup Guide. Caught + fixed a launch-crash (invalid FontAwesome icon names —
  `ServerSolid`→`Server`, `Diagram_Project`→`DiagramProject`, etc.; all names now checked against
  the assembly). **41 tests pass, 6 projects build clean.**


- ✅ **IDS standalone window chrome fixed** — added themed min/max/close caption-button
  handlers to `PrivaCore.IDS/Shell.xaml.cs`; config overlay no longer covers the title bar.
- ✅ **SIEM dashboard fully reworked** (`Views/SiemDashboardPage.xaml(.cs)`): the janky
  free-drag canvas is gone. New **tabbed** layout, all themed:
  - **Overview** — KPI strip (Total / In-window / Events-sec / Critical / High / Machines /
    Dropped) + a **responsive flowing tile grid** (histogram, severity donut, top hosts /
    categories / event-types, high-sev watchlist). Add/remove tiles; no overlaps, snaps clean.
  - **Search** — Discover-style results `DataGrid` (themed `DataGridStyle`) + an event **detail
    pane** (fields, raw). Live-tails, drill-down by clicking values.
  - **Sources & Agents** — local source toggles (Win Event Log / syslog / generator) **plus a
    reporting-machines roll-up table** (host, last source, events, high, critical, last-seen) →
    this is the multi-machine view.
  - **Pipeline** — composable **Logstash-style** stages editor with a data-flow diagram.
- ✅ **SIEM engine — pipeline** (`Models/SiemPipeline.cs`, `Services/Siem/SiemPipelineStore.cs`):
  ordered processors (Drop / KeepOnly / SetSeverity / SetCategory / AddTag / RenameSource) with a
  field+substring match. Applied in `SiemStore.Add(applyPipeline:true)`; persisted; UI editor
  (`Views/PipelineStageDialog.cs`). Console relays use `applyPipeline:false` (no double-process).
- ✅ **SIEM engine — multi-machine intake**: `SiemModuleBridge.AttachHost` now handles the
  agent `siem.ingest` command (deserialise → stamp origin → `Add`). `SiemStore.SourceStats()`
  rolls events up per reporting machine for the Sources tab.
- ✅ **PrivaCore.Agent — cross-OS log shipper** (new project, portable **net8.0**, no WPF):
  reuses `PrivaCore.ModuleSdk`. Config (collector ip/port + creds + pairing + which logs);
  interactive first-run **or** CLI args (`--host --port --user --pass --pairing --name --tail --gen`);
  tails log files (only new lines, any OS), heartbeat, optional demo generator; auto-reconnect
  with backoff; ships events via the `siem.ingest` command. Deploy docs + scripts in
  `Modules/Agent/` (README, Run-Agent.cmd, run-agent.sh) and `Modules/SIEM/Allow-Firewall.cmd`.
- ✅ **Tests:** +7 SIEM tests (pipeline behaviours, per-machine roll-up, **full agent→collector
  wire round-trip**). **41 tests pass.** All **6 projects** build clean.
- ✅ **SIEM promoted** to an available module in the catalog (was mis-grouped under "coming soon").
- ✅ **Animated Setup Guide tab** (§11.4 done for SIEM): a real WPF-animated onboarding — flowing
  data-flow strip (agents → collector → pipeline → dashboards) + staggered fade/rise step cards,
  one-click "Start demo data", and a copy-ready agent command line.
- 📌 **Still open from §11 (next session):** generalise the tutorial to the whole module system;
  a couple of chart tiles could grow richer; optional per-tile size options. Core SIEM (engine +
  multi-machine + agent + pipeline + reworked GUI + onboarding) is all done, builds clean, 41 tests.

