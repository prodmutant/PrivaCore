# PrivaCore

**A modular security toolkit for Windows — formerly "ProScanner".**

> ⚠️ **For authorised security testing only.** Use PrivaCore against networks and systems you
> own or have explicit written permission to test. You are responsible for how you use it.

---

## A note from me (please read this first)

This project started life as **ProScanner** — a network/security scanning tool I was building.
Over time it grew well past "a scanner": it turned into a whole suite of security tools that
talk to each other, plus a module system so heavier pieces can run on other machines and be
controlled from one console. Because it became something much bigger than the original idea,
I renamed it to **PrivaCore**.

Here's the honest part. I did most of the work on this myself. I hoped for more support along
the way and it didn't really come, and for a while I kept the project close to my chest. But
sitting on it wasn't helping anyone — so instead of gatekeeping it, I decided to **let it out
as open source** for anyone who wants to use it, learn from it, fork it, or build on it.

A few things I want to be upfront about:

- **I'm not a professional programmer.** I'm someone who cares about security tooling and tried
  my best to build something real and useful. That means there are almost certainly bugs, rough
  edges, and things a seasoned engineer would do differently. If you find issues, that's expected
  — please be kind, and pull requests are genuinely welcome.
- **I'm not stopping.** I still plan to work on PrivaCore. The one change is that it'll probably
  be **slower and less than before** — this is a passion project, not a funded product, so
  progress will come when I have the time and energy.
- **The unfinished modules are still on the roadmap.** Several modules listed below are marked
  "planned / in progress." I fully intend to keep working toward them — though I'll be honest,
  I don't always know exactly *how* I'll get there yet. I'm figuring it out as I go, which is
  part of why open-sourcing it feels right: maybe someone reading this can help.

If any of this is useful to you, that already makes putting it out here worth it. Thanks for
taking a look.

---

## What PrivaCore actually is

PrivaCore is a **networking + cybersecurity suite** for Windows, built with .NET 8 WPF. The
guiding idea is:

- A **main app ("console")** acts as a SOC-style dashboard and control plane — it holds the
  everyday tools and gives you one place to see everything.
- **Heavier capabilities are modules.** A module can run as a **standalone app on another
  machine** (a sensor, a honeypot host, a log collector) and be **controlled remotely from the
  console** over the network — with pairing + challenge/response login so it isn't wide open.
- Everything shares a **common theme and data model**, so the pieces are meant to feel like one
  product rather than a bag of separate tools.

It's aimed at two kinds of people: **SOC analysts** (from L1 to senior) and **home-lab / learners**
who want a visual, all-in-one place to explore security tooling.

### The plan — then and now

**What the plan *was*:** cover everything a large enterprise SOC might want — scanning, IDS,
SIEM, honeypots, threat intel, EDR, cloud security, and more — all modularized so each piece
runs where it makes sense and reports back to one console. Eventually add proper auth/RBAC,
multi-tenancy, TLS on the wire, and a real database backend.

**What the plan *is now*:** the same vision, just realistic about pace. The foundation, the
module system, and the first real modules exist and work. I'll keep extending it toward that
enterprise-grade goal — but as a solo, part-time effort now shared openly, so others can use it
and (hopefully) contribute.

---

## What exists today

### Local tools (built into the console)

These live in the main app and are always available:

- **Dashboard** — SOC-style aggregation of module data into freely-positionable widgets.
- **Port Scanner** — TCP/UDP scanning, multiple scan modes, banner grabbing, service fingerprinting.
- **Network Discovery** — ARP + ICMP subnet sweep, OS fingerprinting, MAC vendor lookup.
- **Network Topology** — multi-phase discovery → router identification → hierarchy mapping.
- **Traffic Analysis** — live packet capture, protocol dissectors, conversation grouping, threat scoring.
- **Vulnerability Scanner** — port scan → NVD CVE lookup → CVSS scoring → export.
- **POC Explorer** — CVE-linked exploit search and proof-of-concept workflow helpers.
- **SSH Manager** — multi-host SSH client with in-app terminal and file browser.
- **Reports** — self-contained single-file HTML reports (no external/CDN dependencies).
- **Gallery & Achievements** — screenshots and a gamified progress tracker.

### Modules (the modular, remote-capable part)

These are the pieces built around the module system:

| Module | Status | What it is |
|---|---|---|
| **IDS** | ✅ Working | Full Network + Host IDS. Runs in the console **or** as a standalone sensor app on another machine, controlled live from the console (start/stop, rules, interface selection all flow both ways). |
| **SIEM** | ✅ Working | A central log collector with an ELK / Elastic-Security-style experience: ingest, a configurable Logstash-style pipeline, KQL-ish search/Discover, dashboards, detection rules + alerts, cases, timelines, and more. Runs standalone as a collector; the console connects to view it. |
| **Agent** | ✅ Working | A lightweight **cross-OS (Windows/Linux/macOS)** log-shipping agent you deploy on a monitored machine and point at the SIEM collector. Portable .NET console app, no UI. |
| **Honeypot** | ✅ Present | Hyper-V-based honeypot management + capture. |

### Modules that are planned / still being worked on

These appear in the "Add Module" catalog as placeholders. I intend to build them out into real
standalone modules the same way IDS and SIEM were done — I'm just not there yet, and I'll be
honest that I don't have every detail figured out:

- **EDR** (endpoint detection & response)
- **Cloud Security**
- **Threat Intel** feed
- **Email / Phishing Security**
- **DLP** (data loss prevention)
- **SOAR** (automation / playbooks)
- **Firewall Manager**
- **Compliance / GRC**
- **Asset Inventory**
- **Deception**

If one of these is your area, this is exactly the kind of thing a contributor could pick up.

---

## What you'll need

**To run it:**

- **Windows 10 / 11 (x64)**
- **.NET 8 runtime** (or the SDK, if building from source)
- **[Npcap](https://npcap.com/)** — required for Traffic Analysis and IDS packet capture. Install
  in **WinPcap compatibility mode**. Without it, the interface list is empty and capture won't start.
- **Administrator privileges** — needed for raw sockets (SYN scan, packet capture, IDS) and to
  auto-open the Windows firewall for remote modules.

**Optional, for specific features:**

- **Hyper-V** — for Honeypot VM management (enable via Windows Features).
- **An OpenAI or Anthropic API key** — enables the optional AI assistant (CVE service-name
  normalization + a security advisor chat). Entered in **Settings → Secrets** at runtime; no key
  ships in the source. Everything else works without it.
- **A second machine** — to actually try the modular part: run a standalone module (IDS/SIEM) or
  the agent on another box and connect to it from the console.

---

## Build & run

This is a multi-project .NET 8 solution.

```bash
# Get the source
git clone https://github.com/prodmutant/PrivaCore.git
cd PrivaCore

# Build everything
dotnet build PROSCANNERCONT.sln -c Debug

# Run the tests
dotnet test PROSCANNERCONT.Tests/PROSCANNERCONT.Tests.csproj -c Debug
```

Run the apps (Debug output paths):

```bash
# The console / main app
PROSCANNERCONT/bin/Debug/net8.0-windows/PROSCANNERCONT.exe

# Standalone IDS sensor
PrivaCore.IDS/bin/Debug/net8.0-windows/privacore-ids.exe

# Standalone SIEM collector (listens on port 9720)
PrivaCore.SIEM/bin/Debug/net8.0-windows/privacore-siem.exe

# Cross-OS agent (run on a monitored machine, point it at the collector)
PrivaCore.Agent/bin/Debug/net8.0/privacore-agent.exe \
    --host <collector-ip> --port 9720 --user admin --pass <pw> --pairing <code> --gen
```

> **Tip:** run the console **as Administrator**. Install Npcap before opening Traffic Analysis or
> IDS. For cross-machine modules, the module host tries to open the inbound firewall for you
> (needs admin), and shows its reachable LAN IPs.

---

## Project layout

```
PROSCANNERCONT         The console / main WPF app (dashboard, local tools, module connect flow).
PrivaCore.ModuleSdk    Shared wire protocol used by the console and every module (framed JSON over
                       TCP, pairing + challenge/response auth, host/client, LAN reach helpers).
PrivaCore.IDS          Standalone IDS sensor app (reuses the real IDS engine + UI).
PrivaCore.SIEM         Standalone SIEM collector app (reuses the real SIEM engine + dashboard).
PrivaCore.Agent        Cross-OS log-shipping agent (portable console app, no UI).
PrivaCore.Honeypot     Honeypot module.
PROSCANNERCONT.Tests   xUnit + FluentAssertions test suite.
```

The standalone modules reuse the *real* engines and GUIs from the main app via linked-source
compilation, so they look and behave the same but don't depend on the console at runtime.

---

## Honest known issues / caveats

- I'm not a professional developer, so expect rough edges and bugs. Treat this as a capable
  hobby/portfolio project, not production-hardened enterprise software.
- **Security posture is a work in progress.** The agent/console path is authenticated (pairing +
  challenge/response), but some ingest listeners (e.g. syslog) are unauthenticated by design and
  meant for **trusted networks only**. TLS on the wire is structured for but not yet enabled.
- The SIEM store is currently **in-memory** (a ring buffer with disk snapshots) — great for a
  demo or a home lab, not yet a true multi-node datastore. A real Elasticsearch/OpenSearch backend
  is designed-for but not wired up.
- Auth / RBAC / multi-tenancy are **deferred** — this is effectively single-user today.
- The "planned" modules above are not built yet.

---

## Contributing

Contributions, bug reports, and ideas are all welcome — that's the whole point of opening this up.
Because I'm doing this solo and part-time, I may be slow to respond, but I'll do my best. If you
want to tackle one of the planned modules or clean up something I got wrong, please do.

---

## License

Open source — see the `LICENSE` file. If none is present yet, treat this as "all rights reserved
pending a license" and reach out; a permissive license is intended.

---

*PrivaCore is provided as-is, for authorised and educational security use. Be responsible.*
