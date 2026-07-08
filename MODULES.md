# PrivaCore — Modular Architecture

PrivaCore is split into a **console** (the main app) and **standalone module apps**
you deploy on other machines. Some capabilities are built into the console; the
heavier, deployable ones (IDS, Honeypot, …) run as their own apps and are controlled
remotely over the network.

## Projects

| Project | What it is |
|---|---|
| **PROSCANNERCONT** | The console / controller (the main WPF app). |
| **PrivaCore.ModuleSdk** | Shared library: wire protocol, auth, host, client. Used by the console *and* every module. |
| **Modules/PrivaCore.Module.IDS** | Standalone IDS sensor app — run it on a sensor host. |
| *(Modules/… )* | Future standalone modules (Honeypot, etc.) follow the same template. |

## Console nav

- **TOOLS** (built-in, local): Port Scanner, Vulnerability Scanner, Network Discovery,
  Network Topology, Traffic Analysis, POC Explorer — these are *not* modular.
- **REMOTE MODULES**: modules you add with **+ Add Module** (IDS, Honeypot today; many
  "coming soon" placeholders: SIEM, EDR, Cloud, Threat Intel, Email, DLP, SOAR, Firewall,
  Compliance, Asset Inventory, Deception).

## Running a module (example: IDS)

1. Copy the IDS module app to the sensor host and run `privacore-ids.exe`.
2. First run shows a **setup screen**: set the **listen port**, create a **username +
   password**, and a **pairing code** (deployment secret). Save & Start.
3. The module now hosts itself and shows a live dashboard (connections + detections).

## Connecting from the console

**Add Module → Intrusion Detection → enter the host IP + port → Check connection →
username + password + pairing code → Connect.** A live view then streams the module's
events in real time.

## Security (defence in depth)

- **Pairing code** — a deployment enrolment secret required before any login is even
  attempted (rejects unknown clients early).
- **Password never transmitted** — SCRAM-style challenge/response: the host stores only a
  PBKDF2-derived key + per-secret salt; the client proves knowledge with
  `HMAC(key, server-nonce)`. Verified in constant time.
- **Session token** issued on success.
- **TLS-ready** — the channel wraps any `Stream`, so an `SslStream` drops in for
  transport encryption without changing the protocol.

## Data flow

After login the connection stays open. The module **pushes events** (`Broadcast`) to
every connected console; the console renders them live. The console can also **send
commands** back. This is the bidirectional channel future modules build on.

## Verified

- Solution builds with **0 errors**; **31 tests pass** (incl. pairing verify/reject, the
  password-never-sent proof, and a full host→client event-stream round-trip).
- Demonstrated live: IDS module hosting on :9700 → console connects with IP + credentials
  + pairing → real detections stream into the console.
