# PrivaCore Honeypot — module

A standalone honeypot **sensor** you deploy on a machine you want to watch. It runs decoy
services (Telnet / HTTP / SSH / FTP / raw TCP), records every attacker interaction (including
credentials tried), and streams the hits back to the console over the module channel.

## Run it
1. Copy `PrivaCore.Honeypot\bin\Debug\net8.0-windows\` to the sensor host and run
   `privacore-honeypot.exe` (or use `Run-Honeypot-Module.cmd`).
2. First run: set the **control port** (default 9710), a **username + password**, and a
   **pairing code** (deployment secret). Save & Start.
3. The sensor starts decoys (defaults: Telnet 2323, HTTP 8080, SSH 2222) and shows live captures.
   Add or stop decoys from the running view; they persist and auto-start next launch.
4. Run `Allow-Firewall.cmd` **as Administrator** so the console can reach the control port and
   attackers can reach the decoys.

## Connect from the console
**Add Module → Honeypot Manager → enter the host IP + control port → username + password +
pairing code → Connect.** Captured hits stream into the console live.

## Security
Same as the other modules: pairing code gate + SCRAM-style challenge/response (the password is
never sent). Bind decoys to ports below 1024 only when running elevated.
