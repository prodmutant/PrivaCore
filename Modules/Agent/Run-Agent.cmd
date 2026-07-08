@echo off
REM ── PrivaCore Agent quick start (Windows) ──
REM Edit the values below, then double-click this file.

set HOST=192.168.1.50
set PORT=9720
set USER=admin
set PASS=changeme
set PAIRING=ABCD-EFGH-JKLM
set NAME=%COMPUTERNAME%

REM Optional: comma-separated log files to ship (leave blank for heartbeat only).
set TAIL=

privacore-agent.exe --host %HOST% --port %PORT% --user %USER% --pass %PASS% --pairing %PAIRING% --name %NAME% --tail "%TAIL%"
pause
