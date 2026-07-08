@echo off
REM Run as Administrator (right-click > Run as administrator).
REM Opens the Windows Firewall so other machines can reach the IDS module.
REM Change 9700 if you configured a different listen port.
set PORT=9700
netsh advfirewall firewall delete rule name="PrivaCore IDS %PORT%" >nul 2>&1
netsh advfirewall firewall add rule name="PrivaCore IDS %PORT%" dir=in action=allow protocol=TCP localport=%PORT%
echo.
echo Allowed inbound TCP %PORT% for the PrivaCore IDS module.
pause
