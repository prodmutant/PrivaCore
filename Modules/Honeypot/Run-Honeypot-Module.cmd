@echo off
REM Launch the standalone PrivaCore Honeypot sensor.
REM First run shows a setup screen (control port + username/password + pairing code).
start "" "%~dp0..\..\PrivaCore.Honeypot\bin\Debug\net8.0-windows\privacore-honeypot.exe"
