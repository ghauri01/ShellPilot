@echo off
REM Runs the built CLI directly, no npm install/publish needed.
REM Usage: bin\shellpilot.cmd claude | codex | run -- <command>
node "%~dp0..\out\cli\index.js" %*
