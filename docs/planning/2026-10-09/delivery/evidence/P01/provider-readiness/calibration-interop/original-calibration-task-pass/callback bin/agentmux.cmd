@echo off
setlocal DisableDelayedExpansion
REM Python 3 must be installed on Windows. The calling shell still parses syntax.
python "%~dp0agentmux_windows.py" %*
exit /b %errorlevel%
