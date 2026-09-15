@echo off
where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%~dp0daybreak.py" %*
  goto finish
)
where python >nul 2>nul
if not errorlevel 1 (
  python "%~dp0daybreak.py" %*
  goto finish
)
echo Install Python 3.11 or newer from https://www.python.org/downloads/windows/
echo Or run: winget install --exact --id Python.Python.3.13
echo Then reopen this launcher.
exit /b 1
:finish
set "launcher_exit=%errorlevel%"
if "%~1"=="" pause
exit /b %launcher_exit%
