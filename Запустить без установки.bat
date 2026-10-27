@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
%PY% -m pip install --disable-pip-version-check psutil pystray pillow
%PY% antivirus.py
if errorlevel 1 pause
