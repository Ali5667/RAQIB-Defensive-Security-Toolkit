@echo off
REM =====================================================
REM  RAQIB - Defensive Security Toolkit
REM  Windows launcher - مشغّل ويندوز
REM
REM  Goal: locate Git Bash (preferred) and launch the toolkit
REM  inside it. If Bash is missing, guide the user to install
REM  Git for Windows or WSL2.
REM =====================================================
setlocal enabledelayedexpansion

REM CWD = folder that contains raqib.bat
set "RAQIB_DIR=%~dp0"
cd /d "%RAQIB_DIR%"

chcp 65001 >nul 2>&1

set "BASH_CMD="

REM Standard install locations for Git Bash:
for %%P in (
    "%ProgramFiles%\Git\bin\bash.exe"
    "%ProgramFiles(x86)%\Git\bin\bash.exe"
    "%ProgramW6432%\Git\bin\bash.exe"
    "%LocalAppData%\Programs\Git\bin\bash.exe"
    "%LocalAppData%\Programs\Git\cmd\bash.exe"
    "%USERPROFILE%\scoop\apps\git\current\bin\bash.exe"
) do (
    if exist %%P (
        if not defined BASH_CMD set "BASH_CMD=%%~P"
    )
)

REM Last resort: bash on PATH (MSYS2 or custom install)
if not defined BASH_CMD (
    where bash >nul 2>&1
    if not errorlevel 1 for /f "tokens=* usebackq" %%B in (`where bash`) do (
        if not defined BASH_CMD set "BASH_CMD=%%B"
    )
)

if defined BASH_CMD (
    echo.
    echo   [RAQIB] Windows launcher found Bash: !BASH_CMD!
    echo   [RAQIB] starting toolkit...
    echo.
    "!BASH_CMD!" "%RAQIB_DIR%raqib.sh" %*
    endlocal
    exit /b
)

REM Git Bash not found — guide the user:
echo.
echo  =====================================================
echo   RAQIB on Windows needs a POSIX Bash environment.
echo   يحتاج RAQIB في ويندوز إلى بيئة Bash متوافقة مع POSIX.
echo  =====================================================
echo.
echo   Option 1 (recommended) - Git for Windows (Git Bash):
echo     1) Download: https://git-scm.com/download/win
echo     2) Install with default options
echo     3) Re-run this file: raqib.bat
echo.
echo   الخيار 1 (المستحسن) - Git for Windows (Git Bash):
echo     1) حمّل: https://git-scm.com/download/win
echo     2) ثبّت بالخيارات الافتراضية
echo     3) شغّل raqib.bat من جديد
echo.
echo   Option 2 - WSL2 (full Linux environment on Windows):
echo     4) Open PowerShell as Administrator and run:
echo        wsl --install
echo     5) Restart the PC, then inside the Ubuntu/Kali terminal:
echo        git clone https://github.com/Ali5667/RAQIB-Defensive-Security-Toolkit.git
echo        cd RAQIB-Defensive-Security-Toolkit
echo        chmod +x raqib.sh
echo        ./raqib.sh
echo.
echo   الخيار 2 - WSL2 (بيئة لينكس كاملة داخل ويندوز):
echo     4) افتح PowerShell كمسؤول ونفّذ:  wsl --install
echo     5) أعد تشغيل الجهاز ثم من طرفية Ubuntu/Kali:
echo        git clone https://github.com/Ali5667/RAQIB-Defensive-Security-Toolkit.git
echo        cd RAQIB-Defensive-Security-Toolkit ^&^& chmod +x raqib.sh ^&^& ./raqib.sh
echo.
pause
exit /b 1
