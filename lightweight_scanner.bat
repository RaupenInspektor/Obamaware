@echo off
setlocal enabledelayedexpansion

rem === UNQUOTED SERVICE PATHS (no :IsQuote dependency) ===
rem === Unquoted Service Paths check ===
CALL :Header "UNQUOTED SERVICE PATHS"
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
    for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
        echo Service: %%n
        echo Path: %%~s
        icacls %%s | findstr /i "(F) (M) (W) :\\" | findstr /i ":\ everyone authenticated users %username%" && echo.
    )
)
echo.

rem === DLL hijacking via PATH variable ===
CALL :Header "DLL HIJACKING in PATHenv variable"
for %%A in ("%path:;=";"%") do (
    icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\ everyone authenticated users %username%" && echo Writable: %%A
)
echo.

rem === File permissions of running process executables ===
CALL :Header "Permissions of running process executables"
for /f "tokens=2 delims==" %%x in ('wmic process list full ^| find /i "executablepath" ^| find /i /v "system32" ^| find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('echo.%%x') do (
        icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\ everyone authenticated users %username%" && echo Writable binary: %%z
    )
)
echo.

rem === Directory permissions of running processes (DLL injection) ===
CALL :Header "Permissions of directories of running processes"
for /f "tokens=2 delims==" %%x in ('wmic process list full ^| find /i "executablepath" ^| find /i /v "system32" ^| find ":"') do (
    for /f eol^=^"^ delims^=^" %%y in ('echo.%%x') do (
        icacls "%%~dpy\\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\ everyone authenticated users %username%" && echo Writable directory: %%~dpy
    )
)
echo.

rem === Run-at-startup locations ===
CALL :Header "Run-at-startup registry and folders"
for %%k in ("HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") do (
    reg query %%k 2>nul
)
for %%d in ("C:\Documents and Settings\All Users\Start Menu\Programs\Startup" "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup") do (
    icacls %%d 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\ everyone authenticated users %username%" && echo Writable startup folder: %%d
    icacls %%d\* 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\ everyone authenticated users %username%" && echo Writable file in startup folder: %%d
)
echo.

rem === AlwaysInstallElevated ===
CALL :Header "AlwaysInstallElevated registry settings"
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
echo.

rem === Token privileges ===
CALL :Header "Token privileges (enabled)"
for /f "skip=3 tokens=1,2,3,4,5" %%a in ('whoami /priv') do (
    echo %%a | findstr /i "SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege SeIncreaseQuotaPrivilege SeTcbPrivilege SeBackupPrivilege SeRestorePrivilege SeLoadDriverPrivilege SeTakeOwnershipPrivilege SeDebugPrivilege" >nul && (
        echo %%a    %%d
    )
)
echo.

rem === Security settings (LSA, Credential Guard, WDigest, CachedLogons) ===
CALL :Header "Security settings (LSA, Credential Guard, WDigest, CachedLogons)"
echo LSA Protection (RunAsPPL):
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL 2>nul
echo Credential Guard Enabled:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v Enabled 2>nul
echo WDigest UseLogonCredential:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>nul
echo Cached credentials (CachedLogonsCount):
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount 2>nul
echo.

rem === Service binary permissions ===
CALL :Header "Service binary permissions"
for /f "tokens=2 delims==" %%a in ('cmd.exe /c wmic service list full ^| findstr /i "pathname" ^| findstr /i /v "system32"') do (
    for /f eol^=^"^ delims^=^" %%b in ("%%a") do (
        icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\ everyone authenticated users %username%" && echo Writable service binary: %%b
    )
)
echo.

rem === Modifiable service registry keys ===
CALL :Header "Modifiable service registry keys"
for /f %%a in ('reg query hklm\system\currentcontrolset\services') do (
    del %temp%\reg.hiv >nul 2>&1
    reg save %%a %temp%\reg.hiv >nul 2>&1 && reg restore %%a %temp%\reg.hiv >nul 2>&1 && echo Can modify service key: %%a
)
echo.

endlocal
goto :EOF

:Header
set "head=%~1"
echo --------------------------------------------------------------------
echo %head%
echo --------------------------------------------------------------------
exit /b

