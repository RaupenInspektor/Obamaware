@ECHO OFF
TITLE WinPEAS - Windows local Privilege Escalation Awesome Script
COLOR 0F
CALL :SetOnce

REM :: WinPEAS - Windows local Privilege Escalation Awesome Script
REM :: Code by carlospolop; Re-Write by ThisLimn0

REM Registry scan of other drives besides 
REM /////true or false
SET long=true

REM Check if the current path contains spaces
SET "CurrentFolder=%~dp0"
IF "!CurrentFolder!" NEQ "!CurrentFolder: =!" (
    ECHO winPEAS.bat cannot run if the current path contains spaces.
	ECHO Exiting.
    EXIT /B 1
)

:Splash
ECHO.
CALL :ColorLine "            %E%32m((,.,/((((((((((((((((((((/,  */%E%97m"
CALL :ColorLine "     %E%32m,/*,..*(((((((((((((((((((((((((((((((((,%E%97m"              
CALL :ColorLine "   %E%32m,*/((((((((((((((((((/,  %E%92m.*//((//**,%E%32m .*((((((*%E%97m"       
CALL :ColorLine "   %E%32m((((((((((((((((* %E%94m*****%E%32m,,,/########## %E%32m.(* ,((((((%E%97m"   
CALL :ColorLine "   %E%32m(((((((((((/* %E%94m******************%E%32m/####### %E%32m.(. ((((((%E%97m"
CALL :ColorLine "   %E%32m((((((.%E%92m.%E%94m******************%E%97m/@@@@@/%E%94m***%E%92m/######%E%32m /((((((%E%97m"
CALL :ColorLine "   %E%32m,,.%E%92m.%E%94m**********************%E%97m@@@@@@@@@@(%E%94m***%E%92m,####%E%32m ../(((((%E%97m"
CALL :ColorLine "   %E%32m, ,%E%92m%E%94m**********************%E%97m#@@@@@#@@@@%E%94m*********%E%92m##%E%32m((/ /((((%E%97m"
CALL :ColorLine "   %E%32m..((%E%92m(##########%E%94m*********%E%97m/#@@@@@@@@@/%E%94m*************%E%32m,,..((((%E%97m"
CALL :ColorLine "   %E%32m.((%E%92m(################(/%E%94m******%E%97m/@@@@@#%E%94m****************%E%32m.. /((%E%97m"
CALL :ColorLine "   %E%32m.(%E%92m(########################(/%E%94m************************%E%32m..*(%E%97m"
CALL :ColorLine "   %E%32m.(%E%92m(#############################(/%E%94m********************%E%32m.,(%E%97m"
CALL :ColorLine "   %E%32m.(%E%92m(##################################(/%E%94m***************%E%32m..(%E%97m"
CALL :ColorLine "   %E%32m.(%E%92m(######################################(%E%94m************%E%32m..(%E%97m"
CALL :ColorLine "   %E%32m.(%E%92m(######(,.***.,(###################(..***(/%E%94m*********%E%32m..(%E%97m"
CALL :ColorLine "   %E%32m.(%E%92m(######*(#####((##################((######/(%E%94m********%E%32m..(%E%97m"
CALL :ColorLine "   %E%32m.(%E%92m(##################(/**********(################(%E%94m**%E%32m...(%E%97m"
CALL :ColorLine "   %E%32m.((%E%92m(####################/*******(###################%E%32m.((((%E%97m" 
CALL :ColorLine "   %E%32m.((((%E%92m(############################################/%E%32m  /((%E%97m"
CALL :ColorLine "   %E%32m..((((%E%92m(#########################################(%E%32m..(((((.%E%97m"
CALL :ColorLine "   %E%32m....((((%E%92m(#####################################(%E%32m .((((((.%E%97m"
CALL :ColorLine "   %E%32m......((((%E%92m(#################################(%E%32m .(((((((.%E%97m"
CALL :ColorLine "   %E%32m(((((((((. ,%E%92m(############################(%E%32m../(((((((((.%E%97m"
CALL :ColorLine "       %E%32m(((((((((/,  %E%92m,####################(%E%32m/..((((((((((.%E%97m"
CALL :ColorLine "             %E%32m(((((((((/,.  %E%92m,*//////*,.%E%32m ./(((((((((((.%E%97m"
CALL :ColorLine "                %E%32m(((((((((((((((((((((((((((/%E%97m"
ECHO.                       by carlospolop
ECHO.
ECHO.

:Advisory
REM // Increase progress in title by n percent
CALL :T_Progress 0
ECHO./^^!\ Advisory: WinPEAS - Windows local Privilege Escalation Awesome Script
CALL :ColorLine "   %E%41mWinPEAS should be used for authorized penetration testing and/or educational purposes only.%E%40;97m"
CALL :ColorLine "   %E%41mAny misuse of this software will not be the responsibility of the author or of any other collaborator.%E%40;97m"
CALL :ColorLine "   %E%41mUse it at your own networks and/or with the network owner's permission.%E%40;97m"
ECHO.

:SystemInfo
CALL :ColorLine "%E%32m[*]%E%97m BASIC SYSTEM INFO"
CALL :ColorLine " %E%33m[+]%E%97m WINDOWS OS"
ECHO.   [i] Check for vulnerabilities for the OS version with the applied patches
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits
systeminfo
ECHO.
CALL :T_Progress 2

:ListHotFixes
wmic qfe get Caption,Description,HotFixID,InstalledOn | more
set expl=no
for /f "tokens=3-9" %%a in ('systeminfo') do (ECHO."%%a %%b %%c %%d %%e %%f %%g" | findstr /i "2000 XP 2003 2008 vista" && set expl=yes) & (ECHO."%%a %%b %%c %%d %%e %%f %%g" | findstr /i /C:"windows 7" && set expl=yes)
IF "%expl%" == "yes" ECHO.   [i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2592799" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS11-080 patch is NOT installed! (Vulns: XP/SP3,2K3/SP3-afd.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3143141" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS16-032 patch is NOT installed! (Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2393802" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS11-011 patch is NOT installed! (Vulns: XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB982799" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS10-59 patch is NOT installed! (Vulns: 2K8,Vista,7/SP0-Chimichurri)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB979683" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS10-21 patch is NOT installed! (Vulns: 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2305420" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS10-092 patch is NOT installed! (Vulns: 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB981957" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS10-073 patch is NOT installed! (Vulns: XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB4013081" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS17-017 patch is NOT installed! (Vulns: 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB977165" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS10-015 patch is NOT installed! (Vulns: 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB941693" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS08-025 patch is NOT installed! (Vulns: 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB920958" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS06-049 patch is NOT installed! (Vulns: 2K/SP4-ZwQuerySysInfo)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB914389" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS06-030 patch is NOT installed! (Vulns: 2K,XP/SP2-Mrxsmb.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB908523" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS05-055 patch is NOT installed! (Vulns: 2K/SP4-APC Data-Free)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB890859" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS05-018 patch is NOT installed! (Vulns: 2K/SP3/4,XP/SP1/2-CSRSS)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB842526" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS04-019 patch is NOT installed! (Vulns: 2K/SP2/3/4-Utility Manager)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB835732" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS04-011 patch is NOT installed! (Vulns: 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB841872" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS04-020 patch is NOT installed! (Vulns: 2K/SP4-POSIX)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2975684" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS14-040 patch is NOT installed! (Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3136041" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS16-016 patch is NOT installed! (Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3057191" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS15-051 patch is NOT installed! (Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2989935" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS14-070 patch is NOT installed! (Vulns: 2K3/SP2-TCP/IP)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2778930" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS13-005 patch is NOT installed! (Vulns: Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2850851" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS13-053 patch is NOT installed! (Vulns: 7SP0/SP1_x86-schlamperei)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2870008" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 ECHO.MS13-081 patch is NOT installed! (Vulns: 7SP0/SP1_x86-track_popup_menu)
ECHO.
CALL :T_Progress 2

:DateAndTime
CALL :ColorLine " %E%33m[+]%E%97m DATE and TIME"
ECHO.   [i] You may need to adjust your local date/time to exploit some vulnerability
date /T
time /T
ECHO.
CALL :T_Progress 2

:AuditSettings
CALL :ColorLine " %E%33m[+]%E%97m Audit Settings"
ECHO.   [i] Check what is being logged
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit 2>nul
ECHO.
CALL :T_Progress 1

:WEFSettings
CALL :ColorLine " %E%33m[+]%E%97m WEF Settings"
ECHO.   [i] Check where are being sent the logs
REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager 2>nul
ECHO.
CALL :T_Progress 1

:LAPSInstallCheck
CALL :ColorLine " %E%33m[+]%E%97m Legacy Microsoft LAPS installed?"
ECHO.   [i] Check what is being logged
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>nul
ECHO.
CALL :T_Progress 1

:WindowsLAPSInstallCheck
CALL :ColorLine " %E%33m[+]%E%97m Windows LAPS installed?"
ECHO.   [i] Check what is being logged: 0x00 Disabled, 0x01 Backup to Entra, 0x02 Backup to Active Directory
REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Policies\LAPS" /v BackupDirectory 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" /v BackupDirectory 2>nul
ECHO.
CALL :T_Progress 1

:LSAProtectionCheck
CALL :ColorLine " %E%33m[+]%E%97m LSA protection?"
ECHO.   [i] Active if "1"
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL 2>nul
CALL :T_Progress 1

:LSACredentialGuard
CALL :ColorLine " %E%33m[+]%E%97m Credential Guard?"
ECHO.   [i] Active if "1" or "2"
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags 2>nul
ECHO.
CALL :T_Progress 1

:LogonCredentialsPlainInMemory
CALL :ColorLine " %E%33m[+]%E%97m WDigest?"
ECHO.   [i] Plain-text creds in memory if "1"
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential 2>nul
ECHO.
CALL :T_Progress 1

:CachedCreds
CALL :ColorLine " %E%33m[+]%E%97m Number of cached creds"
ECHO.   [i] You need System-rights to extract them
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT 2>nul
CALL :T_Progress 1

:UACSettings
CALL :ColorLine " %E%33m[+]%E%97m UAC Settings"
ECHO.   [i] If the results read ENABLELUA REG_DWORD 0x1, part or all of the UAC components are on
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control.html#very-basic-uac-bypass-full-file-system-access
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA 2>nul
ECHO.
CALL :T_Progress 1

:AVSettings
CALL :ColorLine " %E%33m[+]%E%97m Registered Anti-Virus(AV)"
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more 
ECHO.Checking for defender whitelisted PATHS
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 2>nul
CALL :T_Progress 1

:PSSettings
CALL :ColorLine " %E%33m[+]%E%97m PowerShell settings"
ECHO.PowerShell v2 Version:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine /v PowerShellVersion 2>nul
ECHO.PowerShell v5 Version:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion 2>nul
ECHO.Transcriptions Settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription 2>nul
ECHO.Module logging settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging 2>nul
ECHO.Scriptblog logging settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging 2>nul
ECHO.
ECHO.PS default transcript history
dir %SystemDrive%\transcripts\ 2>nul
ECHO.
ECHO.Checking PS history file
dir "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
ECHO.
CALL :T_Progress 3

:MountedDisks
CALL :ColorLine " %E%33m[+]%E%97m MOUNTED DISKS"
ECHO.   [i] Maybe you find something interesting
(wmic logicaldisk get caption 2>nul | more) || (fsutil fsinfo drives 2>nul)
ECHO.
CALL :T_Progress 1

:Environment
CALL :ColorLine " %E%33m[+]%E%97m ENVIRONMENT"
ECHO.   [i] Interesting information?
ECHO.
set
ECHO.
CALL :T_Progress 1

:InstalledSoftware
CALL :ColorLine " %E%33m[+]%E%97m INSTALLED SOFTWARE"
ECHO.   [i] Some weird software? Check for vulnerabilities in unknow software installed
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#applications
ECHO.
dir /b "C:\Program Files" "C:\Program Files (x86)" | sort
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr InstallLocation | findstr ":\\"
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr InstallLocation | findstr ":\\"
IF exist C:\Windows\CCM\SCClient.exe ECHO.SCCM is installed (installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading)
ECHO.
CALL :T_Progress 2

:RemodeDeskCredMgr
CALL :ColorLine " %E%33m[+]%E%97m Remote Desktop Credentials Manager"
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#remote-desktop-credential-manager
IF exist "%LOCALAPPDATA%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" ECHO.Found: RDCMan.settings in %AppLocal%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings, check for credentials in .rdg files
ECHO.
CALL :T_Progress 1

:WSUS
CALL :ColorLine " %E%33m[+]%E%97m WSUS"
ECHO.   [i] You can inject 'fake' updates into non-SSL WSUS traffic (WSUXploit)
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wsus
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ 2>nul | findstr /i "wuserver" | findstr /i "http://"
ECHO.
CALL :T_Progress 1

:RunningProcesses
CALL :ColorLine " %E%33m[+]%E%97m RUNNING PROCESSES"
ECHO.   [i] Something unexpected is running? Check for vulnerabilities
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#running-processes
tasklist /SVC
ECHO.
CALL :T_Progress 2
ECHO.   [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('ECHO.%%x') do (
		icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
	)
)
ECHO.
ECHO.   [i] Checking directory permissions of running processes (DLL injection)
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('ECHO.%%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
)
ECHO.
CALL :T_Progress 3

:RunAtStartup
CALL :ColorLine " %E%33m[+]%E%97m RUN AT STARTUP"
ECHO.   [i] Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#run-at-startup
::(autorunsc.exe -m -nobanner -a * -ct /accepteula 2>nul || wmic startup get caption,command 2>nul | more & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
CALL :T_Progress 2
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
CALL :T_Progress 2
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
CALL :T_Progress 2
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab informa")
ECHO.
CALL :T_Progress 2

:AlwaysInstallElevated
CALL :ColorLine " %E%33m[+]%E%97m AlwaysInstallElevated?"
ECHO.   [i] If '1' then you can install a .msi file with admin privileges ;)
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated-1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
ECHO.
CALL :T_Progress 2

:NetworkShares
CALL :ColorLine "%E%32m[*]%E%97m NETWORK"
CALL :ColorLine " %E%33m[+]%E%97m CURRENT SHARES"
net share
ECHO.
CALL :T_Progress 1

:NetworkInterfaces
CALL :ColorLine " %E%33m[+]%E%97m INTERFACES"
ipconfig  /all
ECHO.
CALL :T_Progress 1

:SetOnce
REM :: ANSI escape character is set once below - for ColorLine Subroutine
SET "E=0x1B["
SET "PercentageTrack=0"
EXIT /B

:T_Progress
SET "Percentage=%~1"
SET /A "PercentageTrack=PercentageTrack+Percentage"
TITLE WinPEAS - Windows local Privilege Escalation Awesome Script - Scanning... !PercentageTrack!%%
EXIT /B

:ColorLine
SET "CurrentLine=%~1"
FOR /F "delims=" %%A IN ('FORFILES.EXE /P %~dp0 /M %~nx0 /C "CMD /C ECHO.!CurrentLine!"') DO ECHO.%%A
EXIT /B

:NetworkUsedPorts
CALL :ColorLine " %E%33m[+]%E%97m USED PORTS"
ECHO.   [i] Check for services restricted from the outside
netstat -ano | findstr /i listen
ECHO.
CALL :T_Progress 1

:NetworkFirewall
CALL :ColorLine " %E%33m[+]%E%97m FIREWALL"
netsh firewall show state
netsh firewall show config
ECHO.
CALL :T_Progress 2

:ARP
CALL :ColorLine " %E%33m[+]%E%97m ARP"
arp -A
ECHO.
CALL :T_Progress 1
