
:NetworkRoutes
CALL :ColorLine " %E%33m[+]%E%97m ROUTES"
route print
ECHO.
CALL :T_Progress 1

:WindowsHostsFile
CALL :ColorLine " %E%33m[+]%E%97m Hosts file"
type C:\WINDOWS\System32\drivers\etc\hosts | findstr /v "^#"
CALL :T_Progress 1

:DNSCache
CALL :ColorLine " %E%33m[+]%E%97m DNS CACHE"
ipconfig /displaydns | findstr "Record" | findstr "Name Host"
ECHO.
CALL :T_Progress 1

:WifiCreds
CALL :ColorLine " %E%33m[+]%E%97m WIFI"
for /f "tokens=4 delims=: " %%a in ('netsh wlan show profiles ^| find "Profile "') do (netsh wlan show profiles name=%%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & ECHO.)
CALL :T_Progress 1

:BasicUserInfo
CALL :ColorLine "%E%32m[*]%E%97m BASIC USER INFO
ECHO.   [i] Check if you are inside the Administrators group or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups
ECHO.
CALL :ColorLine " %E%33m[+]%E%97m CURRENT USER"
net user %username%
net user %USERNAME% /domain 2>nul
whoami /all
ECHO.
CALL :T_Progress 2

:BasicUserInfoUsers
CALL :ColorLine " %E%33m[+]%E%97m USERS"
net user
ECHO.
CALL :T_Progress 1

:BasicUserInfoGroups
CALL :ColorLine " %E%33m[+]%E%97m GROUPS"
net localgroup
ECHO.
CALL :T_Progress 1

:BasicUserInfoAdminGroups
CALL :ColorLine " %E%33m[+]%E%97m ADMINISTRATORS GROUPS"
REM seems to be localised
net localgroup Administrators 2>nul
net localgroup Administradores 2>nul
ECHO. 
CALL :T_Progress 1

:BasicUserInfoLoggedUser
CALL :ColorLine " %E%33m[+]%E%97m CURRENT LOGGED USERS"
quser
ECHO. 
CALL :T_Progress 1

:KerberosTickets
CALL :ColorLine " %E%33m[+]%E%97m Kerberos Tickets"
klist
ECHO. 
CALL :T_Progress 1

:CurrentClipboard
CALL :ColorLine " %E%33m[+]%E%97m CURRENT CLIPBOARD"
ECHO.   [i] Any passwords inside the clipboard?
powershell -command "Get-Clipboard" 2>nul
ECHO.
CALL :T_Progress 1

:ServiceVulnerabilities
CALL :ColorLine "%E%32m[*]%E%97m SERVICE VULNERABILITIES"
:::sysinternals external tool
::ECHO.
::CALL :ColorLine " %E%33m[+]%E%97m SERVICE PERMISSIONS WITH accesschk.exe FOR 'Authenticated users', Everyone, BUILTIN\Users, Todos and CURRENT USER"
::ECHO.   [i] If Authenticated Users have SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG or WRITE_DAC or WRITE_OWNER or GENERIC_WRITE or GENERIC_ALL, you can modify the binary that is going to be executed by the service and start/stop the service
::ECHO.   [i] If accesschk.exe is not in PATH, nothing will be found here
::ECHO.   [i] AUTHETICATED USERS
::accesschk.exe -uwcqv "Authenticated Users" * /accepteula 2>nul
::ECHO.   [i] EVERYONE
::accesschk.exe -uwcqv "Everyone" * /accepteula 2>nul
::ECHO.   [i] BUILTIN\Users
::accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
::ECHO.   [i] TODOS
::accesschk.exe -uwcqv "Todos" * /accepteula 2>nul
::ECHO.   [i] %USERNAME%
::accesschk.exe -uwcqv %username% * /accepteula 2>nul
::ECHO.
::CALL :ColorLine " %E%33m[+]%E%97m SERVICE PERMISSIONS WITH accesschk.exe FOR *"
::ECHO.   [i] Check for weird service permissions for unexpected groups"
::accesschk.exe -uwcqv * /accepteula 2>nul
CALL :T_Progress 1
ECHO.

:ServiceBinaryPermissions
CALL :ColorLine " %E%33m[+]%E%97m SERVICE BINARY PERMISSIONS WITH WMIC and ICACLS"
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
for /f "tokens=2 delims='='" %%a in ('cmd.exe /c wmic service list full ^| findstr /i "pathname" ^|findstr /i /v "system32"') do (
    for /f eol^=^"^ delims^=^" %%b in ("%%a") do icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos usuarios %username%" && ECHO.
)
ECHO.
CALL :T_Progress 1

:CheckRegistryModificationAbilities
CALL :ColorLine " %E%33m[+]%E%97m CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY"
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
for /f %%a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv >nul 2>&1 & reg save %%a %temp%\reg.hiv >nul 2>&1 && reg restore %%a %temp%\reg.hiv >nul 2>&1 && ECHO.You can modify %%a
ECHO.
CALL :T_Progress 1

:UnquotedServicePaths
CALL :ColorLine " %E%33m[+]%E%97m UNQUOTED SERVICE PATHS"
ECHO.   [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Program.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'
ECHO.   [i] The permissions are also checked and filtered using icacls
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		ECHO.%%~s ^| findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (ECHO.%%n && ECHO.%%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && ECHO.
	)
)
CALL :T_Progress 2
::wmic service get name,displayname,pathname,startmode | more | findstr /i /v "C:\\Windows\\system32\\" | findstr /i /v """
ECHO.
::CALL :T_Progress 1

:PATHenvHijacking
CALL :ColorLine "%E%32m[*]%E%97m DLL HIJACKING in PATHenv variable"
ECHO.   [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations
ECHO.   [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. )
ECHO.
CALL :T_Progress 1

:WindowsCredentials
CALL :ColorLine "%E%32m[*]%E%97m CREDENTIALS"
ECHO.
CALL :ColorLine " %E%33m[+]%E%97m WINDOWS VAULT"
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault
cmdkey /list
ECHO.
CALL :T_Progress 2

:DPAPIMasterKeys
CALL :ColorLine " %E%33m[+]%E%97m DPAPI MASTER KEYS"
ECHO.   [i] Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
powershell -command "Get-ChildItem %appdata%\Microsoft\Protect" 2>nul
powershell -command "Get-ChildItem %localappdata%\Microsoft\Protect" 2>nul
CALL :T_Progress 2
CALL :ColorLine " %E%33m[+]%E%97m DPAPI MASTER KEYS"
ECHO.   [i] Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt
ECHO.   [i] You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
ECHO.
ECHO.Looking inside %appdata%\Microsoft\Credentials\
ECHO.
dir /b/a %appdata%\Microsoft\Credentials\ 2>nul 
CALL :T_Progress 2
ECHO.
ECHO.Looking inside %localappdata%\Microsoft\Credentials\
ECHO.
dir /b/a %localappdata%\Microsoft\Credentials\ 2>nul
CALL :T_Progress 2
ECHO.

:UnattendedFiles
CALL :ColorLine " %E%33m[+]%E%97m Unattended files"
IF EXIST %WINDIR%\sysprep\sysprep.xml ECHO.%WINDIR%\sysprep\sysprep.xml exists. 
IF EXIST %WINDIR%\sysprep\sysprep.inf ECHO.%WINDIR%\sysprep\sysprep.inf exists. 
IF EXIST %WINDIR%\sysprep.inf ECHO.%WINDIR%\sysprep.inf exists. 
IF EXIST %WINDIR%\Panther\Unattended.xml ECHO.%WINDIR%\Panther\Unattended.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend.xml ECHO.%WINDIR%\Panther\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattend.xml ECHO.%WINDIR%\Panther\Unattend\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattended.xml ECHO.%WINDIR%\Panther\Unattend\Unattended.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattend.xml ECHO.%WINDIR%\System32\Sysprep\unattend.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattended.xml ECHO.%WINDIR%\System32\Sysprep\unattended.xml exists.
IF EXIST %WINDIR%\..\unattend.txt ECHO.%WINDIR%\..\unattend.txt exists.
IF EXIST %WINDIR%\..\unattend.inf ECHO.%WINDIR%\..\unattend.inf exists. 
ECHO.
CALL :T_Progress 2

:SAMSYSBackups
CALL :ColorLine " %E%33m[+]%E%97m SAM and SYSTEM backups"
IF EXIST %WINDIR%\repair\SAM ECHO.%WINDIR%\repair\SAM exists. 
IF EXIST %WINDIR%\System32\config\RegBack\SAM ECHO.%WINDIR%\System32\config\RegBack\SAM exists.
IF EXIST %WINDIR%\System32\config\SAM ECHO.%WINDIR%\System32\config\SAM exists.
IF EXIST %WINDIR%\repair\SYSTEM ECHO.%WINDIR%\repair\SYSTEM exists.
IF EXIST %WINDIR%\System32\config\SYSTEM ECHO.%WINDIR%\System32\config\SYSTEM exists.
IF EXIST %WINDIR%\System32\config\RegBack\SYSTEM ECHO.%WINDIR%\System32\config\RegBack\SYSTEM exists.
ECHO.
CALL :T_Progress 3

:McAffeeSitelist
CALL :ColorLine " %E%33m[+]%E%97m McAffee SiteList.xml"
cd %ProgramFiles% 2>nul
dir /s SiteList.xml 2>nul
cd %ProgramFiles(x86)% 2>nul
dir /s SiteList.xml 2>nul
cd "%windir%\..\Documents and Settings" 2>nul
dir /s SiteList.xml 2>nul
cd %windir%\..\Users 2>nul
dir /s SiteList.xml 2>nul
ECHO.
CALL :T_Progress 2

:GPPPassword
CALL :ColorLine " %E%33m[+]%E%97m GPP Password"
cd "%SystemDrive%\Microsoft\Group Policy\history" 2>nul
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml 2>nul
cd "%windir%\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" 2>nul
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml 2>nul
ECHO.
CALL :T_Progress 2

:CloudCreds
CALL :ColorLine " %E%33m[+]%E%97m Cloud Credentials"
cd "%SystemDrive%\Users"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json 2>nul
cd "%windir%\..\Documents and Settings"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json 2>nul
ECHO.
CALL :T_Progress 2

:AppCMD
CALL :ColorLine " %E%33m[+]%E%97m AppCmd"
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#appcmdexe
IF EXIST %systemroot%\system32\inetsrv\appcmd.exe ECHO.%systemroot%\system32\inetsrv\appcmd.exe exists. 
ECHO.
CALL :T_Progress 2

:RegFilesCredentials
CALL :ColorLine " %E%33m[+]%E%97m Files in registry that may contain credentials"
ECHO.   [i] Searching specific files that may contains credentials.
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials
ECHO.Looking inside HKCU\Software\ORL\WinVNC3\Password
reg query HKCU\Software\ORL\WinVNC3\Password 2>nul
CALL :T_Progress 2
ECHO.Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password 2>nul
CALL :T_Progress 2
ECHO.Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"
CALL :T_Progress 2
ECHO.Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s 2>nul
CALL :T_Progress 2
ECHO.Looking inside HKCU\Software\TightVNC\Server
reg query HKCU\Software\TightVNC\Server 2>nul
CALL :T_Progress 2
ECHO.Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>nul
CALL :T_Progress 2
ECHO.Looking inside HKCU\Software\OpenSSH\Agent\Keys
CALL :T_Progress 2
reg query HKCU\Software\OpenSSH\Agent\Keys /s 2>nul
cd %USERPROFILE% 2>nul && dir /s/b *password* == *credential* 2>nul
cd ..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..
dir /s/b /A:-D RDCMan.settings == *.rdg == SCClient.exe == *_history == .sudo_as_admin_successful == .profile == *bashrc == httpd.conf == *.plan == .htpasswd == .git-credentials == *.rhosts == hosts.equiv == Dockerfile == docker-compose.yml == appcmd.exe == TypedURLs == TypedURLsTime == History == Bookmarks == Cookies == "Login Data" == places.sqlite == key3.db == key4.db == credentials == credentials.db == access_tokens.db == accessTokens.json == legacy_credentials == azureProfile.json == unattend.txt == access.log == error.log == *.gpg == *.pgp == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12 == *.der == *.csr == *.cer == known_hosts == id_rsa == id_dsa == *.ovpn == anaconda-ks.cfg == hostapd.conf == rsyncd.conf == cesi.conf == supervisord.conf == tomcat-users.xml == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == unattend.xml == unattended.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == groups.xml == services.xml == scheduledtasks.xml == printers.xml == drives.xml == datasources.xml == php.ini == https.conf == https-xampp.conf == httpd.conf == my.ini == my.cnf == access.log == error.log == server.xml == SiteList.xml == ConsoleHost_history.txt == setupinfo == setupinfo.bak 2>nul | findstr /v ".dll"
cd inetpub 2>nul && (dir /s/b web.config == *.log & cd ..)
ECHO.
CALL :T_Progress 2

:ExtendedDriveScan
if "%long%" == "true" (
    CALL :ColorLine " %E%33m[+]%E%97m REGISTRY WITH STRING pass OR pwd"
	reg query HKLM /f passw /t REG_SZ /s
	reg query HKCU /f passw /t REG_SZ /s
	reg query HKLM /f pwd /t REG_SZ /s
	reg query HKCU /f pwd /t REG_SZ /s
	ECHO.
	ECHO.   [i] Iterating through the drives
	ECHO.
	for /f %%x in ('wmic logicaldisk get name^| more') do (
		set tdrive=%%x
		if "!tdrive:~1,2!" == ":" (
			%%x
            CALL :ColorLine " %E%33m[+]%E%97m FILES THAT CONTAINS THE WORD PASSWORD WITH EXTENSION: .xml .ini .txt *.cfg *.config"
	        findstr /s/n/m/i password *.xml *.ini *.txt *.cfg *.config 2>nul | findstr /v /i "\\AppData\\Local \\WinSxS ApnDatabase.xml \\UEV\\InboxTemplates \\Microsoft.Windows.Cloud \\Notepad\+\+\\ vmware cortana alphabet \\7-zip\\" 2>nul
            ECHO.
            CALL :ColorLine " %E%33m[+]%E%97m FILES WHOSE NAME CONTAINS THE WORD PASS CRED or .config not inside \Windows\"
            dir /s/b *pass* == *cred* == *.config* == *.cfg 2>nul | findstr /v /i "\\windows\\"  
            ECHO.
		)
	)
	CALL :T_Progress 2
) ELSE (
	CALL :T_Progress 2
)
