@echo off
setlocal

:: ===============================
:: CONFIGURATION
:: ===============================
set "BASE=%LOCALAPPDATA%\python-v.3.11.0\lib"
set "TOR_DIR=%BASE%\tor"
set "TOR_DATA=%TOR_DIR%\data"
set "TOR_ARCHIVE=%BASE%\tor-win32.tar.gz"

:: ===============================
:: CREATE FOLDERS
:: ===============================
mkdir "%BASE%" 2>nul
mkdir "%TOR_DIR%" 2>nul
mkdir "%TOR_DATA%" 2>nul

:: ===============================
:: DOWNLOAD TOR EXPERT BUNDLE
:: ===============================
echo Downloading Tor Expert Bundle...
curl -L -o "%TOR_ARCHIVE%" ^
https://archive.torproject.org/tor-package-archive/torbrowser/14.5.8/tor-expert-bundle-windows-x86_64-14.5.8.tar.gz

:: ===============================
:: EXTRACT AND CLEAN
:: ===============================
echo Extracting Tor Expert Bundle...
tar -xf "%TOR_ARCHIVE%" -C "%TOR_DIR%" || (
    echo [!] Extraction failed. Trying PowerShell fallback...
    powershell -Command "tar -xf '%TOR_ARCHIVE%' -C '%TOR_DIR%'"
)
echo [+] Succesfully Extracted Tor Bundle

del "%TOR_ARCHIVE%" >nul 2>&1

:: ===============================
:: WRITE torrc CONFIG
:: ===============================
(
    echo SocksPort 9050
    echo ControlPort 0
    echo DataDirectory %TOR_DATA:\=/%
    echo Log notice file NUL
) > "%TOR_DIR%\torrc"

echo [+] torrc Succesfully Written

:: ===============================
:: CREATE STARTER (for reuse)
:: ===============================
(
    echo @echo off
    echo cd /d "%%~dp0"
    echo echo Starting headless Tor client...
    echo start /b tor/tor.exe -f torrc
    echo echo.
    echo echo Use this command in any terminal to fetch .onion sites:
    echo echo   curl --socks5 127.0.0.1:9050 http://example.onion
    echo echo.
    echo echo Press Ctrl+C to stop Tor.
) > "%TOR_DIR%\Start-Tor-Proxy.cmd"

echo [+] Tor Starter Succesfully Written

echo Tor installed to: %TOR_DIR%
echo Run "%TOR_DIR%\Start-Tor-Proxy.cmd" to start Tor client.

echo When running, any tool can use SOCKS5 proxy at 127.0.0.1:9050

echo Example:
echo [CMD] Start Tor Proxy: %LOCALAPPDATA%\python-v.3.11.0\lib\tor\Start-Tor-Proxy.cmd
echo [CMD] curl --socks5-hostname 127.0.0.1:9050 http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion
echo [PS1] iwr http://exampleonion1234abcd.onion -Proxy 'socks5://127.0.0.1:9050'