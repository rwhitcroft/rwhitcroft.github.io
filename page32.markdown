---
layout: default
---
<br/>
## Shellcode: Overview
* * *

Modern shellcode more or less does the following:
- Read the Process Environment Block (PEB) to locate the linked list of loaded DLLs
- Iterate through the list looking for kernel32.dll (base address)
- Resolve the address of LoadLibraryA() in kernel32.dll to load any required DLLs
- Load required DLLs (ws2_32.dll, user32.dll, etc) with LoadLibraryA()
- To find function addresses, hash the name of the function, enumerate the DLL's Export Address Table (EAT), hash each function name, and compare the hashes
- Prepare registers with the required parameters (rcx, rdx, r8, r9) and call the functions
