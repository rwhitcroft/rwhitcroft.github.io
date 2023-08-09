---
layout: default
---
<br/>
## Shellcode: Loading Libraries & Locating Functions
* * *

Shellcode will need to make use of the Windows API. To do that, it must first locate (or load) any modules it needs.

For a reverse shell, `ws2_32.dll` is needed, as it contains the socket functionality. For `MessageBoxA()`, we need `user32.dll`.

To load a module, the `LoadLibraryA()` function is used, which resides in `kernel32.dll` (which is itself almost always loaded).

Locating the base address of `kernel32.dll` is generally the first thing modern shellcode does.
