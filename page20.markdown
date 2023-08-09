---
layout: default
---
<br/>
## Shellcode: Strings (1)
* * *
Sometimes we'll need to store strings in memory with shellcode. For example, we'll need to pass a pointer to a null-terminated string to `LoadLibraryA()` to tell it which DLL to load.

The C language's way of dealing with strings is using null termination, which just means that a null byte (`0x00`) is used to mark the end of the string.

This of course is the main reason we want to always avoid null bytes.
