---
layout: default
---
<br/>
## Shellcode: Strings (3)
* * *
To store a string, the idea is to put the bytes into a register, then write the register somewhere in memory. That address will then be used as the pointer to the C-string that we can pass to functions.

Because we're in a little-endian environment, we'll need to put the bytes into the register in reverse before writing it to memory.

We can use WinDbg's `da` command to display a C-string at a given address. WinDbg will treat the data at that address as a C-string and print characters until it encounters a null terminator.

* * *

<p style="text-align: center;"><img src="/images/strings1.png"/></p>
