---
layout: default
---
<br/>
## Shellcode: Null-Free (4)
* * *

Instead of using `0x100` (which is `00 01` in little endian bytes), we can use `0x101` (`01 01`) to avoid the null byte in our integer.

As before, we need to zero the 32-bit `eax` register first to clear any upper bits, then `dec eax` to subtract one from `0x101` to get `0x100`.

```
    31c0            xor   eax,eax       # zero eax
    66b80101        mov   ax,101h       # put 0x101 into ax
    ffc8            dec   eax           # decrement eax
```

We now have `eax` set to `0x100` with no null bytes, but at the cost of shellcode size.
