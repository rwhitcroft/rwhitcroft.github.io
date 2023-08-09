---
layout: default
---
<br/>
## Endianness
* * *

Endianness describes the order in which a sequence of bytes is stored in computer memory. Bytes are either stored left-to-right (big), or they're reversed (little). Windows is little endian, meaning it stores bytes in reverse.

<p style="text-align: center;"><img src="/images/endianness2.webp"/></p>

* * *

Below, we're putting `0x4142434445464748` into `rax` and then writing the register contents somewhere in memory (`rsp`).

If we ask WinDbg to show us the raw bytes at `rsp` with `db`, it shows `48 47 46 45 44 43 42 41`, but if we ask for the 64-bit number representation of those same 8 bytes with `dq` (display qword), it shows the value we supplied originally.

<p style="text-align: center;"><img src="/images/endianness.png"/></p>
