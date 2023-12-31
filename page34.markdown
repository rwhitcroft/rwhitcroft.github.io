---
layout: default
---
<br/>
## Process Environment Block (2)
* * *

A pointer to the `PEB` structure, which contains a pointer to the `PEB_LDR_DATA` structure (`Ldr`), can be obtained by any process by reading the value at offset `0x60` (on x64) from the base of the `gs` segment.

* * *

<p style="text-align: center;"><img src="/images/peb2.png"/></p>
