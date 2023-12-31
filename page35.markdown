---
layout: default
---
<br/>
## Process Environment Block (3)
* * *

The shellcode's task is then to get a pointer to the `PEB` structure, follow that to get a pointer to the `PEB_LDR_DATA` structure, follow that to get a pointer to a linked list of loaded modules, then cycle through until `kernel32.dll` is found.

* * *

<p style="text-align: center;"><img src="/images/peb3.png"/></p>
