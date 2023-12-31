---
layout: default
---
<br/>
## Process Environment Block (1)
* * *

"The Process Environment Block (PEB) is a data structure in the Windows NT operating system family. It is an opaque data structure that is used by the operating system internally, most of whose fields are not intended for use by anything other than the operating system." --Wikipedia

To locate the base address of `kernel32.dll`, our shellcode will read data from the various structures stored in the PEB.

* * *

<p style="text-align: center;"><img src="/images/peb1.png"/></p>
