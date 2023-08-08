---
layout: default
---
<br/>
## Shellcode: Strings (6)
* * *

If we change the byte at offset `rbp+58` to a null and show the string again with `da`, WinDbg sees the null terminator and we get our string displayed as intended.

* * *

<p style="text-align: center;"><img src="/images/strings5.png"/></p>
