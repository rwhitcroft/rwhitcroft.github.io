---
layout: default
---
<br/>
## Shellcode: Strings (5)
* * *
After putting `0x3433323174736574` into `rax` and writing it to memory at `rbp+0x50`, we use `da` to display the string.

Without a null terminator, `da` reads way past the end of our string, as will any other Windows function that expects a null-terminated string.
* * *

<p style="text-align: center;"><img src="/images/strings4.png"/></p>
