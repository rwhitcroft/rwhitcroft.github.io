---
layout: default
---
<br/>
## Shellcode: Strings (9)
* * *
Since we're going to lose a byte when shifting, we'll update our string to "xtest123" (the "x" will drop). The new reversed hex value is `0x3332317473657478`. Note that the "x" can be anything except null.

Examining `rax` before the `shr` instruction shows the hex representation of "321tsetx". After the shift, it becomes "\x00321tset", and is written to memory. Showing the string with `da` works as expected, and we now have a null-terminated string without having sent a null byte.

* * *

<p style="text-align: center;"><img src="/images/strings8.png"/></p>
