---
layout: default
---
<br/>
## Shellcode: Strings (8)
* * *
One way to create a null byte (there are many) is to use the right-shift instruction (`shr`).

When a number is right-shifted, the rightmost bits "fall off" and new bits come in on the left side. The new bits are always zeros.

So, if we right shift 8 bits (1 byte), we drop the last byte of our string on the right and a new zero byte appears on the left. Of course, this means we lose our first character (the "t" in "test1234"), but that can be overcome.

Remember that because this is little endian, we need the null byte as the first character (on the left side), so we need to shift right.

* * *

<p style="text-align: center;"><img height="70" src="/images/strings7.png"/></p>
