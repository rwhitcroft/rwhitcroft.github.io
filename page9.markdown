---
layout: default
---
<br/>
## Shellcode: Null-Free (3)
* * *

We can try using the narrower (2 byte) `ax` register instead of the 4-byte `eax` register to avoid having to send zero values for the higher bytes. (We need to zero `eax` first to clear any residual data in the high bytes.)

![Null Bytes 2](/images/nullbytes2.png)

Better, but there's still one null byte.
