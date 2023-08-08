---
layout: default
---
<br/>
## Shellcode: Null-Free (2)
* * *

Null bytes, and other bad characters, can usually be avoided by using different instructions to obtain the same result.

If we want to set `eax` to `0x100`, we might try:

```
    mov   eax, 0x100             # just put 0x100 into eax
```

But this would result in three null bytes in the machine code:

![Null Bytes 1](/images/nullbytes1.png)
