---
layout: default
---
<br/>
## Shellcode: Null-Free (5)
* * *

To demonstrate that there are many ways to achieve the same result, here's another example that ends up being one byte smaller:

```
    31c0          xor   eax,eax       # zero eax
    ffc0          inc   eax           # increment eax
    c1e008        shl   eax,8         # left shift eax by 8 bits (1 byte)
```
