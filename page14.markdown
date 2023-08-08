---
layout: default
---
<br/>
## Shellcode: Position Independence (2)
* * *
The raw bytes break down as follows: `e8` is the opcode for `call`, and the operand is `03 00 00 00` in little endian, which is `3`. Essentially, "call ahead 3 bytes" (3 + 6 == 9).
* * *
<p style="text-align: center;"><img src="/images/pic1.png"/></p>
