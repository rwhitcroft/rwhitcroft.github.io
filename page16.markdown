---
layout: default
---
<br/>
## Shellcode: Position Independence (3)
* * *
One solution is to ensure we only ever `call` backwards (to a lower address) to force the offset to be negative and much less likely to contain null bytes.

As before, `f7 ff ff ff` in little endian is `ff ff ff f7` (-9), so the operand to the `e8` opcode is -9, or "call backwards 9 bytes".
* * *
<p style="text-align: center;"><img src="/images/pic2.png"/></p>
