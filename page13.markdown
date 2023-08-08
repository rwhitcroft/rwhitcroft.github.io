---
layout: default
---
<br/>
## Shellcode: Position Independence (1)
* * *
To be "position independent" means the shellcode can run anywhere in memory; it does not rely on hardcoded, absolute addresses, since these will not be known when performing the buffer overflow.

Shellcode will need to use the `call` instruction to call functions. Unfortunately, null bytes will be introduced if a `call` is performed to a higher address than the call site because the offset must be expressed as a 32-bit (4 byte) positive number which is highly likely to contain zeros (null bytes).
