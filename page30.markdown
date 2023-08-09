---
layout: default
---
<br/>
## Shellcode: Strings (11)
* * *

Previously, we have been writing strings directly to addresses (`rbp+0x50`). This time, we're using the stack to store our string by `push`ing data onto it.

One benefit in using the stack is that each time we `push`, the stack pointer (`rsp`) moves automatically, so we can just keep `push`ing data, and `rsp` will always be pointing to the beginning of our string.

* * *

<p style="text-align: center;"><img src="/images/strings10.png"/></p>

* * *

<p style="text-align: center;"><img src="/images/strings9.png"/></p>
