---
layout: default
---
<br/>
## Shellcode: Strings (7)
* * *
To null-terminate our string, it's tempting to just try to include the null byte when we put our reversed hex bytes into `rax` and sacrificing one byte of space:

<p style="text-align: center;"><img src="/images/strings6.png"/></p>

But of course that doesn't work because we just used a null character.

We need a way to create a null character without sending a null character.
