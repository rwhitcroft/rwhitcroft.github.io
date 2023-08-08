---
layout: default
---
<br/>
## Shellcode: Null-Free (1)
* * *

Depending on the application you're performing the buffer overflow against, certain characters must be avoided. These are known as “bad characters” because they affect how the buffer is consumed by the target application and can break the shellcode.

For example, if the target is a web server, you may need to avoid 0x25 (%), 0x2f (/), and so on, because those characters will affect how the buffer gets parsed.

At the very least, the null byte (0x00) is often a bad character, as it acts as a delimiter between fields and may cause the payload buffer to be split or mangled.

* * *

![strcpy](/images/strcpy.png)
