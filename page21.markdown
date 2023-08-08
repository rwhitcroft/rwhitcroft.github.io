---
layout: default
---
<br/>
## Shellcode: Strings (4)
* * *
We can use a simple Python3 script to convert a string to reversed hex, the format we need in order to put it into a register and write it to memory.

The string "test1234" in reversed hex is `0x3433323174736574`.

* * *

```py
import sys

def to_reversed_hex(s):
    r = [hex(ord(c)) for c in s]
    ba = bytearray.fromhex("".join(r).replace("0x", ""))
    ba.reverse()
    return "0x" + ba.hex()

print(to_reversed_hex(sys.argv[1]))
```

```bash
$ python3 to_reversed_hex.py test1234
0x3433323174736574
```
