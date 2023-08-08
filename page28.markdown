---
layout: default
---
<br/>
## Shellcode: Strings (10)
* * *

Or we can write a function that takes a string, converts it to hex, reverses it, chops it up into chunks, pushes it onto the stack, and uses `xor` to null-terminate the string.

* * *

```python
def push_string(s):
    reversed_hex = reverse_hex_string(to_hex(s))
    chunks = []
    while len(reversed_hex) > 0:
        chunk = reversed_hex[-16:]
        if len(chunk) < 16:
            chunk = chunk.rjust(16, "f")
        chunks.append(chunk)
        reversed_hex = reversed_hex[:-16]

    if len(s) % 8 == 0:
        chunks.append("ffffffffffffffff")

    chunks.reverse()
    instructions = [f"mov rax, 0x{c}; push rax" for c in chunks]
    instructions.append(f"xor byte ptr [rsp+{hex(len(s))}], 0xff")

    return ';'.join(instructions)
```
