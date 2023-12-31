---
layout: default
---
<br/>
## Registers (1)
* * *

A register is a small area of memory inside the processor that is used to store data and perform operations on.

On 64-bit systems, registers are 64 bits (8 bytes) in size. On 32-bit systems, they're 32 bits (4 bytes). There are other, larger registers that we won't worry about.

Some registers have specific uses, others are general purpose. Registers can be thought of like variables in a programming language - they can hold values and have operations performed on them (add, subtract, shift, xor, etc).

* * *
<p style="text-align: center;"><img src="/images/registers.png"/></p>
* * *

As in the chart above, registers also have "sub-registers": smaller parts of the register. If you only want to store 1 byte, you don't need to use the full `rax` (8-byte) register.

```
    mov al, 0x7f                 # put 0x7f (1 byte) into the 1-byte sub-register of rax (least significant byte)
    mov ax, 0x8085               # put 0x8085 (2 bytes) into the 2-byte sub-register of rax
    mov eax, 0x41424344          # put 0x41424344 (4 bytes) into the 4-byte sub-register of rax
    mov rax, 0x8081828384858687  # put 0x8081828384858687 (8 bytes) using the full 8-byte rax register
```
