---
layout: default
---
<br/>
## Instructions & Operands
* * *

Assembly instructions are actions to carry out, and operands are the data to operate on (often a register or memory address). Most assembly instructions require at least one operand. For example, if you want to add two numbers, `add` is the instruction, and the two registers to add are the operands.

The machine code below is what the processor consumes - the disassembly is just for humans.

While at first the machine code seems unintelligible, a pattern is visible below. If we consider that `mov eax, 0x11111111` translates to `b8 11 11 11 11`, then `b8` must be the opcode for `mov` into `eax`. The next three `mov` instructions show the same thing, except the opcode is `bb` when the destination register is `ebx`.

Shellcode *is* machine code. These bytes are what get injected and executed in a buffer overflow exploit.

<p style="text-align: center;"><img src="/images/insops.png"/></p>
