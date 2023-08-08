---
layout: default
---
<br/>
## Registers
* * *

A register is a small area of memory inside the processor that is used to store data and perform operations on. Some registers have specific uses, others are general purpose. Registers can be thought of like variables in a programming language.

<p style="text-align: center;"><img src="/images/registers.png"/></p>

Some basic examples of putting data into registers and performing operations on them:

```
    mov   rax, 0x4142434445464748               # put 0x4142434445464748 into rax
    mov   rbx, rax                              # put rax's value into rbx
    xor   ecx, ecx                              # zero ecx (and thus rcx)
    xchg  rbx, rcx                              # swap the contents of rbx and rcx
    mov   rdx, 5                                # put 5 into rdx
    mov   r11, 4                                # put 4 into r11
    add   rdx, r11                              # add r11 to rdx, store value in rdx
    mov   rax, 0xa                              # put 10 into rax
    mov   rsi, 5                                # put 5 into rsi
    mul   rsi                                   # multiply rax by rsi, store result in rax
    sub   rax, 0x10                             # subtract 16 from rax
    dec   rax                                   # decrement rax (subtract one)
    neg   rax                                   # negate rax (subtract from 0)
```
