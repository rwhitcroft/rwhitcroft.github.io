---
layout: default
---
<br/>
## Shellcode: Position Independence (4)
* * *
The better solution is to use the `jmp/call/pop` shellcode trick to dynamically find the address of the desired instruction.

Both `jmp` and `call` are used to transfer execution to a different address; however, `call` first pushes the address of the next instruction onto the stack so execution can be resumed where it left off (with the `ret` instruction).

If we place the `call` immediately before the desired instruction, the return address will be pushed onto the stack and can be `pop`&apos;d off and stored in a register for later use.
* * *
<p style="text-align: center;"><img src="/images/pic3.png"/></p>
