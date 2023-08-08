---
layout: default
---
<br/>
## Export Address Table (1)
* * *

Now that we have the base address of `kernel32.dll`, we need a way to find the functions inside it, namely `LoadLibraryA()`.

Since DLLs are libraries of functions that are meant to be called externally, there must be a way to find those functions inside the DLL. This can be done by examining the DLL's Export Address Table (EAT).

* * *

<p style="text-align: center;"><img src="/images/eat1.png"/></p>
