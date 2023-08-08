---
layout: default
---
<br/>
## Locating Functions (1)
* * *

We can now enumerate all the functions exported by `kernel32.dll` and have their names and addresses.

We could now search for functions by name (`LoadLibraryA`), but this is cumbersome to do in shellcode and would cause identifiable strings to be present in the shellcode.

Instead, we hash the name of the function we want, iterate through the exported functions, hash each function name, and compare it to our hash. If it matches, we've found the function.

The hashing algorithm uses bit rotation and addition to generate a unique 4-byte hash of a string.

* * *

<p style="text-align: center;"><img src="/images/lf1.png"/></p>
