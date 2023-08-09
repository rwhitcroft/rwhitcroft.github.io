---
layout: default
---
<br/>
## Shellcode: Strings (2)
* * *
In C (and Windows in general), "C-strings" are one-dimensional arrays of single-byte values with a null terminator (`0x00`).

In terms of arrays, `s1` and `s2` are not the same. But in terms of C-strings, they are identical, because a string stops at the first null byte (position 6 in both).

When we declare a C-string (using double quotes), the compiler appends a null terminator automatically.

The `sizeof` operator is used to get the total size of an array. The `strlen()` function is used to get the total length of a string, not including the null terminator.

```c
    char s1[] = "hello";           // raw: { h, e, l, l, o, 0 }
    char s2[] = "hello\x00there";  // raw: { h, e, l, l, o, 0, t, h, e, r, e, 0 }

    printf("%d\n", sizeof(s1));    // prints "6"
    printf("%d\n", sizeof(s2));    // prints "12"

    printf("%d\n", strlen(s1));    // prints "5"
    printf("%d\n", strlen(s2));    // also prints "5"

```
