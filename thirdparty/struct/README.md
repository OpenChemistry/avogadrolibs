# Preface

`struct` has been used in Avogadro for unpacking
binary-file trajectories, particularly of the .trr and .dcd formats. 

Original source: https://github.com/svperbeast/struct

SHA-1 used: f200d57d52292c13391dc164e9acce9a9fce8419

# Introduction

`struct` is a binary data formatting library inspired by
'The Practice of Programming (Brian W. Kernighan, Rob Pike)' and
Python struct module.

## Format

`struct` uses following format characters (note that `struct` does not fully
support the Python struct module's format):

Table 1. Byte order

Character | Byte order             
----------|-----------
 `=`      | native                 
 `<`      | little-endian          
 `>`      | big-endian             
 `!`      | network (= big-endian) 


Table 2. Format characters

Format | C/C++ Type         | Standard size
-------|--------------------|--------------
 `b`   | char               | 1
 `B`   | unsigned char      | 1
 `h`   | short              | 2
 `H`   | unsigned short     | 2
 `i`   | int                | 4
 `I`   | unsigned int       | 4
 `l`   | long               | 4
 `L`   | unsigned long      | 4
 `q`   | long long          | 8
 `Q`   | unsigned long long | 8
 `f`   | float              | 4
 `d`   | double             | 8
 `s`   | char[]             |
 `p`   | char[]             |
 `x`   | pad bytes          |

## Pack

```c
#include "struct.h"
...
char buf1[BUFSIZ] = {'\0',};
char buf2[BUFSIZ] = {'\0',};
char str[BUFSIZ] = {'\0',};
char fmt[BUFSIZ] = {'\0',};
int val = 42;

struct_pack(buf1, "i", val);

strcpy(str, "test");
snprintf(fmt, sizeof(fmt), "%ds", strlen(str));

struct_pack(buf2, fmt, str);
```

## Unpack

```c
...
int rval;
char rstr[32] = {'\0',};

struct_unpack(buf1, "i", &rval);

struct_unpack(buf2, fmt, rstr);
```

# Install

    cd build
    cmake ..
    make
    make install

headers: `build/release/include/struct/`.
library: `build/release/lib/`.

## Test

    make test

or run `struct_test`.

valgrind memory check:

    ctest -T memcheck

# References

[The Practice of Programming (9.1 Formatting Data)](http://www.amazon.com/Practice-Programming-Addison-Wesley-Professional-Computing/dp/020161586X/ref=sr_1_1?ie=UTF8&qid=1359350725&sr=8-1&keywords=practice+of+programming "The Practice of Programming")

[Python struct](http://docs.python.org/2/library/struct.html#module-struct "Python struct module")

# License
Code released under [the MIT license](https://github.com/svperbeast/struct/blob/master/LICENSE).
