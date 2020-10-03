# CyberTalents Egypt National CTF 2020: Web - Cooki3 Sl4yer [50 points]

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-description.PNG "Description")

From the challenge description and name we can estimate that the challenge will be related to browser cookies. 

Visiting the website directs us the the main page where there is a login prompt and thats it. 

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-mainpage.PNG "Main Page")

Inspecting the source code of the page we will find an HTML comment saying that the creds are `guest:guest`, when we login using these creds we will be redirected to the gues profile.

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-guest-login.PNG "Guest Account")

Clearly we need to elevate our privilages in the web application, and since the challenge name has "cookies" in it we will first look at the cookies. Lets open burpsuite and look at the cookies in a request for convenience.

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-cookie-firsst-look.PNG "First Look at Cookies")

The cookies are `base64` encoded, when we decode them we will find that the `auth` cookie is actually a serialized php object of the class `user` in the application. 

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-second-look-at-cookie.PNG "Auth Cookie")

This is a step in the right direction, as taking unsanitized user input in the form of a php serialized object is a bad idea, [OWASP](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) explains it best.

`O:4:"User":2{s:4:"user":s:5:"guest":s:4:"pass":s:5:"guest"}` The php serialized object consists of a `User` class that has 2 variables `user` which is the username and `pass` which is the password. Searching around the internet for various techniques for authentication bypass I found [this](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md#type-juggling) which talks about authentication bypass using `type-juggling` in php serialization objects. 

We know that the username should be `admin` and the password is unknown, therefore I assumed to change the type of `pass` to boolean and give it the value of `1` which is true `O:4:"User":2{s:4:"user":s:5:"admin":s:4:"pass":b:1}` We take the base64 of that object and slap it in `auth` cookie. 

>Here is where it gets interesting!

The second cookie called `check` checks the integrity of `auth` cookie by taking the `md5sum` of the `base64` string of the php serialized object and puts the resule into `base64`... In short!

```
check_cookie = base64(md5(base64(auth_cookie)))
```

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-check-cookie2.PNG "Check Cookie")

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-check-cookie-answer.PNG "New Check Cookie")

Putting them all together, we will be able to bypass authentication and get the flag from the `admin` account

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/Cybertalents/cookie_slayer-flag.PNG "flag achieved!")

`flag{0p5_h0w_d4r3_y0u_!!}`