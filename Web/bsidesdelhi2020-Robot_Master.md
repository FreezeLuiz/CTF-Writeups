# Bsides Delhi CTF 2020: Web - Robot Master (Variable Scoring)

<p align="center">
<img src="https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/BsidesDelhi2020/Robot_Master-Description.PNG">
</p>

This challenge was a fun scavenge hunt, although it will take some time if you cannot automate specific parts of the process. 


## Recon and Analysis

Going to the link `http://15.206.202.26/` we will see a static page welcoming us to this CTF. 

```html
<!DOCTYPE html>
<html>
      <head>
          <meta charset="utf-8">
          <title> BSides Delhi </title>
      </head>
      <body>
            <body background ='cube.jpg'>
            <p style = "font-family:georgia,garamond,serif;font-size:64px;text-align:center;color:white;font-style:italic;"> Welcome to BSides Delhi CTF </p>
            <!--Are robots eating C00ki3s???-->
      </body>
</html>
```

A comment in the HTML source code will lead you down the page of searching `robots.txt`, where you will find that the file exists and contains one entry:

```
http://15.206.202.26/robots.txt

User-agent: * 
Disallow: /cookie.php
```

Going to that disallowed directory, we will be greeted with another static page.

```html
<html>
      <head>
          <meta charset="utf-8">
          <title> BSides Delhi </title>
      </head>
      <body>
            <body background ='robots.jpg'>
            <p style = "font-family:georgia,garamond,serif;font-size:64px;text-align:center;color:#DA5F45;font-style:italic;"> Yummyy!! </p>
            <!--Robots made our work difficult. Broke everything into pieces! :(-->
      </body>
</html>
```

Another comment in the HTML source code will lead us down the path where the challenge should start...


## Solution and Flag

Checking the page's cookies, we can see `Piece` and `Our_Fav_Cookie`. The latter is SHA256 hashed; if we try to crack it, we will have the cracked result of `O` (capital letter 'o').

Refreshing the page, we see that `Piece` cookie value incrementes by 1 and `Our_Fav_Cookie` value changes to a different SHA256 hash; if we try to crack the new one, we will have the result of `F`.

Now the object becomes a bit clear; there are multiple pieces of the flag and they are hidden in these SHA256 hashes. We need to get all the pieces before getting the flag. 

A simple python script can go through the website and get the cookies for us...

```python
import requests

s = requests.Session()
r = s.get(url="http://15.206.202.26/cookie.php")

with open("hashes","w") as file:
	done = []
	while True:
		r = s.get(url="http://15.206.202.26/cookie.php")
		cookie = s.cookies['Our_Fav_Cookie']
		if (s.cookies['Piece'] in done):
			break
		else:
			done.append(s.cookies['Piece'])
			file.write(cookie)
			print(cookie)
s.close()
```

Now we have a list of SHA256 hashes, each of 1 character that we will be using to get the flag. 

```
c4694f2e93d5c4e7d51f9c5deb75e6cc8be5e1114178c6a45b6fc2c566a0aa8c
f67ab10ad4e4c53121b6a5fe4da9c10ddee905b978d3788d2723d7bfacbe28a9
4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260
5c62e091b8c0565f1bafad0dad5934276143ae2ccef7a5381e8ada5b1a8d26d2
333e0a1e27815d0ceee55c473fe3dc93d56c63e3bee2b3b4aee8eed6d70191a3
8de0b3c47f112c59745f717a626932264c422a7563954872e237b223af4ad643
021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96
5c62e091b8c0565f1bafad0dad5934276143ae2ccef7a5381e8ada5b1a8d26d2
5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9
5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9
2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
...
```

Using [crackstation](https://crackstation.net/) or [hashcat](https://hashcat.net/hashcat/) we can crack these hashes, and put them together. They will form the following string:

`OFQPGS{P00x135_ne3_o35g_cy4p3_70_pu3px}`

Trying a random guess of ROT13 will yeld us the flag:

`BSDCTF{C00K135_ar3_b35t_pl4c3_70_ch3ck}`
