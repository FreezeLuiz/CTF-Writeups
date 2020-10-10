# Arpcon CTF 2020: Misc - Git The Flag (700 Points)

<p align="center">
<img src="https://github.com/FreezeLuiz/CTF-Writeups/blob/master/Misc/images/arpconctf2020-Git_the_Flag/git-the-flag_desc.PNG">
</p>

The challenge descrption didn't indicate any path to take in the challenge, however we are presented with a link that lets' us download a folder `secret` that contains a `.git` hidden folder inside.


## Recon and Analysis

```shell
kali@kali:~/Documents/arpconctf/secret$ ls -la
total 36
drwx------ 3 kali kali 4096 Oct  9 11:05 .
drwxr-xr-x 3 kali kali 4096 Oct  9 10:38 ..
-rw-r--r-- 1 kali kali   29 Oct  8 01:54 FLAG.md
drwx------ 7 kali kali 4096 Oct  8 01:55 .git
-rw-r--r-- 1 kali kali    5 Oct  8 01:02 .gitignore
-rw-r--r-- 1 kali kali   87 Oct  8 01:53 README.md
```

Looking at the folder, we see `FLAG.md` and `README.md`, the README contains the following description

>Git The Flag: A friend of ours lost his flag in the dark realms of git. Help him out.

The first thing I like to do when I get my hands on a local `.git` repository, is to check the `git log -p` option for the history of commits.

```
commit 0bc7a94e82cb1dfaad8e44eae698b39e19e219b5
Author: TheSpeedX <ggspeedx29@gmail.com>
Date:   Thu Oct 8 01:30:57 2020 +0530

    remove flag.py

diff --git a/.env b/.env
new file mode 100644
index 0000000..60796db
--- /dev/null
+++ b/.env
@@ -0,0 +1 @@
+SECRET="qyrJxvPFAbo8YDYNrCzSSj1DkHjGpLtW"
\ No newline at end of file
diff --git a/flag.py b/flag.py
deleted file mode 100644
index bfc837a..0000000
--- a/flag.py
+++ /dev/null
@@ -1 +0,0 @@
-print("arpcon{lmao}") #fake flag xD
\ No newline at end of file
```

The above commit has a string named `SECRET`, so we take note of this as we are analyzing the rest of the commits.

```
commit 8add315be212e0a2da6228144c83d5c29446d4bd
Author: TheSpeedX <ggspeedx29@gmail.com>
Date:   Thu Oct 8 01:49:06 2020 +0530

    some codes

diff --git a/main.py b/main.py
new file mode 100644
index 0000000..ab7b0ac
--- /dev/null
+++ b/main.py
@@ -0,0 +1,17 @@
+import pyaes
+import base64
+import os
+from dotenv import load_dotenv
+
+
+load_dotenv()
+SECRET = os.getenv("SECRET")
+
+flag=open("flag.txt").read()
+
+aes = pyaes.AESModeOfOperationCTR(SECRET.encode())
+ciphertext = aes.encrypt(flag)
+base_cipher = base64.b64encode(ciphertext)
+
+with open("flag.bin","wb") as file:
+  file.write(base_cipher)
```

The above commit has a python script that seems to be encrypting the content of `flag.txt` using AES, the script is using [pyaes](https://github.com/ricmoo/pyaes). And the key used in the encryption process looks like the `SECRET` we found in the commit before that.


```
commit 8f07fc8cbf00fef79887ee82dd001204545c5373
Author: TheSpeedX <ggspeedx29@gmail.com>
Date:   Thu Oct 8 01:50:32 2020 +0530

    added bin

diff --git a/flag.bin b/flag.bin
new file mode 100644
index 0000000..2e31797
--- /dev/null
+++ b/flag.bin
@@ -0,0 +1 @@
+/A8Mm2hbkL5yEuss8EelU8xaBsELiJOpilIqpp8=
```

The above commit contains the content of the AES encrypted flag, with that we have everything we need to crack this challenge.

## Solution and Flag

By now you can guess it, we should reverse the AES script so we can recreate `flag.txt` from `flag.bin` and `SECRET`.


```python
import pyaes
import base64

SECRET="qyrJxvPFAbo8YDYNrCzSSj1DkHjGpLtW"
encrypted_flag = '/A8Mm2hbkL5yEuss8EelU8xaBsELiJOpilIqpp8='

aes = pyaes.AESModeOfOperationCTR(SECRET.encode())
base_cipher = base64.b64decode(encrypted_flag)
plaintext = aes.decrypt(base_cipher)

with open("flag.txt","wb") as file:
  file.write(plaintext)
```

This script will write the flag in a file called `flag.txt`.

`arpcon{h1570RY_4lw4Y5_M4773R}`
