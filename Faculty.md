## Nmap
![nmap](https://user-images.githubusercontent.com/8396956/185782903-da589573-7152-4717-8eba-93268e515bfb.png)

Let's add faculty.htb to /etc/hosts

Now trying to discover directories of `faculty.htb`

![Dirb](https://user-images.githubusercontent.com/8396956/185783211-07acfd3e-22e5-439a-942a-c1eb6f10c8f9.png)

First go to `http://faculty.htb/`

![welcome_to_faculty](https://user-images.githubusercontent.com/8396956/185783228-3b143185-7bc2-47cb-a589-c6ce2f6853b7.png)

Trying to enter any number 

![req_burp](https://user-images.githubusercontent.com/8396956/185783239-8f17adda-e062-4429-a02b-54bbb863ef8b.png)

This is how the request looks , so add the request to file and let's try if there is SQLi 

## Sqlmap 

![sqlmap](https://user-images.githubusercontent.com/8396956/185783275-6c64b533-1ad6-4971-baf6-50e7602a6abe.png)

i already extracted the data 

![extract](https://user-images.githubusercontent.com/8396956/185783333-a9034c00-ca56-407b-9ca6-11b413251ef2.png)


Trying to crack the hash password but couldn't get anything 

So  go to `http://faculty.htb/admin` which we got from `dirb` 

![admin](https://user-images.githubusercontent.com/8396956/185783589-bf37663e-7d75-4a2c-8c26-f00957e088e1.png)

Let's go for login bypass on `admin` user with `admin' #`

![admin1](https://user-images.githubusercontent.com/8396956/185783595-47b66d59-260a-4615-924a-abcefad62898.png)

We are admin user now :) 

![adminHome](https://user-images.githubusercontent.com/8396956/185783667-39beb9f1-7089-437b-b503-4b8d952e7a9a.png)


analyzing the web pages 

we find 

![subject](https://user-images.githubusercontent.com/8396956/185784067-b116a29e-f37d-4579-b693-885012717967.png)

trying pdf functionality on same page we get


![mpdf](https://user-images.githubusercontent.com/8396956/185784101-f6558f33-9e3e-4e1f-ad3d-c1e1069945cb.png)

we can see `mpdf` !

`mPDF is a PHP library which generates PDF files from UTF-8 encoded HTML`

Searching for mpdf exploit we find https://github.com/mpdf/mpdf/issues/356 && https://www.exploit-db.com/exploits/50995


```
The PDF is dark and full of attachments  
 <annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
 
``` 

Here is how the request looks like when we try to download pdf 

![burpPDF](https://user-images.githubusercontent.com/8396956/185784450-8d7f437c-ecc8-462a-afa2-2621515ced9d.png)


We can see it is base64 encoded , so we have to encode our payload 

[CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(false)URL_Encode(false)To_Base64('A-Za-z0-9%2B/%3D'))


![pdfInj](https://user-images.githubusercontent.com/8396956/185784806-e87a2601-1962-47dd-a9c4-9420bbfb66f6.png)

Download the generated pdf we got from response [Generated PDF](http://faculty.htb/mpdf/tmp/OKKCWxjlETXStuvyaZopNGq6sL.pdf)

![Screenshot_2022-08-21_05_34_38](https://user-images.githubusercontent.com/8396956/185784895-8308240d-e938-4d82-adbf-345b88da8fac.png)

We got /etc/passwd 

Users (gbyolo, developer) 


I tried to get content of some pages , started with config.php , db_config.php but got nothing 

then i tried `db_connect.php` and yes it exists 

![db_connect](https://user-images.githubusercontent.com/8396956/185800489-92f27383-a63f-42d2-a25c-531192536b43.png)

Let's try this password for ssh 

## FootHold

![ssh_gbyolo](https://user-images.githubusercontent.com/8396956/185800607-ba78811d-8bd4-45b2-bf08-584c497fac8e.png)

## PE

let's try the first thing we do for PE :D 

`sudo -l` 

![PE1](https://user-images.githubusercontent.com/8396956/185800954-84fc2581-95f5-4da1-a3b4-b6ea63a21028.png)

We see we can run `/usr/local/bin/meta-git` as developer 


![PE2](https://user-images.githubusercontent.com/8396956/185801019-1cb49259-ff76-421a-83ee-ae829f213be0.png)




