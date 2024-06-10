# Venom Information Security Collection

<h1 align="center">
  <a href="https://github.com/kraloveckey/venom"><img src="images/img/venom-logo.png" width=150 height=140 lt="Venom"></a>
</h1>

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/kraloveckey)

[![Telegram Channel](https://img.shields.io/badge/Telegram%20Channel-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/cyber_notes)

> The collection of awesome software, tools, libraries, documents, books, resources and cool stuff about information security, penetration testing and offensive cybersecurity.

[`Information security (or InfoSec)`](https://en.wikipedia.org/wiki/Information_security), is the practice of protecting information by mitigating information risks. It is part of information risk management. It typically involves preventing or reducing the probability of unauthorized/inappropriate access to data, or the unlawful use, disclosure, disruption, deletion, corruption, modification, inspection, recording, or devaluation of information. It also involves actions intended to reduce the adverse impacts of such incidents. Information security's primary focus is the balanced protection of the data confidentiality, data integrity, and data availability of data while maintaining a focus on efficient policy implementation, all without hampering organization productivity.

[`Penetration testing (or PenTesting)`](https://en.wikipedia.org/wiki/Penetration_test) is the practice of launching authorized, simulated attacks against computer systems and their physical infrastructure to expose potential security weaknesses and vulnerabilities. The purpose of this simulated attack is to identify any weak spots in a system’s defenses which attackers could take advantage of. This is like a bank hiring someone to dress as a burglar and try to break into their building and gain access to the vault. If the ‘burglar’ succeeds and gets into the bank or the vault, the bank will gain valuable information on how they need to tighten their security measures. Should you discover a vulnerability, please follow [this guidance](https://kb.cert.org/vuls/guidance/) to report it responsibly.

---------

Your contributions and suggestions are heartily welcome. Please, check the [Guide](CONTRIBUTING.md) for more details.

------

## Overview
- [Venom Information Security Collection](#venom-information-security-collection)
  - [Overview](#overview)
- [TOOLS AND RESOURCES](#tools-and-resources)
  - [Analysis Tools](#analysis-tools)
  - [Anonymity / Tor Tools](#anonymity--tor-tools)
  - [Anti-virus Evasion Tools](#anti-virus-evasion-tools)
  - [Cloud Platform Attack Tools](#cloud-platform-attack-tools)
  - [Collaboration Tools](#collaboration-tools)
  - [CTF Tools / Resources / Courses](#ctf-tools--resources--courses)
  - [Datastores](#datastores)
  - [Emails](#emails)
  - [Endpoint](#endpoint)
    - [Anti-Virus / Anti-Malware](#anti-virus--anti-malware)
    - [Authentication](#authentication)
    - [Configuration Management](#configuration-management)
    - [Mobile / Android / iOS](#mobile--android--ios)
    - [Forensics](#forensics)
  - [Exfiltration Tools](#exfiltration-tools)
  - [Exploit Development Tools](#exploit-development-tools)
  - [Hash Cracking Tools](#hash-cracking-tools)
  - [Hex Editors](#hex-editors)
  - [Intentionally Vulnerable Systems](#intentionally-vulnerable-systems)
  - [Multi-paradigm Frameworks](#multi-paradigm-frameworks)
  - [Network](#network)
    - [Anti-Spam](#anti-spam)
    - [DDoS Tools](#ddos-tools)
    - [Firewall](#firewall)
    - [IDS / IPS / Host IDS / Host IPS](#ids--ips--host-ids--host-ips)
    - [IP](#ip)
    - [Honey Pot / Honey Net](#honey-pot--honey-net)
    - [Monitoring / Logging / Event Management](#monitoring--logging--event-management)
    - [Network Reconnaissance Tools](#network-reconnaissance-tools)
    - [Network Traffic Replay and Editing Tools](#network-traffic-replay-and-editing-tools)
    - [Network Vulnerability Scanners](#network-vulnerability-scanners)
    - [Protocol Analyzers / Sniffers](#protocol-analyzers--sniffers)
    - [Proxies and Machine-in-the-Middle (MITM) Tools](#proxies-and-machine-in-the-middle-mitm-tools)
    - [Transport Layer Security Tools](#transport-layer-security-tools)
    - [VPN](#vpn)
    - [Wireless Network Tools](#wireless-network-tools)
  - [Open Sources Intelligence (OSINT)](#open-sources-intelligence-osint)
    - [Dorking tools](#dorking-tools)
    - [Email, phone search and analysis tools](#email-phone-search-and-analysis-tools)
    - [Metadata harvesting and analysis](#metadata-harvesting-and-analysis)
    - [Network device discovery tools](#network-device-discovery-tools)
    - [OSINT Online Resources](#osint-online-resources)
    - [Source code repository searching tools](#source-code-repository-searching-tools)
    - [Web application and resource analysis tools](#web-application-and-resource-analysis-tools)
  - [Operating Systems](#operating-systems)
    - [Linux](#linux)
      - [Linux Online Resources](#linux-online-resources)
    - [macOS](#macos)
    - [Windows](#windows)
    - [Operating System Distributions](#operating-system-distributions)
    - [Online Operating Systems Resources](#online-operating-systems-resources)
  - [Penetration Testing](#penetration-testing)
    - [Addintional Penetration Tools](#addintional-penetration-tools)
    - [Online Penetration Testing Resources](#online-penetration-testing-resources)
    - [Passwords](#passwords)
    - [Penetration Testing Report Templates](#penetration-testing-report-templates)
  - [Physical Access Tools](#physical-access-tools)
  - [Reverse Engineering](#reverse-engineering)
  - [Samba Enumerating](#samba-enumerating)
  - [Social Engineering](#social-engineering)
  - [Static Analyzers](#static-analyzers)
  - [Steganography Tools](#steganography-tools)
  - [Threat Intelligence](#threat-intelligence)
  - [Vulnerability Databases](#vulnerability-databases)
  - [Web](#web)
    - [Web Accessible Source Code Ripping Tools](#web-accessible-source-code-ripping-tools)
    - [Web Application Firewall](#web-application-firewall)
    - [Web Exploitation](#web-exploitation)
    - [Web File Inclusion Tools](#web-file-inclusion-tools)
    - [Web Injection Tools](#web-injection-tools)
    - [Web Path Discovery / Bruteforcing Tools](#web-path-discovery--bruteforcing-tools)
    - [Web Proxies Intercepting](#web-proxies-intercepting)
    - [Web Shells / C2 Frameworks](#web-shells--c2-frameworks)
    - [Web Subdomains](#web-subdomains)
    - [Web Vulnerability Scanners](#web-vulnerability-scanners)
  - [Web Servers](#web-servers)
  - [Useful Resources](#useful-resources)
    - [Documents / Images](#documents--images)
    - [Security Awesome Lists](#security-awesome-lists)
    - [Other Lists](#other-lists)
  - [Other](#other)
  - [Contributing](#contributing)

------

# TOOLS AND RESOURCES

## Analysis Tools

**[`^        back to top        ^`](#overview)**

* [`CyberChef`](https://gchq.github.io/CyberChef/) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis.
* [`DocBleach`](https://github.com/docbleach/DocBleach) - An open-source Content Disarm & Reconstruct software sanitizing Office, PDF and RTF Documents.
* [`ExifTool`](https://www.sno.phy.queensu.ca/~phil/exiftool/) - Platform-independent Perl library plus a command-line application for reading, writing and editing meta information in a wide variety of files.
* [`Hachoir`](https://hachoir.readthedocs.io/) - Python library to view and edit a binary stream as tree of fields and tools for metadata extraction.
* [`Kaitai Struct`](http://kaitai.io/) - File formats and network protocols dissection language and web IDE, generating parsers in C++, C#, Java, JavaScript, Perl, PHP, Python, Ruby.
* [`peepdf`](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool) - Python tool to explore PDF files in order to find out if the file can be harmful or not.
* [`Veles`](https://codisec.com/veles/) - Binary data visualization and analysis tool.

------

## Anonymity / Tor Tools

**[`^        back to top        ^`](#overview)**

* [`dos-over-tor`](https://github.com/skizap/dos-over-tor) - Proof of concept denial of service over Tor stress test tool.
* [`I2P`](https://geti2p.net/) - The Invisible Internet Project.
* [`kalitorify`](https://github.com/brainfuckSec/kalitorify) - Transparent proxy through Tor for Kali Linux OS.
* [`Metadata Anonymization Toolkit (MAT)`](https://0xacab.org/jvoisin/mat2) - Metadata removal tool, supporting a wide range of commonly used file formats, written in Python3.
* [`Nipe`](https://github.com/GouveaHeitor/nipe) - Script to redirect all traffic from the machine to the Tor network.
* [`OnionScan`](https://onionscan.org/) - Tool for investigating the Dark Web by finding operational security issues introduced by Tor hidden service operators.
* [`Tails`](https://tails.boum.org/) - Live operating system aiming to preserve your privacy and anonymity.
* [`Tor`](https://www.torproject.org/) - Free software and onion routed overlay network that helps you defend against traffic analysis.
* [`What Every Browser Knows About You`](http://webkay.robinlinus.com/) - Comprehensive detection page to test your own Web browser's configuration for privacy and identity leaks.

------

## Anti-virus Evasion Tools

**[`^        back to top        ^`](#overview)**

* [`AntiVirus Evasion Tool (AVET)`](https://github.com/govolution/avet) - Post-process exploits containing executable files targeted for Windows machines to avoid being recognized by antivirus software.
* [`CarbonCopy`](https://github.com/paranoidninja/CarbonCopy) - Tool that creates a spoofed certificate of any online website and signs an Executable for AV evasion.
* [`Hyperion`](http://nullsecurity.net/tools/binary.html) - Runtime encryptor for 32-bit portable executables ("PE `.exe`s").
* [`peCloakCapstone`](https://github.com/v-p-b/peCloakCapstone) - Multi-platform fork of the `peCloak.py` automated malware antivirus evasion tool.
* [`Shellter`](https://www.shellterproject.com/) - Dynamic shellcode injection tool, and the first truly dynamic PE infector ever created.
* [`UniByAv`](https://github.com/Mr-Un1k0d3r/UniByAv) - Simple obfuscator that takes raw shellcode and generates Anti-Virus friendly executables by using a brute-forcable, 32-bit XOR key.
* [`Veil`](https://www.veil-framework.com/) - Generate metasploit payloads that bypass common anti-virus solutions.

------

## Cloud Platform Attack Tools

**[`^        back to top        ^`](#overview)**

See also *[`HackingThe.cloud`](https://hackingthe.cloud/)*.

* [`Cloud Container Attack Tool (CCAT)`](https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/) - Tool for testing security of container environments.
* [`CloudHunter`](https://github.com/belane/CloudHunter) - Looks for AWS, Azure and Google cloud storage buckets and lists permissions for vulnerable buckets.
* [`Cloudsplaining`](https://cloudsplaining.readthedocs.io/) - Identifies violations of least privilege in AWS IAM policies and generates a pretty HTML report with a triage worksheet.
* [`Endgame`](https://endgame.readthedocs.io/) - AWS Pentesting tool that lets you use one-liner commands to backdoor an AWS account's resources with a rogue AWS account.
* [`GCPBucketBrute`](https://github.com/RhinoSecurityLabs/GCPBucketBrute) - Script to enumerate Google Storage buckets, determine what access you have to them, and determine if they can be privilege escalated.

------

## Collaboration Tools

**[`^        back to top        ^`](#overview)**

* [`Dradis`](https://dradisframework.com) - Open-source reporting and collaboration tool for IT security professionals.
* [`Lair`](https://github.com/lair-framework/lair/wiki) - Reactive attack collaboration framework and web application built with meteor.
* [`Pentest Collaboration Framework (PCF)`](https://gitlab.com/invuls/pentest-projects/pcf) - Open source, cross-platform, and portable toolkit for automating routine pentest processes with a team.
* [`Reconmap`](https://reconmap.org/) - Open-source collaboration platform for InfoSec professionals that streamlines the pentest process.
* [`RedELK`](https://github.com/outflanknl/RedELK) - Track and alarm about Blue Team activities while providing better usability in long term offensive operations.

------

## CTF Tools / Resources / Courses

**[`^        back to top        ^`](#overview)**

See also *[`Awesome CTF`](https://github.com/apsdehal/awesome-ctf)* - A curated list of CTF frameworks, libraries, resources and software.
See also *[`Awesome Cyber Skills`](https://github.com/joe-shenouda/awesome-cyber-skills)* - A curated list of hacking environments where you can train your cyber skills legally and safely.

* [`Arizona Cyber Warfare Range`](http://azcwr.org/) - 24x7 live fire exercises for beginners through real world operations; capability for upward progression into the real world of cyber warfare.
* [`Ciphey`](https://github.com/ciphey/ciphey) - Automated decryption tool using artificial intelligence and natural language processing.
* [`CTF Field Guide`](https://trailofbits.github.io/ctf/) - Everything you need to win your next CTF competition.
* [`Cybrary`](http://cybrary.it) - Free courses in ethical hacking and advanced penetration testing. Advanced penetration testing courses are based on the book 'Penetration Testing for Highly Secured Environments'.
* [`Hack The Box`](https://www.hackthebox.com/) - An online cybersecurity training platform allowing IT professionals to advance their ethical hacking skills and be part of a worldwide community.
* [`Offensive Security Training`](https://www.offensive-security.com/information-security-training/) - Training from BackTrack/Kali developers.
* [`Open Security Training`](http://opensecuritytraining.info/) - Training material for computer security classes.
* [`OverTheWire War Games`](https://overthewire.org/wargames/bandit/bandit0.html) - The wargames offered by the OverTheWire community can help you to learn and practice security concepts in the form of fun-filled games.
* [`PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads and bypass for Web Application Security and Pentest/CTF
* [`Roppers Academy Training`](https://www.hoppersroppers.org/training.html) - Free courses on computing and security fundamentals designed to train a beginner to crush their first CTF.
* [`RsaCtfTool`](https://github.com/Ganapati/RsaCtfTool) - Decrypt data enciphered using weak RSA keys, and recover private keys from public keys using a variety of automated attacks.
* [`SANS Security Training`](http://www.sans.org/) - Computer Security Training & Certification.
* [`shellpop`](https://github.com/0x00-0x00/shellpop) - Easily generate sophisticated reverse or bind shell commands to help you save time during penetration tests.
* [`TryHackMe`](https://tryhackme.com/) - Online platform for learning cyber security, using hands-on exercises and labs.

------

## Datastores

**[`^        back to top        ^`](#overview)**

* [`acra`](https://github.com/cossacklabs/acra) - Database security suite: proxy for data protection with transparent "on the fly" data encryption, data masking and tokenization, SQL firewall (SQL injections prevention), intrusion detection system.
* [`aws-vault`](https://github.com/99designs/aws-vault) - Store AWS credentials in the OSX Keychain or an encrypted file
* [`blackbox`](https://github.com/StackExchange/blackbox) - Safely store secrets in a VCS repo using GPG
* [`chamber`](https://github.com/segmentio/chamber) - Store secrets using AWS KMS and SSM Parameter Store
* [`confidant`](https://github.com/lyft/confidant) - Stores secrets in AWS DynamoDB, encrypted at rest and integrates with IAM
* [`credstash`](https://github.com/fugue/credstash) - Store secrets using AWS KMS and DynamoDB
* [`databunker`](https://databunker.org/) - Databunker is an address book on steroids for storing personal data. GDPR and encryption are out of the box.
* [`dotgpg`](https://github.com/ConradIrwin/dotgpg) - A tool for backing up and versioning your production secrets or shared passwords securely and easily.
* [`nextcloud`](https://github.com/nextcloud) - A safe home for all your data. 
* [`LunaSec`](https://github.com/lunasec-io/lunasec) - Database for PII with automatic encryption/tokenization, sandboxed components for handling data, and centralized authorization controls.
* [`passbolt`](https://www.passbolt.com/) - The password manager your team was waiting for. Free, open source, extensible, based on OpenPGP.
* [`passpie`](https://github.com/marcwebbie/passpie) - Multiplatform command-line password manager
* [`pwndrop`](https://github.com/kgretzky/pwndrop) - Self-deployable file hosting service for red teamers, allowing to easily upload and share payloads over HTTP and WebDAV.
* [`redoctober`](https://github.com/cloudflare/redoctober) - Server for two-man rule style file encryption and decryption.
* [`Safe`](https://github.com/starkandwayne/safe) - A Vault CLI that makes reading from and writing to the Vault easier to do.
* [`Sops`](https://github.com/mozilla/sops) - An editor of encrypted files that supports YAML, JSON and BINARY formats and encrypts with AWS KMS and PGP.
* [`Vault`](https://www.vaultproject.io/) - An encrypted datastore secure enough to hold environment and application secrets.
* [`Yopass`](https://github.com/jhaals/yopass) - Secure sharing of secrets, passwords and files.
------

## Emails

**[`^        back to top        ^`](#overview)**

* [`10minutemail`](https://10minutemail.com/) - Free Temporary Email.
* [`mail-tester`](https://www.mail-tester.com/) - Test the Spammyness of your Emails.
* [`dkimvalidator`](https://dkimvalidator.com/) - DKIM, SPF, SpamAssassin Email Validator.
* [`spf-policy-tester`](https://vamsoft.com/support/tools/spf-policy-tester) - SPF Policy Tester.
* [`spf`](https://mxtoolbox.com/spf.aspx) - SPF Record Check - Lookup SPF Records.

------

## Endpoint

### Anti-Virus / Anti-Malware

**[`^        back to top        ^`](#overview)**

See also *[`Awesome Malware Analysis`](https://github.com/rshipp/awesome-malware-analysis)* - A curated list of awesome malware analysis tools and resources.

* [`ClamAv`](http://www.clamav.net/) - ClamAV® is an open-source antivirus engine for detecting trojans, viruses, malware & other malicious threats.
* [`Fastfinder`](https://github.com/codeyourweb/fastfinder) - Fast customisable cross-platform suspicious file finder. Supports md5/sha1/sha256 hashs, litteral/wildcard strings, regular expressions and YARA rules. Can easily be packed to be deployed on any windows / linux host.
* [`Linux Malware Detect`](https://www.rfxn.com/projects/linux-malware-detect/) - A malware scanner for Linux designed around the threats faced in shared hosted environments.
* [`LOKI`](https://github.com/Neo23x0/Loki) - Simple Indicators of Compromise and Incident Response Scanner.
* [`rkhunter`](http://rkhunter.sourceforge.net/) - A Rootkit Hunter for Linux.

### Authentication

**[`^        back to top        ^`](#overview)**

* [`google-authenticator`](https://github.com/google/google-authenticator) - The Google Authenticator project includes implementations of one-time passcode generators for several mobile platforms, as well as a pluggable authentication module (PAM). One-time passcodes are generated using open standards developed by the Initiative for Open Authentication (OATH) (which is unrelated to OAuth). These implementations support the HMAC-Based One-time Password (HOTP) algorithm specified in RFC 4226 and the Time-based One-time Password (TOTP) algorithm specified in RFC 6238. [Tutorials: How to set up two-factor authentication for SSH login on Linux](http://xmodulo.com/two-factor-authentication-ssh-login-linux.html)
* [`FreeOTP`](https://freeotp.github.io/) - A two-factor authentication application for systems utilizing one-time password protocols. Tokens can be added easily by scanning a QR code.
* [`Stegcloak`](https://github.com/kurolabs/stegcloak) - Securely assign Digital Authenticity to any written text

### Configuration Management

**[`^        back to top        ^`](#overview)**

* [`Fleet device management`](https://github.com/fleetdm/fleet) - Fleet is the lightweight, programmable telemetry platform for servers and workstations. Get comprehensive, customizable data from all your devices and operating systems.
* [`GLPi`](https://github.com/glpi-project/glpi) - Free Asset and IT Management Software package, Data center management, ITIL Service Desk, licenses tracking and software auditing.
* [`Rudder`](http://www.rudder-project.org/) - Rudder is an easy to use, web-driven, role-based solution for IT Infrastructure Automation & Compliance. Automate common system administration tasks (installation, configuration); Enforce configuration over time (configuring once is good, ensuring that configuration is valid and automatically fixing it is better); Inventory of all managed nodes; Web interface to configure and manage nodes and their configuration; Compliance reporting, by configuration and/or by node.

### Mobile / Android / iOS

**[`^        back to top        ^`](#overview)**

See also *[`android-security-awesome`](https://github.com/ashishb/android-security-awesome)* - A collection of android security related resources. A lot of work is happening in academia and industry on tools to perform dynamic analysis, static analysis and reverse engineering of android apps.
See also *[`Android Exploits`](https://github.com/sundaysec/Android-Exploits)* - Guide on Android Exploitation and Hacks.

* [`AMExtractor`](https://github.com/ir193/AMExtractor) - AMExtractor can dump out the physical content of your Android device even without kernel source code.
* [`Android Storage Extractor`](https://github.com/51j0/Android-Storage-Extractor) - A tool to extract local data storage of an Android application in one click.
* [`Apktool`](https://github.com/iBotPeaches/Apktool) - A tool for reverse engineering Android apk files.
* [`dotPeek`](https://www.jetbrains.com/decompiler/) - Free-of-charge standalone tool based on ReSharper's bundled decompiler.
* [`enjarify`](https://github.com/Storyyeller/enjarify) - A tool for translating Dalvik bytecode to equivalent Java bytecode.
* [`frida`](https://github.com/frida/frida) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
* [`hardened_malloc`](https://github.com/GrapheneOS/hardened_malloc) - Hardened allocator designed for modern systems. It has integration into Android's Bionic libc and can be used externally with musl and glibc as a dynamic library for use on other Linux-based platforms. It will gain more portability / integration over time.
* [`jadx`](https://github.com/skylot/jadx) - Command line and GUI tools for produce Java source code from Android Dex and Apk files.
* [`Mobile Security Wiki`](https://mobilesecuritywiki.com/) - A collection of mobile security resources.
* [`OSX Security Awesome`](https://github.com/kai5263499/osx-security-awesome) - A collection of OSX and iOS security resources
* [`OWASP Mobile Security Testing Guide`](https://github.com/OWASP/owasp-mstg) - A comprehensive manual for mobile app security testing and reverse engineering.
* [`symbiote`](https://github.com/hasanfirnas/symbiote) - Your target's phone's front and back cameras can be accessed by sending a link.
* [`Quark-Engine`](https://github.com/quark-engine/quark-engine) - An Obfuscation-Neglect Android Malware Scoring System.
* [`reFlutter`](https://github.com/ptswarm/reFlutter) - Flutter Reverse Engineering Framework.
* [`SecMobi Wiki`](http://wiki.secmobi.com/) - A collection of mobile security resources which including articles, blogs, books, groups, projects, tools and conferences. *
* [`Themis`](https://github.com/cossacklabs/themis) - High-level multi-platform cryptographic framework for protecting sensitive data: secure messaging with forward secrecy and secure data storage (AES256GCM), suits for building end-to-end encrypted applications.
* [`UDcide`](https://github.com/UDcide/udcide) - Android Malware Behavior Editor.

### Forensics

**[`^        back to top        ^`](#overview)**

See also *[`Awesome Forensics`](https://github.com/Cugu/awesome-forensics)* - Free (mostly open source) forensic analysis tools and resources.

* [`grr`](https://github.com/google/grr) - GRR Rapid Response is an incident response framework focused on remote live forensics.
* [`ir-rescue`](https://github.com/diogo-fernan/ir-rescue) - *ir-rescue* is a Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
* [`LiME`](https://github.com/504ensicsLabs/LiME.git) - Linux Memory Extractor
* [`Logdissect`](https://github.com/dogoncouch/logdissect) - CLI utility and Python API for analyzing log files and other data.
* [`Maigret`](https://github.com/soxoj/maigret) - Maigret collect a dossier on a person by username only, checking for accounts on a huge number of sites and gathering all the available information from web pages.
* [`Meerkat`](https://github.com/TonyPhipps/Meerkat) - PowerShell-based Windows artifact collection for threat hunting and incident response.
* [`mig`](http://mig.mozilla.org/) - MIG is a platform to perform investigative surgery on remote endpoints. It enables investigators to obtain information from large numbers of systems in parallel, thus accelerating investigation of incidents and day-to-day operations security.
* [`Rekall`](https://github.com/google/rekall) - The Rekall Framework is a completely open collection of tools, implemented in Python under the Apache and GNU General Public License, for the extraction and analysis of digital artifacts computer systems.
* [`Volatility`](https://github.com/volatilityfoundation/volatility) - Python based memory extraction and analysis framework.
* [`url-sandbox`](https://github.com/qeeqbox/url-sandbox) - Scalable URL Sandbox for analyzing URLs and Domains from phishing attacks.

------

## Exfiltration Tools

**[`^        back to top        ^`](#overview)**

* [`DET`](https://github.com/sensepost/DET) - Proof of concept to perform data exfiltration using either single or multiple channel(s) at the same time.
* [`dnscat2`](https://github.com/iagox86/dnscat2) - Tool designed to create an encrypted command and control channel over the DNS protocol, which is an effective tunnel out of almost every network.
* [`Iodine`](https://code.kryo.se/iodine/) - Tunnel IPv4 data through a DNS server; useful for exfiltration from networks where Internet access is firewalled, but DNS queries are allowed.
* [`pwnat`](https://github.com/samyk/pwnat) - Punches holes in firewalls and NATs.
* [`QueenSono`](https://github.com/ariary/QueenSono) - Client/Server Binaries for data exfiltration with ICMP. Useful in a network where ICMP protocol is less monitored than others (which is a common case).
* [`tgcd`](http://tgcd.sourceforge.net/) - Simple Unix network utility to extend the accessibility of TCP/IP based network services beyond firewalls.
* [`TrevorC2`](https://github.com/trustedsec/trevorc2) - Client/server tool for masking command and control and data exfiltration through a normally browsable website, not typical HTTP POST requests.

------

## Exploit Development Tools

**[`^        back to top        ^`](#overview)**

See also *[`Reverse Engineering`](#reverse-engineering)*.

* [`Magic Unicorn`](https://github.com/trustedsec/unicorn) - Shellcode generator for numerous attack vectors, including Microsoft Office macros, PowerShell, HTML applications (HTA), or `certutil` (using fake certificates).
* [`peda`](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB.
* [`Pwntools`](https://github.com/Gallopsled/pwntools) - Rapid exploit development framework built for use in CTFs.
* [`VcenterKit`](https://github.com/W01fh4cker/VcenterKit) - Vcenter Comprehensive Penetration and Exploitation Toolkit.
* [`Wordpress Exploit Framework`](https://github.com/rastating/wordpress-exploit-framework) - Ruby framework for developing and using modules which aid in the penetration testing of WordPress powered websites and systems.

------

## Hash Cracking Tools

**[`^        back to top        ^`](#overview)**

* [`BruteForce Wallet`](https://github.com/glv2/bruteforce-wallet) - Find the password of an encrypted wallet file (i.e. `wallet.dat`).
* [`CeWL`](https://digi.ninja/projects/cewl.php) - Generates custom wordlists by spidering a target's website and collecting unique words.
* [`crackstation`](https://crackstation.net/) - Password Hash Cracker.
* [`duplicut`](https://github.com/nil0x42/duplicut) - Quickly remove duplicates, without changing the order, and without getting OOM on huge wordlists.
* [`GoCrack`](https://github.com/fireeye/gocrack) - Management Web frontend for distributed password cracking sessions using hashcat (or other supported tools) written in Go.
* [`Hashcat`](http://hashcat.net/hashcat/) - The more fast hash cracker.
* [`hate_crack`](https://github.com/trustedsec/hate_crack) - Tool for automating cracking methodologies through Hashcat.
* [`John the Ripper`](http://www.openwall.com/john/) - Fast password cracker.
* [`JWT Cracker`](https://github.com/lmammino/jwt-cracker) - Simple HS256 JSON Web Token (JWT) token brute force cracker.
* [`pydictor`](https://github.com/LandGrey/pydictor?tab=readme-ov-file) - A powerful and useful hacker dictionary builder for a brute-force attack.
* [`Rar Crack`](http://rarcrack.sourceforge.net) - RAR bruteforce cracker.

------

## Hex Editors

**[`^        back to top        ^`](#overview)**

* [`Bless`](https://github.com/bwrsandman/Bless) - High quality, full featured, cross-platform graphical hex editor written in Gtk#.
* [`Frhed`](http://frhed.sourceforge.net/) - Binary file editor for Windows.
* [`Hex Fiend`](http://ridiculousfish.com/hexfiend/) - Fast, open source, hex editor for macOS with support for viewing binary diffs.
* [`HexEdit.js`](https://hexed.it) - Browser-based hex editing.
* [`hexedit`](https://github.com/pixel/hexedit) - Simple, fast, console-based hex editor.
* [`Hexinator`](https://hexinator.com/) - World's finest (proprietary, commercial) Hex Editor.
* [`wxHexEditor`](http://www.wxhexeditor.org/) - Free GUI hex editor for GNU/Linux, macOS, and Windows.

------

## Intentionally Vulnerable Systems

**[`^        back to top        ^`](#overview)**

* [`Damn Vulnerable Web Application (DVWA)`](https://hub.docker.com/r/citizenstig/dvwa/) - `docker pull citizenstig/dvwa`.
* [`OWASP Juice Shop`](https://github.com/bkimminich/juice-shop#docker-container--) - `docker pull bkimminich/juice-shop`.
* [`OWASP Mutillidae II Web Pen-Test Practice Application`](https://hub.docker.com/r/citizenstig/nowasp/) - `docker pull citizenstig/nowasp`.
* [`OWASP NodeGoat`](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker) - `docker-compose build && docker-compose up`.
* [`OWASP Security Shepherd`](https://hub.docker.com/r/ismisepaul/securityshepherd/) - `docker pull ismisepaul/securityshepherd`.
* [`OWASP WebGoat Project 7.1 docker image`](https://hub.docker.com/r/webgoat/webgoat-7.1/) - `docker pull webgoat/webgoat-7.1`.
* [`OWASP WebGoat Project 8.0 docker image`](https://hub.docker.com/r/webgoat/webgoat-8.0/) - `docker pull webgoat/webgoat-8.0`.
* [`Vulnerability as a service: Heartbleed`](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/) - `docker pull hmlio/vaas-cve-2014-0160`.
* [`Vulnerability as a service: SambaCry`](https://hub.docker.com/r/vulnerables/cve-2017-7494/) - `docker pull vulnerables/cve-2017-7494`.
* [`Vulnerability as a service: Shellshock`](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/) - `docker pull hmlio/vaas-cve-2014-6271`.
* [`Vulnerable WordPress Installation`](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/) - `docker pull wpscanteam/vulnerablewordpress`.

------

## Multi-paradigm Frameworks

**[`^        back to top        ^`](#overview)**

* [`Armitage`](http://fastandeasyhacking.com/) - Java-based GUI front-end for the Metasploit Framework.
* [`AutoSploit`](https://github.com/NullArray/AutoSploit) - Automated mass exploiter, which collects target by employing the Shodan API and programmatically chooses Metasploit exploit modules based on the Shodan query.
* [`Decker`](https://github.com/stevenaldinger/decker) - Penetration testing orchestration and automation framework, which allows writing declarative, reusable configurations capable of ingesting variables and using outputs of tools it has run as inputs to others.
* [`Faraday`](https://github.com/infobyte/faraday) - Multiuser integrated pentesting environment for red teams performing cooperative penetration tests, security audits, and risk assessments.
* [`Metasploit Framework`](https://github.com/rapid7/metasploit-framework) - A tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
* [`Metasploit`](https://www.metasploit.com/) - Software for offensive security teams to help verify vulnerabilities and manage security assessments.
* [`Pupy`](https://github.com/n1nj4sec/pupy) - Cross-platform (Windows, Linux, macOS, Android) remote administration and post-exploitation tool.

------

## Network

* [`network-segmentation-cheat-sheet`](https://github.com/sergiomarotco/Network-segmentation-cheat-sheet) - This project was created to publish the best practices for segmentation of the corporate network of any company. In general, the schemes in this project are suitable for any company.

**[`^        back to top        ^`](#overview)**

* [`CrackMapExec`](https://github.com/byt3bl33d3r/CrackMapExec) - Swiss army knife for pentesting networks.
* [`dnstwist`](https://github.com/elceef/dnstwist) - Domain name permutation engine for detecting typo squatting, phishing and corporate espionage.
* [`dsniff`](https://www.monkey.org/~dugsong/dsniff/) - Collection of tools for network auditing and pentesting.
* [`IKEForce`](https://github.com/SpiderLabs/ikeforce) - Command line IPSEC VPN brute forcing tool for Linux that allows group name/ID enumeration and XAUTH brute forcing capabilities.
* [`impacket`](https://github.com/CoreSecurity/impacket) - Collection of Python classes for working with network protocols.
* [`Intercepter-NG`](http://sniff.su/) - Multifunctional network toolkit.
* [`Legion`](https://github.com/GoVanguard/legion) - Graphical semi-automated discovery and reconnaissance framework based on Python 3 and forked from SPARTA.
* [`Ncrack`](https://nmap.org/ncrack/) - High-speed network authentication cracking tool built to help companies secure their networks by proactively testing all their hosts and networking devices for poor passwords.
* [`NetExec`](https://github.com/Pennyw0rth/NetExec) - Network service exploitation tool that helps automate assessing the security of large networks.
* [`Network-Tools.com`](http://network-tools.com/) - Website offering an interface to numerous basic network utilities like `ping`, `traceroute`, `whois`, and more.
* [`pivotsuite`](https://github.com/RedTeamOperations/PivotSuite) - Portable, platform independent and powerful network pivoting toolkit.
* [`Praeda`](http://h.foofus.net/?page_id=218) - Automated multi-function printer data harvester for gathering usable data during security assessments.
* [`Printer Exploitation Toolkit (PRET)`](https://github.com/RUB-NDS/PRET) - Tool for printer security testing capable of IP and USB connectivity, fuzzing, and exploitation of PostScript, PJL, and PCL printer language features.
* [`routersploit`](https://github.com/reverse-shell/routersploit) - Open source exploitation framework similar to Metasploit but dedicated to embedded devices.
* [`rshijack`](https://github.com/kpcyrd/rshijack) - TCP connection hijacker, Rust rewrite of `shijack`.
* [`SigPloit`](https://github.com/SigPloiter/SigPloit) - Signaling security testing framework dedicated to telecom security for researching vulnerabilites in the signaling protocols used in mobile (cellular phone) operators.
* [`Smart Install Exploitation Tool (SIET)`](https://github.com/Sab0tag3d/SIET) - Scripts for identifying Cisco Smart Install-enabled switches on a network and then manipulating them.
* [`SPARTA`](https://sparta.secforce.com/) - Graphical interface offering scriptable, configurable access to existing network infrastructure scanning and enumeration tools.
* [`THC Hydra`](https://github.com/vanhauser-thc/thc-hydra) - Online password cracking tool with built-in support for many network protocols, including HTTP, SMB, FTP, telnet, ICQ, MySQL, LDAP, IMAP, VNC, and more.
* [`Tsunami`](https://github.com/google/tsunami-security-scanner) - General purpose network security scanner with an extensible plugin system for detecting high severity vulnerabilities with high confidence.
* [`Zarp`](https://github.com/hatRiot/zarp) - Network attack tool centered around the exploitation of local networks.

### Anti-Spam

**[`^        back to top        ^`](#overview)**

* [`rspamd`](https://github.com/rspamd/rspamd) - Fast, free and open-source spam filtering system.
* [`Scammer-List`](https://scammerlist.now.sh/) - A free open source AI based Scam and Spam Finder with a free API
* [`Spam Scanner`](https://github.com/spamscanner) - Anti-Spam Scanning Service and Anti-Spam API.
* [`SpamAssassin`](https://spamassassin.apache.org/) - A powerful and popular email spam filter employing a variety of detection technique.

### DDoS Tools

**[`^        back to top        ^`](#overview)**

* [`Anevicon`](https://github.com/rozgo/anevicon) - Powerful UDP-based load generator, written in Rust.
* [`DDoS-Ripper`](https://github.com/palahsu/DDoS-Ripper) - Distributable Denied-of-Service (DDOS) attack server that cuts off targets or surrounding infrastructure in a flood of Internet traffic.
* [`Ddosify`](https://github.com/ddosify/ddosify) - Effortless Kubernetes Monitoring and Performance Testing. Available on CLI, Self-Hosted, and Cloud.
* [`D(HE)ater`](https://github.com/Balasys/dheater) - D(HE)ater sends forged cryptographic handshake messages to enforce the Diffie-Hellman key exchange.
* [`Finshir`](https://github.com/isgasho/finshir) - A coroutines-driven Low & Slow traffic generator, written in Rust.
* [`HOIC`](https://sourceforge.net/projects/high-orbit-ion-cannon/) - Updated version of Low Orbit Ion Cannon, has 'boosters' to get around common counter measures.
* [`Impulse`](https://github.com/LimerBoy/Impulse) - Modern Denial-of-service ToolKit.
* [`Low Orbit Ion Canon (LOIC)`](https://github.com/NewEraCracker/LOIC) - Open source network stress tool written for Windows.
* [`Memcrashed`](https://github.com/649/Memcrashed-DDoS-Exploit) - DDoS attack tool for sending forged UDP packets to vulnerable Memcached servers obtained using Shodan API.
* [`SlowLoris`](https://github.com/gkbrk/slowloris) - DoS tool that uses low bandwidth on the attacking side.
* [`T50`](https://gitlab.com/fredericopissarra/t50/) - Faster network stress tool.
* [`UFONet`](https://github.com/epsylon/ufonet) - Abuses OSI layer 7 HTTP to create/manage 'zombies' and to conduct different attacks using; `GET`/`POST`, multithreading, proxies, origin spoofing methods, cache evasion techniques, etc.

### Firewall

**[`^        back to top        ^`](#overview)**

* [`blocklist-ipsets`](https://github.com/firehol/blocklist-ipsets) - ipsets dynamically updated with firehol's update-ipsets.sh script.
* [`fwknop`](https://www.cipherdyne.org/fwknop/) - Protects ports via Single Packet Authorization in your firewall.
* [`ipset`](https://ipset.netfilter.org/) - Framework inside the Linux kernel, which can be administered by the ipset utility. Depending on the type, an IP set may store IP addresses, networks, (TCP/UDP) port numbers, MAC addresses, interface names or combinations of them in a way, which ensures lightning speed when matching an entry against a set.
* [`OPNsense`](https://opnsense.org/) - is an open source, easy-to-use and easy-to-build FreeBSD based firewall and routing platform. OPNsense includes most of the features available in expensive commercial firewalls, and more in many cases. It brings the rich feature set of commercial offerings with the benefits of open and verifiable sources.
* [`pfSense`](https://www.pfsense.org/) - Firewall and Router FreeBSD distribution.

### IDS / IPS / Host IDS / Host IPS

**[`^        back to top        ^`](#overview)**

* [`AIEngine`](https://bitbucket.org/camp0/aiengine) - AIEngine is a next generation interactive/programmable Python/Ruby/Java/Lua packet inspection engine with capabilities of learning without any human intervention, NIDS(Network Intrusion Detection System) functionality, DNS domain classification, network collector, network forensics and many others.
* [`CrowdSec`](https://github.com/crowdsecurity/crowdsec) - CrowdSec is a free, modern & collaborative behavior detection engine, coupled with a global IP reputation network. It stacks on Fail2Ban's philosophy but is IPV6 compatible and 60x faster (Go vs Python), uses Grok patterns to parse logs and YAML scenario to identify behaviors. CrowdSec is engineered for modern Cloud / Containers / VM based infrastructures (by decoupling detection and remediation). Once detected, you can remedy threats with various bouncers (firewall block, nginx http 403, Captchas, etc.) while the aggressive IPs can be sent to CrowdSec for curation before being shared among all users to further strengthen the community
* [`Denyhosts`](http://denyhosts.sourceforge.net/) - Thwart SSH dictionary based attacks and brute force attacks.
* [`Fail2Ban`](http://www.fail2ban.org/wiki/index.php/Main_Page) - Scans log files and takes action on IPs that show malicious behavior.
* [`maltrail`](https://github.com/stamparm/maltrail) - Malicious traffic detection system.
* [`OSSEC`](https://ossec.github.io/) - Comprehensive Open Source HIDS. Not for the faint of heart. Takes a bit to get your head around how it works. Performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response. It runs on most operating systems, including Linux, MacOS, Solaris, HP-UX, AIX and Windows. Plenty of reasonable documentation. Sweet spot is medium to large deployments.
* [`Security Onion`](http://blog.securityonion.net/) - Security Onion is a Linux distro for intrusion detection, network security monitoring, and log management. It's based on Ubuntu and contains Snort, Suricata, Zeek, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner, and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!
* [`Snort`](https://www.snort.org/) - Snort is a free and open source network intrusion prevention system (NIPS) and network intrusion detection system (NIDS)created by Martin Roesch in 1998. Snort is now developed by Sourcefire, of which Roesch is the founder and CTO. In 2009, Snort entered InfoWorld's Open Source Hall of Fame as one of the "greatest [pieces of] open source software of all time".
* [`ssh-audit`](https://github.com/jtesta/ssh-audit) -  SSH server & client auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc).
* [`SSHGuard`](http://www.sshguard.net/) - A software to protect services in addition to SSH, written in C.
* [`sshwatch`](https://github.com/marshyski/sshwatch) - IPS for SSH similar to DenyHosts written in Python. It also can gather information about attacker during the attack in a log.
* [`Stealth`](https://fbb-git.gitlab.io/stealth/) - File integrity checker that leaves virtually no sediment. Controller runs from another machine, which makes it hard for an attacker to know that the file system is being checked at defined pseudo random intervals over SSH. Highly recommended for small to medium deployments.
* [`Suricata`](http://suricata-ids.org/) - Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. Open Source and owned by a community run non-profit foundation, the Open Information Security Foundation (OISF). Suricata is developed by the OISF and its supporting vendors.
* [`wazuh`](https://github.com/wazuh/wazuh) - Wazuh is a free and open source XDR platform used for threat prevention, detection, and response. It is capable of protecting workloads across on-premises, virtualized, containerized, and cloud-based environments. Great tool foor all kind of deployments, it includes SIEM capabitilies (indexing + searching + WUI).
* [`Zeek`](https://zeek.org/) - Zeek is a powerful network analysis framework that is much different from the typical IDS you may know.
  * [`zeek2es`](https://github.com/corelight/zeek2es) - An open source tool to convert Zeek logs to Elastic/OpenSearch. You can also output pure JSON from Zeek's TSV logs!

### IP

**[`^        back to top        ^`](#overview)**

* [`abuseipdb`](https://www.abuseipdb.com/) - Check an IP Address, Domain Name, or Subnet.
* [`CloakQuest3r`](https://github.com/spyboy-productions/CloakQuest3r) - Uncover the true IP address of websites safeguarded by Cloudflare & Others.
* [`ifconfig.io`](https://ifconfig.io/) - What is my ip address?.
* [`iknowwhatyoudownload`](https://iknowwhatyoudownload.com/en/peer/) - Use internet connection of other people (Wi Fi, their computers, tablets and smartphones) to know what they download in torrent network.
* [`ipdeny`](https://www.ipdeny.com/ipblocks/) - All country IP block files are provided in CIDR format.
* [`myip`](https://myip.ms/) - Live Whois IP Source.
* [`subnet-calculator`](https://www.subnet-calculator.com/cidr.php) - The CIDR Calculator enables CIDR network calculations using IP address, subnet mask, mask bits, maximum required IP addresses and maximum required subnets.

### Honey Pot / Honey Net

**[`^        back to top        ^`](#overview)**

See also *[`awesome-honeypots`](https://github.com/paralax/awesome-honeypots)* - The canonical awesome honeypot list.

* [`Amun`](https://github.com/zeroq/amun) - Amun Python-based low-interaction Honeypot.
* [`Artillery`](https://github.com/trustedsec/artillery/) - Open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods.
* [`Conpot`](http://conpot.org/) - ICS/SCADA Honeypot. Conpot is a low interactive server side Industrial Control Systems honeypot designed to be easy to deploy, modify and extend. By providing a range of common industrial control protocols we created the basics to build your own system, capable to emulate complex infrastructures to convince an adversary that he just found a huge industrial complex. To improve the deceptive capabilities, we also provided the possibility to server a custom human machine interface to increase the honeypots attack surface. The response times of the services can be artificially delayed to mimic the behaviour of a system under constant load. Because we are providing complete stacks of the protocols, Conpot can be accessed with productive HMI's or extended with real hardware. Conpot is developed under the umbrella of the Honeynet Project and on the shoulders of a couple of very big giants.
* [`Cuckoo Sandbox`](http://www.cuckoosandbox.org/) - Cuckoo Sandbox is an Open Source software for automating analysis of suspicious files. To do so it makes use of custom components that monitor the behavior of the malicious processes while running in an isolated environment.
* [`Glastopf`](http://glastopf.org/) - Glastopf is a Honeypot which emulates thousands of vulnerabilities to gather data from attacks targeting web applications. The principle behind it is very simple: Reply the correct response to the attacker exploiting the web application.
* [`HoneyPy`](https://github.com/foospidy/HoneyPy) - HoneyPy is a low to medium interaction honeypot. It is intended to be easy to: deploy, extend functionality with plugins, and apply custom configurations.
* [`HonSSH`](https://github.com/tnich/honssh) - HonSSH is a high-interaction Honey Pot solution. HonSSH will sit between an attacker and a honey pot, creating two separate SSH connections between them.
* [`Kippo`](https://github.com/desaster/kippo) - Kippo is a medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
* [`Kojoney`](http://kojoney.sourceforge.net/) - Kojoney is a low level interaction honeypot that emulates an SSH server. The daemon is written in Python using the Twisted Conch libraries.

### Monitoring / Logging / Event Management

**[`^        back to top        ^`](#overview)**

* [`BoxyHQ`](https://github.com/retracedhq/retraced) - Open source API for security and compliance audit logging.
* [`Falco`](https://falco.org/) - The cloud-native runtime security project and de facto Kubernetes threat detection engine now part of the CNCF.
* [`FIR`](https://github.com/certsocietegenerale/FIR) - Fast Incident Response, a cybersecurity incident management platform.
* [`httpry`](http://dumpsterventures.com/jason/httpry/) - httpry is a specialized packet sniffer designed for displaying and logging HTTP traffic. It is not intended to perform analysis itself, but to capture, parse, and log the traffic for later analysis. It can be run in real-time displaying the traffic as it is parsed, or as a daemon process that logs to an output file. It is written to be as lightweight and flexible as possible, so that it can be easily adaptable to different applications.
* [`httpx`](https://github.com/projectdiscovery/httpx) - Fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library. It is designed to maintain result reliability with an increased number of threads.
* [`justniffer`](http://justniffer.sourceforge.net/) - Justniffer is a network protocol analyzer that captures network traffic and produces logs in a customized way, can emulate Apache web server log files, track response times and extract all "intercepted" files from the HTTP traffic.
* [`LogESP`](https://github.com/dogoncouch/LogESP) - Open Source SIEM (Security Information and Event Management system).
* [`Matano`](https://github.com/matanolabs/matano): Open source serverless security lake platform on AWS that lets you ingest, store, and analyze petabytes of security data into an Apache Iceberg data lake and run realtime Python detections as code.
* [`ngrep`](http://ngrep.sourceforge.net/) - ngrep strives to provide most of GNU grep's common features, applying them to the network layer. ngrep is a pcap-aware tool that will allow you to specify extended regular or hexadecimal expressions to match against data payloads of packets. It currently recognizes IPv4/6, TCP, UDP, ICMPv4/6, IGMP and Raw across Ethernet, PPP, SLIP, FDDI, Token Ring and null interfaces, and understands BPF filter logic in the same fashion as more common packet sniffing tools, such as tcpdump and snoop.
* [`Node Security Platform`](https://nodesecurity.io/) - Similar feature set to Snyk, but free in most cases, and very cheap for others.
* [`ntopng`](http://www.ntop.org/products/traffic-analysis/ntop/) - Ntopng is a network traffic probe that shows the network usage, similar to what the popular top Unix command does.
* [`opensnitch`](https://github.com/evilsocket/opensnitch) - OpenSnitch is a GNU/Linux port of the Little Snitch application firewall.
* [`openvpn-monitor`](https://github.com/furlongm/openvpn-monitor) - Web based OpenVPN monitor, that shows current connection information, such as users, location and data transferred. 
* [`OSSIM`](https://www.alienvault.com/open-threat-exchange/projects) - OSSIM provides all of the features that a security professional needs from a SIEM offering – event collection, normalization, and correlation.
* [`plow`](https://github.com/six-ddc/plow) - High-performance HTTP benchmarking tool with real-time web UI and terminal displaying.
* [`Prelude`](https://www.prelude-siem.org/) - Prelude is a Universal "Security Information & Event Management" (SIEM) system. Prelude collects, normalizes, sorts, aggregates, correlates and reports all security-related events independently of the product brand or license giving rise to such events; Prelude is "agentless".
* [`sagan`](http://sagan.quadrantsec.com/) - Sagan uses a 'Snort like' engine and rules to analyze logs (syslog/event log/snmptrap/netflow/etc).
* [`uptime-kuma`](https://github.com/louislam/uptime-kuma) - Fancy self-hosted monitoring tool.
* [`VAST`](https://github.com/tenzir/vast) - Open source security data pipeline engine for structured event data, supporting high-volume telemetry ingestion, compaction, and retrieval; purpose-built for security content execution, guided threat hunting, and large-scale investigation.

### Network Reconnaissance Tools

**[`^        back to top        ^`](#overview)**

* [`ACLight`](https://github.com/cyberark/ACLight) - Script for advanced discovery of sensitive Privileged Accounts - includes Shadow Admins.
* [`AQUATONE`](https://github.com/michenriksen/aquatone) - Subdomain discovery tool utilizing various open sources producing a report that can be used as input to other tools.
* [`CloudFail`](https://github.com/m0rtem/CloudFail) - Unmask server IP addresses hidden behind Cloudflare by searching old database records and detecting misconfigured DNS.
* [`dnschecker`](https://dnschecker.org/) - Online DNS Check.
* [`DNSDumpster`](https://dnsdumpster.com/) - Online DNS recon and search service.
* [`dnsenum`](https://github.com/fwaeytens/dnsenum/) - Perl script that enumerates DNS information from a domain, attempts zone transfers, performs a brute force dictionary style attack, and then performs reverse look-ups on the results.
* [`dnsmap`](https://github.com/makefu/dnsmap/) - Passive DNS network mapper.
* [`dnsrecon`](https://github.com/darkoperator/dnsrecon/) - DNS enumeration script.
* [`dnstracer`](http://www.mavetju.org/unix/dnstracer.php) - Determines where a given DNS server gets its information from, and follows the chain of DNS servers.
* [`fierce`](https://github.com/mschwager/fierce) - Python3 port of the original `fierce.pl` DNS reconnaissance tool for locating non-contiguous IP space.
* [`MAC Address Vendor Lookup`](https://mac-address.alldatafeeds.com/mac-address-lookup) - By a given MAC address/OUI/IAB, retrieve OUI vendor information, detect virtual machines, manufacturer, locations, read the information encoded in the MAC, and get our research's results regarding any MAC address, OUI, IAB, IEEE.
* [`Mass Scan`](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
* [`netdiscover`](https://github.com/netdiscover-scanner/netdiscover) - Network address discovery scanner, based on ARP sweeps, developed mainly for those wireless networks without a DHCP server.
* [`nmap`](https://nmap.org/) - Free security scanner for network exploration & security audits.
* [`OWASP Amass`](https://github.com/OWASP/Amass) - Subdomain enumeration via scraping, web archives, brute forcing, permutations, reverse DNS sweeping, TLS certificates, passive DNS data sources, etc.
* [`passivedns-client`](https://github.com/chrislee35/passivedns-client) - Library and query tool for querying several passive DNS providers.
* [`passivedns`](https://github.com/gamelinux/passivedns) - Network sniffer that logs all DNS server replies for use in a passive DNS setup.
* [`RustScan`](https://github.com/rustscan/rustscan) - Lightweight and quick open-source port scanner designed to automatically pipe open ports into Nmap.
* [`ScanCannon`](https://github.com/johnnyxmas/ScanCannon) - POSIX-compliant BASH script to quickly enumerate large networks by calling `masscan` to quickly identify open ports and then `nmap` to gain details on the systems/services on those ports.
* [`scanless`](https://github.com/vesche/scanless) - Utility for using websites to perform port scans on your behalf so as not to reveal your own IP.
* [`XRay`](https://github.com/evilsocket/xray) - Network (sub)domain discovery and reconnaissance automation tool.
* [`zmap`](https://zmap.io/) - Open source network scanner that enables researchers to easily perform Internet-wide network studies.

### Network Traffic Replay and Editing Tools

**[`^        back to top        ^`](#overview)**

* [`bittwist`](http://bittwist.sourceforge.net/) - Simple yet powerful libpcap-based Ethernet packet generator useful in simulating networking traffic or scenario, testing firewall, IDS, and IPS, and troubleshooting various network problems.
* [`hping3`](https://github.com/antirez/hping) - Network tool able to send custom TCP/IP packets.
* [`pig`](https://github.com/rafael-santiago/pig) - GNU/Linux packet crafting tool.
* [`scapy`](https://github.com/secdev/scapy) - Python-based interactive packet manipulation program and library.
* [`tcpreplay`](https://tcpreplay.appneta.com/) - Suite of free Open Source utilities for editing and replaying previously captured network traffic.
* [`TraceWrangler`](https://www.tracewrangler.com/) - Network capture file toolkit that can edit and merge `pcap` or `pcapng` files with batch editing features.
* [`WireEdit`](https://wireedit.com/) - Full stack WYSIWYG pcap editor (requires a free license to edit packets).

### Network Vulnerability Scanners

**[`^        back to top        ^`](#overview)**

* [`Above`](https://github.com/c4s73r/Above) - Automates the search for network vulnerabilities, designed for pentesters, Red Team operators, and network security engineers. 
* [`Bolt`](https://github.com/s0md3v/Bolt) - CSRF Scanner.
* [`Boofuzz`](https://github.com/jtpereyda/boofuzz) - Fuzzing engine and fuzz testing framework.
* [`celerystalk`](https://github.com/sethsec/celerystalk) - Asynchronous enumeration and vulnerability scanner that "runs all the tools on all the hosts" in a configurable manner.
* [`CVS`](https://github.com/Safe3/CVS) - Powerful and customizable vulnerability scanner based on VDSL, which can replace Nessus or Nuclei, etc.
* [`Deepfence SecretScanner`](https://github.com/deepfence/SecretScanner) - Find secrets and passwords in container images and file systems.
* [`Deepfence ThreatMapper`](https://github.com/deepfence/ThreatMapper) - Apache v2, powerful runtime vulnerability scanner for kubernetes, virtual machines and serverless.
* [`Goby`](https://gobies.org/) - The new generation of network security technology achieves rapid security emergency through the establishment of a complete asset database for the target.
* [`kube-hunter`](https://kube-hunter.aquasec.com/) - Open-source tool that runs a set of tests ("hunters") for security issues in Kubernetes clusters from either outside ("attacker's view") or inside a cluster.
* [`log4j-scan`](https://github.com/fullhunt/log4j-scan) - Fully automated, accurate, and extensive scanner for finding vulnerable log4j hosts.
* [`monsoon`](https://github.com/RedTeamPentesting/monsoon) - Very flexible and fast interactive HTTP enumeration/fuzzing.
* [`Nessus`](https://www.tenable.com/products/nessus-vulnerability-scanner) - Commercial vulnerability management, configuration, and compliance assessment platform, sold by Tenable.
* [`Netsparker Application Security Scanner`](https://www.netsparker.com/pricing/) - Application security scanner to automatically find security flaws.
* [`Netz`](https://github.com/spectralops/netz)- Discover internet-wide misconfigurations, using zgrab2 and others.
* [`Nexpose`](https://www.rapid7.com/products/nexpose/) - Commercial vulnerability and risk management assessment engine that integrates with Metasploit, sold by Rapid7.
* [`nuclei`](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner based on simple YAML based DSL.
* [`nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) - Community curated list of templates for the nuclei engine to find security vulnerabilities.
* [`Nucleimonst3r`](https://github.com/blackhatethicalhacking/Nucleimonst3r) - Powerful vulnerability scanner that can help Bug Bounty Hunters find low hanging fruit vulnerabilities for known CVEs and exploits but also gather all the technology running behind them for further investigation for a potential target.
* [`OpenVAS`](http://www.openvas.org/) - Free software implementation of the popular Nessus vulnerability assessment system.
* [`Pompem`](https://github.com/rfunix/Pompem) - Pompem is an open source tool, which is designed to automate the search for exploits in major databases. Developed in Python, has a system of advanced search, thus facilitating the work of pentesters and ethical hackers. In its current version, performs searches in databases: Exploit-db, 1337day, Packetstorm Security.
* [`trivy`](https://github.com/aquasecurity/trivy) - Find vulnerabilities, misconfigurations, secrets, SBOM in containers, Kubernetes, code repositories, clouds and more.
* [`Vuls`](https://github.com/future-architect/vuls) - Agentless vulnerability scanner for GNU/Linux and FreeBSD, written in Go.

### Protocol Analyzers / Sniffers

**[`^        back to top        ^`](#overview)**

* [`Debookee`](http://www.iwaxx.com/debookee/) - Simple and powerful network traffic analyzer for macOS.
* [`Deepfence PacketStreamer`](https://github.com/deepfence/PacketStreamer) - High-performance remote packet capture and collection tool, distributed tcpdump for cloud native environments.
* [`Dshell`](https://github.com/USArmyResearchLab/Dshell) - Network forensic analysis framework.
* [`Live HTTP headers`](https://addons.mozilla.org/en-US/firefox/addon/http-header-live/) - Live HTTP headers is a free firefox addon to see your browser requests in real time. It shows the entire headers of the requests and can be used to find the security loopholes in implementations.
* [`Moloch`](https://github.com/aol/moloch) - Moloch is an open source, large scale IPv4 packet capturing (PCAP), indexing and database system. A simple web interface is provided for PCAP browsing, searching, and exporting. APIs are exposed that allow PCAP data and JSON-formatted session data to be downloaded directly. Simple security is implemented by using HTTPS and HTTP digest password support or by using apache in front. Moloch is not meant to replace IDS engines but instead work along side them to store and index all the network traffic in standard PCAP format, providing fast access. Moloch is built to be deployed across many systems and can scale to handle multiple gigabits/sec of traffic.
* [`netsniff-ng`](https://github.com/netsniff-ng/netsniff-ng) - Swiss army knife for network sniffing.
* [`Netzob`](https://github.com/netzob/netzob) - Reverse engineering, traffic generation and fuzzing of communication protocols.
* [`OpenFPC`](http://www.openfpc.org) - OpenFPC is a set of tools that combine to provide a lightweight full-packet network traffic recorder & buffering system. It's design goal is to allow non-expert users to deploy a distributed network traffic recorder on COTS hardware while integrating into existing alert and log management tools.
* [`sniffglue`](https://github.com/kpcyrd/sniffglue) - Secure multithreaded packet sniffer.
* [`stenographer`](https://github.com/google/stenographer) - Stenographer is a packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets.
* [`tcpdump/libpcap`](http://www.tcpdump.org/) - Common packet analyzer that runs under the command line.
* [`tcpflow](https://github.com/simsong/tcpflow) - tcpflow is a program that captures data transmitted as part of TCP connections (flows), and stores the data in a way that is convenient for protocol analysis and debugging. Each TCP flow is stored in its own file. Thus, the typical TCP flow will be stored in two files, one for each direction. tcpflow can also process stored 'tcpdump' packet flows.
* [`Wireshark`](https://www.wireshark.org/) - Widely-used graphical, cross-platform network protocol analyzer.
* [`Xplico`](http://www.xplico.org/) - The goal of Xplico is extract from an internet traffic capture the applications data contained. For example, from a pcap file Xplico extracts each email (POP, IMAP, and SMTP protocols), all HTTP contents, each VoIP call (SIP), FTP, TFTP, and so on. Xplico isn’t a network protocol analyzer. Xplico is an open source Network Forensic Analysis Tool (NFAT).

### Proxies and Machine-in-the-Middle (MITM) Tools

**[`^        back to top        ^`](#overview)**

See also *[`Web Proxies Intercepting`](#web-proxies-intercepting)*.

* [`BetterCAP`](https://www.bettercap.org/) - Modular, portable and easily extensible MITM framework.
* [`dnschef`](https://github.com/iphelix/dnschef) - Highly configurable DNS proxy for pentesters.
* [`Ettercap`](http://www.ettercap-project.org) - Comprehensive, mature suite for machine-in-the-middle attacks.
* [`evilgrade`](https://github.com/infobyte/evilgrade) - Modular framework to take advantage of poor upgrade implementations by injecting fake updates.
* [`Habu`](https://github.com/portantier/habu) - Python utility implementing a variety of network attacks, such as ARP poisoning, DHCP starvation, and more.
* [`Lambda-Proxy`](https://github.com/puresec/lambda-proxy) - Utility for testing SQL Injection vulnerabilities on AWS Lambda serverless functions.
* [`mallory`](https://github.com/justmao945/mallory) - HTTP/HTTPS proxy over SSH.
* [`MITMf`](https://github.com/byt3bl33d3r/MITMf) - Framework for Man-In-The-Middle attacks.
* [`Morpheus`](https://github.com/r00t-3xp10it/morpheus) - Automated ettercap TCP/IP Hijacking tool.
* [`oregano`](https://github.com/nametoolong/oregano) - Python module that runs as a machine-in-the-middle (MITM) accepting Tor client requests.
* [`SSH MITM`](https://github.com/jtesta/ssh-mitm) - Intercept SSH connections with a proxy; all plaintext passwords and sessions are logged to disk.
* [`sylkie`](https://dlrobertson.github.io/sylkie/) - Command line tool and library for testing networks for common address spoofing security vulnerabilities in IPv6 networks using the Neighbor Discovery Protocol.

### Transport Layer Security Tools

**[`^        back to top        ^`](#overview)**

* [`crackpkcs12`](https://github.com/crackpkcs12/crackpkcs12) - Multithreaded program to crack PKCS#12 files (`.p12` and `.pfx` extensions), such as TLS/SSL certificates.
* [`localhost.direct`](https://github.com/Upinel/localhost.direct) - Localhost with public CA signed SSL certificate.
* [`mkcert`](https://github.com/FiloSottile/mkcert) - A simple zero-config tool to make locally trusted development certificates with any names you'd like.
* [`SSLyze`](https://github.com/nabla-c0d3/sslyze) - Fast and comprehensive TLS/SSL configuration analyzer to help identify security mis-configurations.
* [`testssl.sh`](https://github.com/drwetter/testssl.sh) - Command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.
* [`tls_prober`](https://github.com/WestpointLtd/tls_prober) - Fingerprint a server's SSL/TLS implementation.

### VPN

**[`^        back to top        ^`](#overview)**

* [`Firezone`](https://github.com/firezone/firezone) - Open-source VPN server and egress firewall for Linux built on WireGuard that makes it simple to manage secure remote access to your company’s private networks. Firezone is easy to set up (all dependencies are bundled thanks to Chef Omnibus), secure, performant, and self hostable.
* [`OpenVPN`](https://openvpn.net/) - OpenVPN is an open source software application that implements virtual private network (VPN) techniques for creating secure point-to-point or site-to-site connections in routed or bridged configurations and remote access facilities. It uses a custom security protocol that utilizes SSL/TLS for key exchange.

### Wireless Network Tools

**[`^        back to top        ^`](#overview)**

* [`Aircrack-ng`](http://www.aircrack-ng.org/) - Set of tools for auditing wireless networks.
* [`Airgeddon`](https://github.com/v1s1t0r1sh3r3/airgeddon) - Multi-use bash script for Linux systems to audit wireless networks.
* [`BoopSuite`](https://github.com/MisterBianco/BoopSuite) - Suite of tools written in Python for wireless auditing.
* [`Bully`](http://git.kali.org/gitweb/?p=packages/bully.git;a=summary) - Implementation of the WPS brute force attack, written in C.
* [`Cowpatty`](https://github.com/joswr1ght/cowpatty) - Brute-force dictionary attack against WPA-PSK.
* [`Fluxion`](https://github.com/FluxionNetwork/fluxion) - Suite of automated social engineering based WPA attacks.
* [`infernal-twin`](https://github.com/entropy1337/infernal-twin) - Automated wireless hacking tool.
* [`Kismet`](https://kismetwireless.net/) - Wireless network detector, sniffer, and IDS.
* [`KRACK Detector`](https://github.com/securingsam/krackdetector) - Detect and prevent KRACK attacks in your network.
* [`krackattacks-scripts`](https://github.com/vanhoefm/krackattacks-scripts) - WPA2 Krack attack scripts.
* [`PSKracker`](https://github.com/soxrok2212/PSKracker) - Collection of WPA/WPA2/WPS default algorithms, password generators, and PIN generators written in C.
* [`pwnagotchi`](https://github.com/evilsocket/pwnagotchi) - Deep reinforcement learning based AI that learns from the Wi-Fi environment and instruments BetterCAP in order to maximize the WPA key material captured.
* [`Reaver`](https://code.google.com/archive/p/reaver-wps) - Brute force attack against WiFi Protected Setup.
* [`WiFi Pineapple`](https://www.wifipineapple.com/) - Wireless auditing and penetration testing platform.
* [`Wifite`](https://github.com/derv82/wifite) - Automated wireless attack tool.
* [`wifi-arsenal`](https://github.com/0x90/wifi-arsenal) - Resources for Wi-Fi Pentesting.
* [`WiFi-Pumpkin`](https://github.com/P0cL4bs/WiFi-Pumpkin) - Framework for rogue Wi-Fi access point attack.

------

## Open Sources Intelligence (OSINT)

**[`^        back to top        ^`](#overview)**

See also *[`awesome-osint`](https://github.com/jivoi/awesome-osint)*.

* [`bbot`](https://github.com/blacklanternsecurity/bbot) - OSINT automation for hackers.
* [`creepy`](https://github.com/ilektrojohn/creepy) - Geolocation OSINT tool.
* [`DataSploit`](https://github.com/upgoingstar/datasploit) - OSINT visualizer utilizing Shodan, Censys, Clearbit, EmailHunter, FullContact, and Zoomeye behind the scenes.
* [`Depix`](https://github.com/beurtschipper/Depix) - Tool for recovering passwords from pixelized screenshots (by de-pixelating text).
* [`Facebook Friend List Scraper`](https://github.com/narkopolo/fb_friend_list_scraper) - Tool to scrape names and usernames from large friend lists on Facebook, without being rate limited.
* [`gOSINT`](https://github.com/Nhoya/gOSINT) - OSINT tool with multiple modules and a telegram scraper.
* [`GyoiThon`](https://github.com/gyoisamurai/GyoiThon) - GyoiThon is an Intelligence Gathering tool using Machine Learning.
* [`Hunter.io`](https://hunter.io/) - Data broker providing a Web search interface for discovering the email addresses and other organizational details of a company.
* [`image-match`](https://github.com/ascribe/image-match) - Quickly search over billions of images.
* [`Intrigue`](http://intrigue.io) - Automated OSINT & Attack Surface discovery framework with powerful API, UI and CLI.
* [`Maltego`](http://www.maltego.com/) - Proprietary software for open sources intelligence and forensics.
* [`PacketTotal`](https://packettotal.com/) - Simple, free, high-quality packet capture file analysis facilitating the quick detection of network-borne malware (using Zeek and Suricata IDS signatures under the hood).
* [`recon-ng`](https://github.com/lanmaster53/recon-ng) - Full-featured Web Reconnaissance framework written in Python.
* [`Skiptracer`](https://github.com/xillwillx/skiptracer) - OSINT scraping framework that utilizes basic Python webscraping (BeautifulSoup) of PII paywall sites to compile passive information on a target on a ramen noodle budget.
* [`sn0int`](https://github.com/kpcyrd/sn0int) - Semi-automatic OSINT framework and package manager.
* [`Sn1per`](https://github.com/1N3/Sn1per) - Automated Pentest Recon Scanner.
* [`Spiderfoot`](http://www.spiderfoot.net/) - Multi-source OSINT automation tool with a Web UI and report visualizations.
* [`surfraw`](https://github.com/kisom/surfraw) - Fast UNIX command line interface to a variety of popular WWW search engines.
* [`Threat Crowd`](https://www.threatcrowd.org/) - Search engine for threats.
* [`z-cam`](https://github.com/sankethj/z-cam) - The First Python Compatible Camera Hacking Tool.

### Dorking tools

**[`^        back to top        ^`](#overview)**

* [`BinGoo`](https://github.com/Hood3dRob1n/BinGoo) - GNU/Linux bash based Bing and Google Dorking Tool.
* [`dorkbot`](https://github.com/utiso/dorkbot) - Command-line tool to scan Google (or other) search results for vulnerabilities.
* [`dorks`](https://github.com/USSCltd/dorks) - Google hack database automation tool.
* [`dork-cli`](https://github.com/jgor/dork-cli) - Command line Google dork tool.
* [`fast-recon`](https://github.com/DanMcInerney/fast-recon) - Perform Google dorks against a domain.
* [`github-dorks`](https://github.com/techgaun/github-dorks) - CLI tool to scan GitHub repos/organizations for potential sensitive information leaks.
* [`GooDork`](https://github.com/k3170makan/GooDork) - Command line Google dorking tool.
* [`Google Hacking Database`](https://www.exploit-db.com/google-hacking-database/) - Database of Google dorks; can be used for recon.
* [`pagodo`](https://github.com/opsdisk/pagodo) - Automate Google Hacking Database scraping.
* [`snitch`](https://github.com/Smaash/snitch) - Information gathering via dorks.

### Email, phone search and analysis tools

**[`^        back to top        ^`](#overview)**

* [`email2phonenumber`](https://github.com/martinvigo/email2phonenumber) - OSINT tool to obtain a target's phone number just by having his email address.
* [`enola`](https://github.com/TheYahya/enola) - This is [Sherlock](https://github.com/sherlock-project/sherlock)'s sister Enola, Modern shiny CLI tool written with Golang to help you: 🔎 Hunt down social media accounts by username across social networks.
* [`Moriarty-Project`](https://github.com/AzizKpln/Moriarty-Project) - this tool gives information about the phone number that you entered.
* [`SimplyEmail`](https://github.com/SimplySecurity/SimplyEmail) - Email recon made fast and easy.
* [`WhatBreach`](https://github.com/Ekultek/WhatBreach) - Search email addresses and discover all known breaches that this email has been seen in, and download the breached database if it is publicly available.

### Metadata harvesting and analysis

**[`^        back to top        ^`](#overview)**

* [`FOCA (Fingerprinting Organizations with Collected Archives)`](https://www.elevenpaths.com/labstools/foca/) - Automated document harvester that searches Google, Bing, and DuckDuckGo to find and extrapolate internal company organizational structures.
* [`metagoofil`](https://github.com/laramies/metagoofil) - Metadata harvester.
* [`theHarvester`](https://github.com/laramies/theHarvester) - E-mail, subdomain and people names harvester.

### Network device discovery tools

**[`^        back to top        ^`](#overview)**

* [`Censys`](https://www.censys.io/) - Collects data on hosts and websites through daily ZMap and ZGrab scans.
* [`Shodan`](https://www.shodan.io/) - World's first search engine for Internet-connected devices.
* [`ZoomEye`](https://www.zoomeye.org/) - Search engine for cyberspace that lets the user find specific network components.

### OSINT Online Resources

**[`^        back to top        ^`](#overview)**

* [`bugmenot`](https://bugmenot.com/) - Find and share logins, see if the bugmenot community has shared any logins for it.
* [`CertGraph`](https://github.com/lanrat/certgraph) - Crawls a domain's SSL/TLS certificates for its certificate alternative names.
* [`Extract Images`](https://extract.pics/) - Extract Images from any public website by using a virtual browser.
* [`GhostProject`](https://ghostproject.fr/) - Searchable database of billions of cleartext passwords, partially visible for free.
* [`HostHunter`](https://github.com/SpiderLabs/HostHunter) - Recon tool for discovering hostnames using OSINT techniques.
* [`iHUNT Intelligence FRAMEWORK`](https://nitinpandey.in/ihunt/) - Focuses on gathering information from free and open-source tools or resources. The intention is to help people find free and open source combined OSINT, GEOINT, SOCMINT and HUMINT resources for research or practice purposes, especially Law Enforcement and Intelligence Officers.
* [`investigator`](https://github.com/abhijithb200/investigator) - Online handy-recon tool.
* [`NetBootcamp OSINT Tools`](http://netbootcamp.org/osinttools/) - Collection of OSINT links and custom Web interfaces to other services.
* [`OSINT Framework`](http://osintframework.com/) - Collection of various OSINT tools broken out by category.
* [`whatsmyname`](https://whatsmyname.app/) - This tool allows you to enumerate usernames across many websites.
* [`WiGLE.net`](https://wigle.net/) - Information about wireless networks world-wide, with user-friendly desktop and web applications.

### Source code repository searching tools

**[`^        back to top        ^`](#overview)**

See also *[`Web Accessible Source Code Ripping Tools`](#web-accessible-source-code-ripping-tools)*.

* [`vcsmap`](https://github.com/melvinsh/vcsmap) - Plugin-based tool to scan public version control systems for sensitive information.
* [`Yar`](https://github.com/Furduhlutur/yar) - Clone git repositories to search through the whole commit history in order of commit time for secrets, tokens, or passwords.

### Web application and resource analysis tools

**[`^        back to top        ^`](#overview)**

* [`BlindElephant`](http://blindelephant.sourceforge.net/) - Web application fingerprinter.
* [`EyeWitness`](https://github.com/ChrisTruncer/EyeWitness) - Tool to take screenshots of websites, provide some server header info, and identify default credentials if possible.
* [`VHostScan`](https://github.com/codingo/VHostScan) - Virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
* [`wafw00f`](https://github.com/EnableSecurity/wafw00f) - Identifies and fingerprints Web Application Firewall (WAF) products.
* [`Wappalyzer`](https://www.wappalyzer.com/) - Wappalyzer uncovers the technologies used on websites.
* [`webscreenshot`](https://github.com/maaaaz/webscreenshot) - Simple script to take screenshots of websites from a list of sites.
* [`WhatWaf`](https://github.com/Ekultek/WhatWaf) - Detect and bypass web application firewalls and protection systems.
* [`WhatWeb`](https://github.com/urbanadventurer/WhatWeb) - Website fingerprinter.

------

## Operating Systems

### Linux

**[`^        back to top        ^`](#overview)**

* [`Bashark`](https://github.com/redcode-labs/Bashark) - Aids pentesters and security researchers during the post-exploitation phase of security audit.
* [`checksec.sh`](https://www.trapkit.de/tools/checksec.html) - Shell script designed to test what standard Linux OS and PaX security features are being used.
* [`Fenrir`](https://github.com/Neo23x0/Fenrir) - Simple IOC scanner bash script.
* [`GTFOBins`](https://gtfobins.github.io/) - Curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
* [`GTFONow`](https://github.com/Frissi0n/GTFONow) - Automatic privilege escalation for misconfigured capabilities, sudo and suid binaries using GTFOBins.
* [`How-To-Secure-A-Linux-Server`](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server) - An evolving how-to guide for securing a Linux server. 
* [`Hwacha`](https://github.com/n00py/Hwacha) - Post-exploitation tool to quickly execute payloads via SSH on one or more Linux systems simultaneously.
* [`LinEnum`](https://github.com/rebootuser/LinEnum) - Scripted Local Linux Enumeration & Privilege Escalation Checks.
* [`LinPEAS`](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) - LinPEAS is a script that search for possible paths to escalate privileges on Linux/Unix*/MacOS hosts.
* [`Linux Exploit Suggester`](https://github.com/PenturaLabs/Linux_Exploit_Suggester) - Heuristic reporting on potentially viable exploits for a given GNU/Linux system.
* [`linuxprivchecker`](https://github.com/sleventyeleven/linuxprivchecker) - Linux Privilege Escalation Check Script
* [`linux-private-i`](https://github.com/rtcrowley/linux-private-i) - Linux bash tool for Enumeration & Privilege Escalation.
* [`Linux-Privilege-Escalation`](https://github.com/Ignitetechnologies/Linux-Privilege-Escalation) -  This cheatsheet is aimed at the OSCP aspirants to help them understand the various methods of Escalating Privilege on Linux based Machines and CTFs with examples.
* [`linux-smart-enumeration`](https://github.com/diego-treitos/linux-smart-enumeration) - Linux enumeration tool for pentesting and CTFs with verbosity levels.
* [`LOLBAS (Living Off The Land Binaries and Scripts)`](https://lolbas-project.github.io/) - Documents binaries, scripts, and libraries that can be used for "Living Off The Land" techniques, i.e., binaries that can be used by an attacker to perform actions beyond their original purpose.
* [`Lynis`](https://cisofy.com/lynis/) - Auditing tool for UNIX-based systems.
* [`Postenum`](https://github.com/mbahadou/postenum) - Shell script used for enumerating possible privilege escalation opportunities on a local GNU/Linux system.
* [`pyBackdoor`](https://github.com/xp4xbox/Python-Backdoor) - a cross-platform (Windows/Linux/MacOS) yet simple and powerful backdoor/reverse tcp/RAT made in Python3 which contains many features such as multi-client support.
* [`RecoverPy`](https://github.com/PabloLec/RecoverPy) - Interactively find and recover deleted or overwritten files from your terminal.
* [`PwnKit`](https://github.com/ly4k/PwnKit) - Self-contained exploit for CVE-2021-4034 - Pkexec Local Privilege Escalation.
* [`SSH-Harvester`](https://github.com/jm33-m0/SSH-Harvester) - Harvest passwords automatically from OpenSSH server.
* [`unix-privesc-check`](https://github.com/pentestmonkey/unix-privesc-check) - Shell script to check for simple privilege escalation vectors on UNIX systems.

#### Linux Online Resources

**[`^        back to top        ^`](#overview)**

* [`chmod calculator`](https://chmodcommand.com/) - Chmod calculator allows you to quickly generate permissions in numerical and symbolic formats. All extra options are included (recursive, sticky, etc). You’ll be ready to copy paste your chmod command into your terminal in seconds.
* [`crontab.guru`](https://crontab.guru/) - The quick and simple editor for cron schedule expressions.
* [`Data Storage Converter`](https://www.unitconverters.net/data-storage-converter.html) - Popular data storage unit conversions.
* [`explainshell`](https://explainshell.com/) - Write down a command-line to see the help text that matches each argument.
* [`LDAP TS Converter`](https://www.epochconverter.com/ldap) - LDAP, Active Directory & Filetime Timestamp Converter.
* [`Unix TS Converter`](https://www.epochconverter.com/) - Epoch & Unix Timestamp Conversion Tools.

### macOS

**[`^        back to top        ^`](#overview)**

* [`Bella`](https://github.com/kdaoudieh/Bella) - Pure Python post-exploitation data mining and remote administration tool for macOS.
* [`EvilOSX`](https://github.com/Marten4n6/EvilOSX) - Modular RAT that uses numerous evasion and exfiltration techniques out-of-the-box.

### Windows

**[`^        back to top        ^`](#overview)**

* [`Active Directory and Privilege Escalation (ADAPE)`](https://github.com/hausec/ADAPE-Script) - Umbrella script that automates numerous useful PowerShell modules to discover security misconfigurations and attempt privilege escalation against Active Directory.
* [`Bloodhound`](https://github.com/adaptivethreat/Bloodhound/wiki) - Graphical Active Directory trust relationship explorer.
* [`Commando VM`](https://github.com/fireeye/commando-vm) - Automated installation of over 140 Windows software packages for penetration testing and red teaming.
* [`Covenant`](https://github.com/cobbr/Covenant) - ASP .NET Core application that serves as a collaborative command and control platform for red teamers.
* [`ctftool`](https://github.com/taviso/ctftool) - Interactive Collaborative Translation Framework (CTF) exploration tool capable of launching cross-session edit session attacks.
* [`DeathStar`](https://github.com/byt3bl33d3r/DeathStar) - Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory environments.
* [`DomainPasswordSpray`](https://github.com/dafthack/DomainPasswordSpray) - Tool written in PowerShell to perform a password spray attack against users of a domain.
* [`Empire`](https://www.powershellempire.com/) - Pure PowerShell post-exploitation agent.
* [`Fibratus`](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel.
* [`Inveigh`](https://github.com/Kevin-Robertson/Inveigh) - Windows PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer/machine-in-the-middle tool.
* [`LaZagne`](https://github.com/AlessandroZ/LaZagne) - Credentials recovery project.
* [`MailSniper`](https://github.com/dafthack/MailSniper) - Modular tool for searching through email in a Microsoft Exchange environment, gathering the Global Address List from Outlook Web Access (OWA) and Exchange Web Services (EWS), and more.
* [`mimikatz`](http://blog.gentilkiwi.com/mimikatz) - Credentials extraction tool for Windows operating system.
* [`PowerSploit`](https://github.com/PowerShellMafia/PowerSploit) - PowerShell Post-Exploitation Framework.
* [`redsnarf`](https://github.com/nccgroup/redsnarf) - Post-exploitation tool for retrieving password hashes and credentials from Windows workstations, servers, and domain controllers.
* [`Responder`](https://github.com/SpiderLabs/Responder) - Link-Local Multicast Name Resolution (LLMNR), NBT-NS, and mDNS poisoner.
* [`RID_ENUM`](https://github.com/trustedsec/ridenum) - Python script that can enumerate all users from a Windows Domain Controller and crack those user's passwords using brute-force.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) - Toolset for raw Kerberos interaction and abuses.
* [`Ruler`](https://github.com/sensepost/ruler) - Abuses client-side Outlook features to gain a remote shell on a Microsoft Exchange server.
* [`SCOMDecrypt`](https://github.com/nccgroup/SCOMDecrypt) - Retrieve and decrypt RunAs credentials stored within Microsoft System Center Operations Manager (SCOM) databases.
* [`SprayingToolkit`](https://github.com/byt3bl33d3r/SprayingToolkit) - Scripts to make password spraying attacks against Lync/S4B, Outlook Web Access (OWA) and Office 365 (O365) a lot quicker, less painful and more efficient.
* [`Sysinternals Suite`](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - The Sysinternals Troubleshooting Utilities.
* [`ToxicEye`](https://github.com/LimerBoy/ToxicEye) - Program for remote control of windows computers via telegram bot. Written in C#.
* [`wePWNise`](https://labs.mwrinfosecurity.com/tools/wepwnise/) - Generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software.
* [`Windows Credentials Editor`](https://www.ampliasecurity.com/research/windows-credentials-editor/) - Inspect logon sessions and add, change, list, and delete associated credentials, including Kerberos tickets.
* [`Windows Exploit Suggester`](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - Detects potential missing patches on the target.
* [`WinPwn`](https://github.com/SecureThisShit/WinPwn) - Internal penetration test script to perform local and domain reconnaissance, privilege escalation and exploitation.

### Operating System Distributions

**[`^        back to top        ^`](#overview)**

* [`Android Tamer`](https://androidtamer.com/) - Distribution built for Android security professionals that includes tools required for Android security testing.
* [`ArchStrike`](https://archstrike.org/) - Arch GNU/Linux repository for security professionals and enthusiasts.
* [`AttifyOS`](https://github.com/adi0x90/attifyos) - GNU/Linux distribution focused on tools useful during Internet of Things (IoT) security assessments.
* [`BlackArch`](https://www.blackarch.org/) - Arch GNU/Linux-based distribution for penetration testers and security researchers.
* [`Buscador`](https://inteltechniques.com/buscador/) - GNU/Linux virtual machine that is pre-configured for online investigators.
* [`Kali`](https://www.kali.org/) - Rolling Debian-based GNU/Linux distribution designed for penetration testing and digital forensics.
* [`Network Security Toolkit (NST)`](http://networksecuritytoolkit.org/) - Fedora-based GNU/Linux bootable live Operating System designed to provide easy access to best-of-breed open source network security applications.
* [`Parrot`](https://parrotlinux.org/) - Distribution similar to Kali, with support for multiple hardware architectures.
* [`PentestBox`](https://pentestbox.org/) - Open source pre-configured portable penetration testing environment for the Windows Operating System.
* [`Qubes OS`](https://www.qubes-os.org/) - Qubes OS is a free and open-source security-oriented operating system meant for single-user desktop computing.
* [`Tails OS`](https://tails.boum.org/) - Tails is a portable operating system that protects against surveillance and censorship.
* [`The Pentesters Framework`](https://github.com/trustedsec/ptf) - Distro organized around the Penetration Testing Execution Standard (PTES), providing a curated collection of utilities that omits less frequently used utilities.
* [`tsurugi`](https://tsurugi-linux.org/) - heavily customized Linux distribution that designed to support DFIR investigations, malware analysis and OSINT activities.
* [`Whonix`](https://www.whonix.org) - Operating System designed for anonymity.

### Online Operating Systems Resources

**[`^        back to top        ^`](#overview)**

* [`DistroWatch.com's Security Category`](https://distrowatch.com/search.php?category=Security) - Website dedicated to talking about, reviewing, and keeping up to date with open source operating systems.

------

## Penetration Testing

**[`^        back to top        ^`](#overview)**

See also *[`Awesome Pentest`](https://github.com/enaqx/awesome-pentest)* - Collection of awesome penetration testing resources, tools and other shiny things.

See also *[`Awesome Pentest Cheat Sheets`](https://github.com/coreb1t/awesome-pentest-cheat-sheets)* - Collection of the cheat sheets useful for pentesting.

See also our *[`Penetration Testing Collection`](./penetration-testing/)* - Out custom collection of the cheat sheets useful for pentesting.

### Addintional Penetration Tools

**[`^        back to top        ^`](#overview)**

* [`arsenal`](https://github.com/Orange-Cyberdefense/arsenal) - is just a quick inventory, reminder and launcher for pentest commands. 
* [`rsg`](https://github.com/mthbernardes/rsg) - A tool to generate various ways to do a reverse shell.
* [`SSH-Snake`](https://github.com/MegaManSec/SSH-Snake) - Self-propagating, self-replicating, file-less script that automates the post-exploitation task of SSH private key and host discovery.
* 
### Online Penetration Testing Resources

**[`^        back to top        ^`](#overview)**

* [`offsec.tools`](https://offsec.tools/) -  A vast collection of security tools for bug bounty, pentest and red teaming.
* [`MITRE's Adversarial Tactics, Techniques & Common Knowledge (ATT&CK)`](https://attack.mitre.org/) - Curated knowledge base and model for cyber adversary behavior.
* [`Metasploit Unleashed`](https://www.offensive-security.com/metasploit-unleashed/) - Free Offensive Security Metasploit course.
* [`Open Web Application Security Project (OWASP)`](https://www.owasp.org/index.php/Main_Page) - Worldwide not-for-profit charitable organization focused on improving the security of especially Web-based and Application-layer software.
* [`pentest-book`](https://github.com/six2dez/pentest-book) - This book contains a bunch of info, scripts and knowledge used during pentests.
* [`PENTEST-WIKI`](https://github.com/nixawk/pentest-wiki) - Free online security knowledge library for pentesters and researchers.
* [`Penetration Testing Execution Standard (PTES)`](http://www.pentest-standard.org/) - Documentation designed to provide a common language and scope for performing and reporting the results of a penetration test.
* [`Penetration Testing Framework (PTF)`](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html) - Outline for performing penetration tests compiled as a general framework usable by vulnerability analysts and penetration testers alike.
* [`XSS-Payloads`](http://www.xss-payloads.com) - Resource dedicated to all things XSS (cross-site), including payloads, tools, games, and documentation.

### Passwords

**[`^        back to top        ^`](#overview)**

* [`Hive Systems Password Table`](https://www.hivesystems.io/blog/are-your-passwords-in-the-green) - Checking, Are Your Passwords in the Green?
* [`weakpass`](https://weakpass.com/wordlist) - For any kind of bruteforce find wordlists.

### Penetration Testing Report Templates

**[`^        back to top        ^`](#overview)**

* [`OffSec-Reporting`](https://github.com/Syslifters/OffSec-Reporting) -  Offensive Security OSCP, OSWP, OSEP, OSWA, OSWE, OSED, OSMR, OSEE, OSDA Exam and Lab Reporting / Note-Taking Tool.
* [`Public Pentesting Reports`](https://github.com/juliocesarfort/public-pentesting-reports) - Curated list of public penetration test reports released by several consulting firms and academic security groups.
* [`T&VS Pentesting Report Template`](https://www.testandverification.com/wp-content/uploads/template-penetration-testing-report-v03.pdf) - Pentest report template provided by Test and Verification Services, Ltd.
* [`Web Application Security Assessment Report Template`](http://lucideus.com/pdf/stw.pdf) - Sample Web application security assessment reporting template provided by Lucideus.

------

## Physical Access Tools

**[`^        back to top        ^`](#overview)**

* [`AT Commands`](https://atcommands.org/) - Use AT commands over an Android device's USB port to rewrite device firmware, bypass security mechanisms, exfiltrate sensitive information, perform screen unlocks, and inject touch events.
* [`Bash Bunny`](https://www.hak5.org/gear/bash-bunny) - Local exploit delivery tool in the form of a USB thumbdrive in which you write payloads in a DSL called BunnyScript.
* [`LAN Turtle`](https://lanturtle.com/) - Covert "USB Ethernet Adapter" that provides remote access, network intelligence gathering, and MITM capabilities when installed in a local network.
* [`Packet Squirrel`](https://www.hak5.org/gear/packet-squirrel) - Ethernet multi-tool designed to enable covert remote access, painless packet captures, and secure VPN connections with the flip of a switch.
* [`PCILeech`](https://github.com/ufrisk/pcileech) - Uses PCIe hardware devices to read and write from the target system memory via Direct Memory Access (DMA) over PCIe.
* [`Poisontap`](https://samy.pl/poisontap/) - Siphons cookies, exposes internal (LAN-side) router and installs web backdoor on locked computers.
* [`Proxmark3`](https://proxmark3.com/) - RFID/NFC cloning, replay, and spoofing toolkit often used for analyzing and attacking proximity cards/readers, wireless keys/keyfobs, and more.
* [`Thunderclap`](https://thunderclap.io/) - Open source I/O security research platform for auditing physical DMA-enabled hardware peripheral ports.
* [`USB Rubber Ducky`](http://usbrubberducky.com/) - Customizable keystroke injection attack platform masquerading as a USB thumbdrive.

------

## Reverse Engineering

**[`^        back to top        ^`](#overview)**

* [`angr`](https://angr.io/) - Platform-agnostic binary analysis framework.
* [`binwalk`](https://github.com/devttys0/binwalk) - Fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
* [`boxxy`](https://github.com/kpcyrd/boxxy-rs) - Linkable sandbox explorer.
* [`Capstone`](http://www.capstone-engine.org/) - Lightweight multi-platform, multi-architecture disassembly framework.
* [`Detect It Easy(DiE)`](https://github.com/horsicq/Detect-It-Easy) - Program for determining types of files for Windows, Linux and MacOS.
* [`dnSpy`](https://github.com/0xd4d/dnSpy) - Tool to reverse engineer .NET assemblies.
* [`Evan's Debugger`](http://www.codef00.com/projects#debugger) - OllyDbg-like debugger for GNU/Linux.
* [`Fridax`](https://github.com/NorthwaveNL/fridax) - Read variables and intercept/hook functions in Xamarin/Mono JIT and AOT compiled iOS/Android applications.
* [`Frida`](https://www.frida.re/) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
* [`Ghidra`](https://www.ghidra-sre.org/) - Suite of free software reverse engineering tools developed by NSA's Research Directorate originally exposed in WikiLeaks's "Vault 7" publication and now maintained as open source software.
* [`Immunity Debugger`](https://immunityinc.com/products/debugger/) - Powerful way to write exploits and analyze malware.
* [`Interactive Disassembler (IDA Pro)`](https://www.hex-rays.com/products/ida/) - Proprietary multi-processor disassembler and debugger for Windows, GNU/Linux, or macOS; also has a free version, [`IDA Free`](https://www.hex-rays.com/products/ida/support/download_freeware.shtml).
* [`Medusa`](https://github.com/wisk/medusa) - Open source, cross-platform interactive disassembler.
* [`OllyDbg`](http://www.ollydbg.de/) - x86 debugger for Windows binaries that emphasizes binary code analysis.
* [`plasma`](https://github.com/joelpx/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
* [`pwndbg`](https://github.com/pwndbg/pwndbg) - GDB plug-in that eases debugging with GDB, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers, and exploit developers.
* [`PyREBox`](https://github.com/Cisco-Talos/pyrebox) - Python scriptable Reverse Engineering sandbox by Cisco-Talos.
* [`Radare2`](http://rada.re/r/index.html) - Open source, crossplatform reverse engineering framework.
* [`rVMI`](https://github.com/fireeye/rVMI) - Debugger on steroids; inspect userspace processes, kernel drivers, and preboot environments in a single tool.
* [`UEFITool`](https://github.com/LongSoft/UEFITool) - UEFI firmware image viewer and editor.
* [`Voltron`](https://github.com/snare/voltron) - Extensible debugger UI toolkit written in Python.
* [`WDK/WinDbg`](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) - Windows Driver Kit and WinDbg.
* [`x64dbg`](http://x64dbg.com/) - Open source x64/x32 debugger for windows.

------

## Samba Enumerating

**[`^        back to top        ^`](#overview)**

* [`enum4linux-ng`](https://github.com/cddmp/enum4linux-ng) - Checking public resources for specified ranges on the local network.
* [`MANSPIDER`](https://github.com/blacklanternsecurity/MANSPIDER) - Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported.
* [`smbclient-ng`](https://github.com/p0dalirius/smbclient-ng) - A fast and user friendly way to interact with SMB shares.
* [`smbmap`](https://github.com/ShawnDEvans/smbmap) - Checking public resources for specified ranges on the local network.
* [`SMBSR`](https://github.com/oldboy21/SMBSR) - Lookup for interesting stuff in SMB shares.

------

## Social Engineering

**[`^        back to top        ^`](#overview)**

See also *[`awesome-social-engineering`](https://github.com/v2-dev/awesome-social-engineering)*.

* [`Beelogger`](https://github.com/4w4k3/BeeLogger) - Tool for generating keylooger.
* [`Catphish`](https://github.com/ring0lab/catphish) - Tool for phishing and corporate espionage written in Ruby.
* [`Evilginx2`](https://github.com/kgretzky/evilginx2) - Standalone Machine-in-the-Middle (MitM) reverse proxy attack framework for setting up phishing pages capable of defeating most forms of 2FA security schemes.
* [`fakeinfo`](https://fakeinfo.net/) - Generate Fake Info.
* [`fake-telegram-chat-generator`](https://fakedetail.com/fake-telegram-chat-generator) - Generate your very own fake Telegram Messanger Chat.
* [`FiercePhish`](https://github.com/Raikia/FiercePhish) - Full-fledged phishing framework to manage all phishing engagements.
* [`Gophish`](https://getgophish.com) - Open-source phishing framework.
* [`King Phisher`](https://github.com/securestate/king-phisher) - Phishing campaign toolkit used for creating and managing multiple simultaneous phishing attacks with custom email and server content.
* [`Modlishka`](https://github.com/drk1wi/Modlishka) - Flexible and powerful reverse proxy with real-time two-factor authentication.
* [`phishery`](https://github.com/ryhanson/phishery) - TLS/SSL enabled Basic Auth credential harvester.
* [`ReelPhish`](https://github.com/fireeye/ReelPhish) - Real-time two-factor phishing tool.
* [`Social Engineer Toolkit (SET)`](https://github.com/trustedsec/social-engineer-toolkit) - Open source pentesting framework designed for social engineering featuring a number of custom attack vectors to make believable attacks quickly.
* [`Social Engineering Framework`](http://www.social-engineer.org/framework/general-discussion/) - Information resource for social engineers.
* [`SocialFish`](https://github.com/UndeadSec/SocialFish) - Social media phishing framework that can run on an Android phone or in a Docker container.
* [`wifiphisher`](https://github.com/sophron/wifiphisher) - Automated phishing attacks against WiFi networks.
* [`zeoob`](https://zeoob.com/) - Create Fake Instagram, Twitter & Facebook Posts.

------

## Static Analyzers

**[`^        back to top        ^`](#overview)**

* [`bandit`](https://pypi.python.org/pypi/bandit/) - Security oriented static analyser for Python code.
* [`Brakeman`](https://github.com/presidentbeef/brakeman) - Static analysis security vulnerability scanner for Ruby on Rails applications.
* [`cppcheck`](http://cppcheck.sourceforge.net/) - Extensible C/C++ static analyzer focused on finding bugs.
* [`cwe_checker`](https://github.com/fkie-cad/cwe_checker) - Suite of tools built atop the Binary Analysis Platform (BAP) to heuristically detect CWEs in compiled binaries and firmware.
* [`FindBugs`](http://findbugs.sourceforge.net/) - Free software static analyzer to look for bugs in Java code.
* [`Pixee`](https://pixee.ai) - Pixeebot finds security and code quality issues in your code and creates merge-ready pull requests with recommended fixes.
* [`Progpilot`](https://github.com/designsecurity/progpilot) - Static security analysis tool for PHP code.
* [`RegEx-DoS`](https://github.com/jagracey/RegEx-DoS) - Analyzes source code for Regular Expressions susceptible to Denial of Service attacks.
* [`sobelow`](https://github.com/nccgroup/sobelow) - Security-focused static analysis for the Phoenix Framework.

------

## Steganography Tools

**[`^        back to top        ^`](#overview)**

* [`Cloakify`](https://github.com/TryCatchHCF/Cloakify) - Textual steganography toolkit that converts any filetype into lists of everyday strings.
* [`StegCracker`](https://github.com/Paradoxis/StegCracker) - Steganography brute-force utility to uncover hidden data inside files.
* [`StegOnline`](https://stegonline.georgeom.net/) - Web-based, enhanced, and open-source port of StegSolve.

------

## Threat Intelligence

**[`^        back to top        ^`](#overview)**

See also *[`Awesome Threat Detection and Hunting`](https://github.com/0x4D31/awesome-threat-detection)* - A curated list of awesome threat detection and hunting resources.
See also *[`Awesome Threat Intelligence`](https://github.com/hslatman/awesome-threat-intelligence)* - A curated list of threat intelligence resources.
See also *[`Awesome Threat Modeling`](https://github.com/redshiftzero/awesome-threat-modeling)* - A curated list of Threat Modeling resources.

* [`abuse.ch`](https://www.abuse.ch/) - ZeuS Tracker / SpyEye Tracker / Palevo Tracker / Feodo Tracker tracks Command&Control servers (hosts) around the world and provides you a domain- and an IP-blocklist.
* [`AlienVault Open Threat Exchange`](http://www.alienvault.com/open-threat-exchange/dashboard) - AlienVault Open Threat Exchange (OTX), to help you secure your networks from data loss, service disruption and system compromise caused by malicious IP addresses.
* [`AutoShun`](https://www.autoshun.org/) - AutoShun is a Snort plugin that allows you to send your Snort IDS logs to a centralized server that will correlate attacks from your sensor logs with other snort sensors, honeypots, and mail filters from around the world.
* [`CIFv2`](https://github.com/csirtgadgets/massive-octo-spice) - CIF is a cyber threat intelligence management system. CIF allows you to combine known malicious threat information from many sources and use that information for identification (incident response), detection (IDS) and mitigation (null route).
* [`Cyberowl`](https://github.com/karimhabush/cyberowl) - A daily updated summary of the most frequent types of security incidents currently being reported from different sources.
* [`Cyware Threat Intelligence Feeds`](https://cyware.com/community/ctix-feeds) - Cyware’s Threat Intelligence feeds brings to you the valuable threat data from a wide range of open and trusted sources to deliver a consolidated stream of valuable and actionable threat intelligence. Our threat intel feeds are fully compatible with STIX 1.x and 2.0, giving you the latest information on malicious malware hashes, IPs and domains uncovered across the globe in real-time.
* [`DNS-BH`](http://www.malwaredomains.com/) - The DNS-BH project creates and maintains a listing of domains that are known to be used to propagate malware and spyware. This project creates the Bind and Windows zone files required to serve fake replies to localhost for any requests to these, thus preventing many spyware installs and reporting.
* [`Emerging Threats - Open Source`](http://doc.emergingthreats.net/bin/view/Main/EmergingFAQ) - Emerging Threats began 10 years ago as an open source community for collecting Suricata and SNORT® rules, firewall rules, and other IDS rulesets. The open source community still plays an active role in Internet security, with more than 200,000 active users downloading the ruleset daily. The ETOpen Ruleset is open to any user or organization, as long as you follow some basic guidelines. Our ETOpen Ruleset is available for download any time.
* [`FireEye OpenIOCs`](https://github.com/fireeye/iocs) - FireEye Publicly Shared Indicators of Compromise (IOCs)
* [`IntelMQ`](https://github.com/certtools/intelmq/) - IntelMQ is a solution for CERTs for collecting and processing security feeds, pastebins, tweets using a message queue protocol. It's a community driven initiative called IHAP (Incident Handling Automation Project) which was conceptually designed by European CERTs during several InfoSec events. Its main goal is to give to incident responders an easy way to collect & process threat intelligence thus improving the incident handling processes of CERTs. [ENSIA Homepage](https://www.enisa.europa.eu/activities/cert/support/incident-handling-automation).
* [`Internet Storm Center`](https://www.dshield.org/reports.html) - The ISC was created in 2001 following the successful detection, analysis, and widespread warning of the Li0n worm. Today, the ISC provides a free analysis and warning service to thousands of Internet users and organizations, and is actively working with Internet Service Providers to fight back against the most malicious attackers.
* [`leakedin.com`](http://www.leakedin.com/) - The primary purpose of leakedin.com is to make visitors aware about the risks of loosing data. This blog just compiles samples of data lost or disclosed on sites like pastebin.com.
* [`MISP - Open Source Threat Intelligence Platform`](https://www.misp-project.org/) - MISP threat sharing platform is a free and open source software helping information sharing of threat intelligence including cyber security indicators. A threat intelligence platform for gathering, sharing, storing and correlating Indicators of Compromise of targeted attacks, threat intelligence, financial fraud information, vulnerability information or even counter-terrorism information. The MISP project includes software, common libraries ([taxonomies](https://www.misp-project.org/taxonomies.html), [threat-actors and various malware](https://www.misp-project.org/galaxy.html)), an extensive data model to share new information using [objects](https://www.misp-project.org/objects.html) and default [feeds](https://www.misp-project.org/feeds/).
* [`OpenVAS NVT Feed`](http://www.openvas.org/openvas-nvt-feed.html) - The public feed of Network Vulnerability Tests (NVTs). It contains more than 35,000 NVTs (as of April 2014), growing on a daily basis. This feed is configured as the default for OpenVAS.
* [`PhishStats`](https://phishstats.info/) - Phishing Statistics with search for IP, domain and website title.
* [`PhishTank`](http://www.phishtank.com/) - PhishTank is a collaborative clearing house for data and information about phishing on the Internet. Also, PhishTank provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.
* [`Project Honey Pot`](http://www.projecthoneypot.org/) - Project Honey Pot is the first and only distributed system for identifying spammers and the spambots they use to scrape addresses from your website. Using the Project Honey Pot system you can install addresses that are custom-tagged to the time and IP address of a visitor to your site. If one of these addresses begins receiving email we not only can tell that the messages are spam, but also the exact moment when the address was harvested and the IP address that gathered it.
* [`SBL / XBL / PBL / DBL / DROP / ROKSO`](http://www.spamhaus.org/) - The Spamhaus Project is an international nonprofit organization whose mission is to track the Internet's spam operations and sources, to provide dependable realtime anti-spam protection for Internet networks, to work with Law Enforcement Agencies to identify and pursue spam and malware gangs worldwide, and to lobby governments for effective anti-spam legislation.
* [`Threat Jammer`](https://threatjammer.com) - REST API service that allows developers, security engineers, and other IT professionals to access curated threat intelligence data from a variety of sources.
* [`Tor Bulk Exit List`](https://metrics.torproject.org/collector.html) - CollecTor, your friendly data-collecting service in the Tor network. CollecTor fetches data from various nodes and services in the public Tor network and makes it available to the world. If you're doing research on the Tor network, or if you're developing an application that uses Tor network data, this is your place to start. [TOR Node List](https://www.dan.me.uk/tornodes) / [DNS Blacklists](https://www.dan.me.uk/dnsbl) / [Tor Node List](http://torstatus.blutmagie.de/)
* [`virustotal`](https://www.virustotal.com/) - VirusTotal, a subsidiary of Google, is a free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners. At the same time, it may be used as a means to detect false positives, i.e. innocuous resources detected as malicious by one or more scanners.

------

## Vulnerability Databases

**[`^        back to top        ^`](#overview)**

* [`Bugtraq (BID)`](http://www.securityfocus.com/bid/) - Software security bug identification database compiled from submissions to the SecurityFocus mailing list and other sources, operated by Symantec, Inc.
* [`China National Vulnerability Database (CNNVD)`](http://www.cnnvd.org.cn/) - Chinese government-run vulnerability database analoguous to the United States's CVE database hosted by Mitre Corporation.
* [`Common Vulnerabilities and Exposures (CVE)`](https://cve.mitre.org/) - Dictionary of common names (i.e., CVE Identifiers) for publicly known security vulnerabilities.
* [`CXSecurity`](https://cxsecurity.com/) - Archive of published CVE and Bugtraq software vulnerabilities cross-referenced with a Google dork database for discovering the listed vulnerability.
* [`Exploit-DB`](https://www.exploit-db.com/) - Non-profit project hosting exploits for software vulnerabilities, provided as a public service by Offensive Security.
* [`Full-Disclosure`](http://seclists.org/fulldisclosure/) - Public, vendor-neutral forum for detailed discussion of vulnerabilities, often publishes details before many other sources.
* [`GitHub Advisories`](https://github.com/advisories/) - Public vulnerability advisories published by or affecting codebases hosted by GitHub, including open source projects.
* [`HPI-VDB`](https://hpi-vdb.de/) - Aggregator of cross-referenced software vulnerabilities offering free-of-charge API access, provided by the Hasso-Plattner Institute, Potsdam.
* [`Inj3ct0r`](https://www.0day.today/) - Exploit marketplace and vulnerability information aggregator. ([`Onion service`](http://mvfjfugdwgc5uwho.onion/).)
* [`Microsoft Security Advisories and Bulletins`](https://docs.microsoft.com/en-us/security-updates/) - Archive and announcements of security advisories impacting Microsoft software, published by the Microsoft Security Response Center (MSRC).
* [`Mozilla Foundation Security Advisories`](https://www.mozilla.org/security/advisories/) - Archive of security advisories impacting Mozilla software, including the Firefox Web Browser.
* [`National Vulnerability Database (NVD)`](https://nvd.nist.gov/) - United States government's National Vulnerability Database provides additional meta-data (CPE, CVSS scoring) of the standard CVE List along with a fine-grained search engine.
* [`Open Source Vulnerabilities (OSV)`](https://osv.dev/) - Database of vulnerabilities affecting open source software, queryable by project, Git commit, or version.
* [`Packet Storm`](https://packetstormsecurity.com/files/) - Compendium of exploits, advisories, tools, and other security-related resources aggregated from across the industry.
* [`Rapid7`](https://www.rapid7.com/db/) - Vulnerability & Exploit Database.
* [`SecuriTeam`](http://www.securiteam.com/) - Independent source of software vulnerability information.
* [`Snyk Vulnerability DB`](https://snyk.io/vuln/) - Detailed information and remediation guidance for vulnerabilities known by Snyk.
* [`Sploitus`](https://sploitus.com/) - Convenient central place for identifying the newest exploits and finding attacks that exploit known vulnerabilities.
* [`US-CERT Vulnerability Notes Database`](https://www.kb.cert.org/vuls/) - Summaries, technical details, remediation information, and lists of vendors affected by software vulnerabilities, aggregated by the United States Computer Emergency Response Team (US-CERT).
* [`VulDB`](https://vuldb.com) - Independent vulnerability database with user community, exploit details, and additional meta data (e.g. CPE, CVSS, CWE)
* [`Vulmon`](https://vulmon.com/) - Vulnerability search engine with vulnerability intelligence features that conducts full text searches in its database.
* [`Vulnerability Lab`](https://www.vulnerability-lab.com/) - Open forum for security advisories organized by category of exploit target.
* [`Vulners`](https://vulners.com/) - Security database of software vulnerabilities.
* [`Zero Day Initiative`](http://zerodayinitiative.com/advisories/published/) - Bug bounty program with publicly accessible archive of published security advisories, operated by TippingPoint.

------

## Web

**[`^        back to top        ^`](#overview)**

See also *[`Awesome Web Hacking`](https://github.com/infoslack/awesome-web-hacking*)* - This list is for anyone wishing to learn about web application security but do not have a starting point.

* [`OWASP`](http://www.owasp.org) - The Open Web Application Security Project (OWASP) is a 501(c)(3) worldwide not-for-profit charitable organization focused on improving the security of software.
* [`Portswigger`](https://portswigger.net) - PortSwigger offers tools for web application security, testing & scanning. Choose from a wide range of security tools & identify the very latest vulnerabilities.

### Web Accessible Source Code Ripping Tools

**[`^        back to top        ^`](#overview)**

* [`DVCS Ripper`](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG/BZR.
* [`GitTools`](https://github.com/internetwache/GitTools) - Automatically find and download Web-accessible `.git` repositories.
* [`git-dumper`](https://github.com/arthaud/git-dumper) - Tool to dump a git repository from a website.
* [`git-scanner`](https://github.com/HightechSec/git-scanner) - Tool for bug hunting or pentesting websites that have open `.git` repositories available in public.

### Web Application Firewall

**[`^        back to top        ^`](#overview)**

* [`Curiefense`](https://github.com/curiefense/curiefense) - Curiefense adds a broad set of automated web security tools, including a WAF to Envoy Proxy.
* [`ironbee`](https://github.com/ironbee/ironbee) - IronBee is an open source project to build a universal web application security sensor. IronBee as a framework for developing a system for securing web applications - a framework for building a web application firewall (WAF).
* [`ModSecurity`](http://www.modsecurity.org/) - ModSecurity is a toolkit for real-time web application monitoring, logging, and access control.
* [`NAXSI`](https://github.com/nbs-system/naxsi) - NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX, NAXSI means Nginx Anti Xss & Sql Injection.
* [`sql_firewall`](https://github.com/uptimejp/sql_firewall) SQL Firewall Extension for PostgreSQL.

### Web Exploitation

**[`^        back to top        ^`](#overview)**

* [`autochrome`](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/march/autochrome/) - Chrome browser profile preconfigured with appropriate settings needed for web application testing.
* [`badtouch`](https://github.com/kpcyrd/badtouch) - Scriptable network authentication cracker.
* [`corschecker`](https://github.com/Miladkhoshdel/corschecker) - Java Script for performing CORS security test.
* [`FuzzDB`](https://github.com/fuzzdb-project/fuzzdb) - Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
* [`gobuster`](https://github.com/OJ/gobuster) - Lean multipurpose brute force search/fuzzing tool for Web (and DNS) reconnaissance.
* [`h2t`](https://github.com/gildasio/h2t) - HTTP Hardening Tool for scans a website and suggests security headers to apply.
* [`Offensive Web Testing Framework (OWTF)`](https://www.owasp.org/index.php/OWASP_OWTF) - Python-based framework for pentesting Web applications based on the OWASP Testing Guide.
* [`Parth`](https://github.com/s0md3v/Parth) - Heuristic Vulnerable Parameter Scanner.
* [`PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads and bypass for Web Application Security and Pentest/CTF
* [`Raccoon`](https://github.com/evyatarmeged/Raccoon) - High performance offensive security tool for reconnaissance and vulnerability scanning.
* [`sslstrip2`](https://github.com/LeonardoNve/sslstrip2) - SSLStrip version to defeat HSTS.
* [`sslstrip`](https://www.thoughtcrime.org/software/sslstrip/) - Demonstration of the HTTPS stripping attacks.
* [`WPSploit`](https://github.com/espreto/wpsploit) - Exploit WordPress-powered websites with Metasploit.

### Web File Inclusion Tools

**[`^        back to top        ^`](#overview)**

* [`fimap`](https://github.com/kurobeats/fimap) - Find, prepare, audit, exploit and even Google automatically for LFI/RFI bugs.
* [`Kadimus`](https://github.com/P0cL4bs/Kadimus) - LFI scan and exploit tool.
* [`LFISuite`](https://github.com/D35m0nd142/LFISuite) - Automatic LFI scanner and exploiter.
* [`liffy`](https://github.com/hvqzao/liffy) - LFI exploitation tool.

### Web Injection Tools

**[`^        back to top        ^`](#overview)**

* [`Commix`](https://github.com/commixproject/commix) - Automated all-in-one operating system command injection and exploitation tool.
* [`NoSQLmap`](https://github.com/codingo/NoSQLMap) - Automatic NoSQL injection and database takeover tool.
* [`SQLmap`](http://sqlmap.org/) - Automatic SQL injection and database takeover tool.
* [`tplmap`](https://github.com/epinna/tplmap) - Automatic server-side template injection and Web server takeover tool.

### Web Path Discovery / Bruteforcing Tools

**[`^        back to top        ^`](#overview)**

* [`dirhunt`](https://github.com/Nekmo/dirhunt) - Find web directories without bruteforce.
* [`dirsearch`](https://github.com/maurosoria/dirsearch) - Web path scanner.
* [`DotDotPwn`](https://dotdotpwn.blogspot.com/) - Directory traversal fuzzer.
* [`GooFuzz`](https://github.com/m3n0sd0n4ld/GooFuzz) - Tool to perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches (Google Dorking).
* [`lulzbuster`](https://github.com/noptrix/lulzbuster) - Search files and folders on web-sites.
* [`recursebuster`](https://github.com/c-sto/recursebuster) - Content discovery tool to perform directory and file bruteforcing.

### Web Proxies Intercepting

**[`^        back to top        ^`](#overview)**

See also *[`Proxies and Machine-in-the-Middle (MITM) Tools`](#proxies-and-machine-in-the-middle-mitm-tools)*.

* [`Burp Suite`](https://portswigger.net/burp/) - Integrated platform for performing security testing of web applications.
* [`Fiddler`](https://www.telerik.com/fiddler) - Free cross-platform web debugging proxy with user-friendly companion tools.
* [`mitmproxy`](https://mitmproxy.org/) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers.
* [`OWASP Zed Attack Proxy (ZAP)`](https://www.zaproxy.org/) - Feature-rich, scriptable HTTP intercepting proxy and fuzzer for penetration testing web applications.

### Web Shells / C2 Frameworks

**[`^        back to top        ^`](#overview)**

* [`Browser Exploitation Framework (BeEF)`](https://github.com/beefproject/beef) - Command and control server for delivering exploits to commandeered Web browsers.
* [`DAws`](https://github.com/dotcppfile/DAws) - Advanced Web shell.
* [`Merlin`](https://github.com/Ne0nd0g/merlin) - Cross-platform post-exploitation HTTP/2 Command and Control server and agent written in Golang.
* [`PhpSploit`](https://github.com/nil0x42/phpsploit) - Full-featured C2 framework which silently persists on webserver via evil PHP oneliner.
* [`SharPyShell`](https://github.com/antonioCoco/SharPyShell) - Tiny and obfuscated ASP.NET webshell for C# web applications.
* [`weevely3`](https://github.com/epinna/weevely3) - Weaponized PHP-based web shell.

### Web Subdomains

**[`^        back to top        ^`](#overview)**

* [`Dome`](https://github.com/v4d1/Dome) - Subdomain enumeration tool, fast and reliable python script that makes active and/or passive scan to obtain subdomains and search for open ports.
* [`knock`](https://github.com/guelfoweb/knock) - Python3 tool designed to quickly enumerate subdomains on a target domain through dictionary attack.
* [`subbrute`](https://github.com/TheRook/subbrute) - DNS meta-query spider that enumerates DNS records, and subdomains.
* [`subDomainsBrute`](https://github.com/lijiejie/subDomainsBrute) - Fast sub domain brute tool for pentesters.
* [`subfinder`](https://github.com/projectdiscovery/subfinder) - Subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.
* [`Sublist3r`](https://github.com/aboul3la/Sublist3r) - Fast subdomains enumeration tool for penetration testers.

### Web Vulnerability Scanners

**[`^        back to top        ^`](#overview)**

* [`ACSTIS`](https://github.com/tijme/angularjs-csti-scanner) - Automated client-side template injection (sandbox escape/bypass) detection for AngularJS.
* [`Arachni`](http://www.arachni-scanner.com/) - Scriptable framework for evaluating the security of web applications.
* [`cms-explorer`](https://code.google.com/archive/p/cms-explorer/) - Reveal the specific modules, plugins, components and themes that various websites powered by content management systems are running.
* [`Cyclops`](https://github.com/v8blink/Chromium-based-XSS-Taint-Tracking) - The Cyclops is a web browser with XSS detection feature, it is chromium-based xss detection that used to find the flows from a source to a sink.
* [`is-website-vulnerable`](https://github.com/lirantal/is-website-vulnerable) - finds publicly known security vulnerabilities in a website's frontend JavaScript libraries.
* [`JCS`](https://github.com/TheM4hd1/JCS) - Joomla Vulnerability Component Scanner with automatic database updater from exploitdb and packetstorm.
* [`joomscan`](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project) - Joomla vulnerability scanner.
* [`katana`](https://github.com/projectdiscovery/katana) - A next-generation crawling and spidering framework.
* [`Keyscope`](https://github.com/SpectralOps/keyscope) - Keyscope is an extensible key and secret validation for checking active secrets against multiple SaaS vendors built in Rust.
* [`Nikto`](https://cirt.net/nikto2) - Noisy but fast black box web server and web application vulnerability scanner.
* [`Recon-ng`](https://github.com/lanmaster53/recon-ng) - Recon-ng is a full-featured Web Reconnaissance framework written in Python. Recon-ng has a look and feel similar to the Metasploit Framework.
* [`recon`](https://github.com/rusty-ferris-club/recon) - a fast Rust based CLI that uses SQL to query over files, code, or malware with content classification and processing for security experts.
* [`reconFTW`](https://github.com/six2dez/reconftw) - A tool designed to perform automated recon on a target domain by running the best set of tools to perform scanning and finding out vulnerabilities.
* [`Scanmycode CE (Community Edition)`](https://github.com/marcinguy/scanmycode-ce) - Code Scanning/SAST/Static Analysis/Linting using many tools/Scanners with One Report. Currently supports: PHP, Java, Scala, Python, Ruby, Javascript, GO, Secret Scanning, Dependency Confusion, Trojan Source, Open Source and Proprietary Checks (total ca. 1000 checks)
* [`SecApps`](https://secapps.com/) - In-browser web application security testing suite.
* [`skipfish`](https://www.kali.org/tools/skipfish/) - Performant and adaptable active web application security reconnaissance tool.
* [`sqlmap`](http://sqlmap.org/) - sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.
* [`SQLmate`](https://github.com/UltimateHackers/sqlmate) - Friend of `sqlmap` that identifies SQLi vulnerabilities based on a given dork and (optional) website.
* [`urlscan`](urlscan.io) - Website scanner for suspicious and malicious URLs.
* [`w3af`](https://github.com/andresriancho/w3af) - Web application attack and audit framework.
* [`Wapiti`](http://wapiti.sourceforge.net/) - Black box web application vulnerability scanner with built-in fuzzer.
* [`WebReaver`](https://www.webreaver.com/) - Commercial, graphical web application vulnerability scanner designed for macOS.
* [`WPScan`](https://wpscan.org/) - Black box WordPress vulnerability scanner.
* [`ZAP`](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications. It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing. ZAP provides automated scanners as well as a set of tools that allow you to find security vulnerabilities manually.

------

## Web Servers

**[`^        back to top        ^`](#overview)**

* [`nginx playground`](https://nginx-playground.wizardzines.com/) - Paste in an nginx config, and then a server starts nginx for you and runs any curl or http command you want against that nginx server.
* [`nginxpwner`](https://github.com/stark0de/nginxpwner) - Simple tool to look for common Nginx misconfigurations and vulnerabilities.
* [`Server Side TLS`](https://wiki.mozilla.org/Security/Server_Side_TLS) - help teams with the configuration of TLS.

------

## Useful Resources

### Documents / Images

**[`^        back to top        ^`](#overview)**

* [`documents`](documents)
* [`images`](images)

### Security Awesome Lists

**[`^        back to top        ^`](#overview)**

* [`Awesome Anti Forensics`](https://github.com/remiflavien1/awesome-anti-forensic) - A collection of awesome tools used to counter forensics activities.
* [`Awesome AppSec`](https://github.com/paragonie/awesome-appsec) - Resources for learning about application security.
* [`Awesome ARM Exploitation`](https://github.com/HenryHoggard/awesome-arm-exploitation) - A curated list of ARM exploitation resources.
* [`Awesome Blue Team`](https://github.com/fabacab/awesome-cybersecurity-blueteam) - Awesome resources, tools, and other shiny things for cybersecurity blue teams.
* [`Awesome Bluetooth Security`](https://github.com/engn33r/awesome-bluetooth-security) - A curated list of Bluetooth security resources.
* [`Awesome Censys Queries`](https://github.com/thehappydinoa/awesome-censys-queries) - A collection of fascinating and bizarre Censys Search Queries.
* [`Awesome Container Security`](https://github.com/kai5263499/container-security-awesome) - A curated list of awesome resources related to container building and runtime security
* [`Awesome Crypto Papers`](https://github.com/pFarb/awesome-crypto-papers) - A curated list of cryptography papers, articles, tutorials and howtos.
* [`Awesome Electron.js Hacking`](https://github.com/doyensec/awesome-electronjs-hacking) - A curated list of awesome resources about Electron.js (in)security
* [`Awesome Hacking`](https://github.com/carpedm20/awesome-hacking) - A curated list of awesome Hacking tutorials, tools and resources.
* [`Awesome Incident Response`](https://github.com/meirwah/awesome-incident-response) - A curated list of resources for incident response.
* [`Awesome Industrial Control System Security`](https://github.com/mpesen/awesome-industrial-control-system-security) - A curated list of resources related to Industrial Control System (ICS) security.
* [`Awesome Infosec`](https://github.com/onlurking/awesome-infosec) - Information security resources for pentesting, forensics, and more.
* [`Awesome Linux Containers`](https://github.com/Friz-zy/awesome-linux-containers) - A curated list of awesome Linux Containers frameworks, libraries and software.
* [`Awesome Malware`](https://github.com/fabacab/awesome-malware) - Curated collection of awesome malware, botnets, and other post-exploitation tools.
* [`Awesome PCAP Tools`](https://github.com/caesar0301/awesome-pcaptools) - A collection of tools developed by other researchers in the Computer Science area to process network traces.
* [`Awesome Personal Security`](https://github.com/Lissy93/personal-security-checklist) - A curated list of digital security and privacy tips, with links to further resources.
* [`Awesome Privacy`](https://github.com/lissy93/awesome-privacy) - A curated list of privacy-respecting software and services.
* [`Awesome Red Teaming`](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming) - List of Awesome Red Teaming Resources.
* [`Awesome Security Hardening`](https://github.com/decalage2/awesome-security-hardening) - A collection of awesome security hardening guides, best practices, checklists, benchmarks, tools and other resources.
* [`Awesome Security Newsletters`](https://github.com/TalEliyahu/awesome-security-newsletters) - A curated list of awesome newsletters to keep up to date on security news via e-mail.
* [`Awesome Security Talks & Videos`](https://github.com/PaulSec/awesome-sec-talks) - A curated list of awesome security talks, organized by year and then conference.
* [`Awesome Security`](https://github.com/sbilly/awesome-security) - Software, libraries, documents, and other resources.
* [`Awesome Serverless Security`](https://github.com/puresec/awesome-serverless-security/) - Curated list of awesome serverless security resources such as (e)books, articles, whitepapers, blogs and research papers.
* [`Awesome Shell Scripting`](https://github.com/alebcay/awesome-shell) - Command line frameworks, toolkits, guides and gizmos.
* [`Awesome Shodan Search Queries`](https://github.com/jakejarvis/awesome-shodan-queries) - A collection of interesting, funny, and depressing search queries to plug into Shodan.
* [`Awesome SOAR`](https://github.com/correlatedsecurity/Awesome-SOAR) - A curated Cyber "Security Orchestration, Automation and Response (SOAR)" resources list.
* [`Awesome WebSocket Security`](https://github.com/PalindromeLabs/awesome-websocket-security) - A curated list of WebSocket security resources.
* [`Awesome YARA`](https://github.com/InQuest/awesome-yara) - A curated list of awesome YARA rules, tools, and people.
* [`Security Acronyms`](https://github.com/cloudsecurelab/security-acronyms) - A curated list of security related acronyms and concepts

### Other Lists

**[`^        back to top        ^`](#overview)**

* [`lists`](https://github.com/jnv/lists) - The definitive list of (awesome) lists curated on GitHub.
* [`awesome-awesomeness`](https://github.com/bayandin/awesome-awesomeness) - awesome-* or *-awesome lists.
* [`Awesome Analytics`](https://github.com/0xnr/awesome-analytics)
* [`Awesome Self-Hosted`](https://github.com/awesome-selfhosted/awesome-selfhosted)
* [`Awesome Sysadmin`](https://github.com/awesome-foss/awesome-sysadmin)
* [`Azure Security`](https://www.manning.com/books/azure-security-2) - A practical guide to the native security services of Microsoft Azure.
* [`DevOps Exercises`](https://github.com/bregman-arie/devops-exercises)
* [`DevOps Roadmap`](https://github.com/milanm/DevOps-Roadmap)
* [`InfoSec & Hacking challenges`](https://github.com/AnarchoTechNYC/meta/wiki/InfoSec#hacking-challenges) - Comprehensive directory of CTFs, wargames, hacking challenge websites, pentest practice lab exercises, and more.
* [`Infosec / Hacking videos recorded by cooper`](https://administraitor.video) - Collection of security conferences recorded by Cooper.
* [`Kali Linux Tools`](http://tools.kali.org/tools-listing) - List of tools present in Kali Linux.
* [`Movies For Hacker`](https://github.com/k4m4/movies-for-hackers) - A curated list of movies every hacker & cyberpunk must watch.
* [`Python tools for penetration testers`](https://github.com/dloss/python-pentest-tools) - Lots of pentesting tools are written in Python.
* [`Rawsec's CyberSecurity Inventory`](https://inventory.raw.pm/) - An open-source inventory of tools, resources, CTF platforms and Operating Systems about CyberSecurity. ([`Source`](https://gitlab.com/rawsec/rawsec-cybersecurity-list))
* [`SecLists`](https://github.com/danielmiessler/SecLists) - Collection of multiple types of lists used during security assessments.
* [`SecTools`](http://sectools.org/) - Top 125 Network Security Tools.
* [`Securing DevOps`](https://manning.com/books/securing-devops) - A book on Security techniques for DevOps that reviews state of the art practices used in securing web applications and their infrastructure.
* [`test-your-sysadmin-skills`](https://github.com/trimstray/test-your-sysadmin-skills)
* [`.NET Programming`](https://github.com/quozd/awesome-dotnet) - Software framework for Microsoft Windows platform development.
* [`C/C++ Programming`](https://github.com/fffaraz/awesome-cpp) - One of the main language for open source security tools.
* [`JavaScript Programming`](https://github.com/sorrycc/awesome-javascript) - In-browser development and scripting.
* [`Node.js Programming by @sindresorhus`](https://github.com/sindresorhus/awesome-nodejs) - Curated list of delightful Node.js packages and resources.
* [`Ruby Programming by @Sdogruyol`](https://github.com/Sdogruyol/awesome-ruby) - The de-facto language for writing exploits.
* [`Ruby Programming by @dreikanter`](https://github.com/dreikanter/ruby-bookmarks) - The de-facto language for writing exploits.
* [`Ruby Programming by @markets`](https://github.com/markets/awesome-ruby) - The de-facto language for writing exploits.

------

## Other

**[`^        back to top        ^`](#overview)**

* [`development/curlconverter`](https://curlconverter.com/) - Convert curl commands to Python, JavaScript and more.
* [`development/Text to ASCII`](http://patorjk.com/software/taag/) - Text to ASCII Art Generator (TAAG).
* [`funny/genact`](https://github.com/svenstaro/genact) - Nonsense activity generator.

------

## [Contributing](CONTRIBUTING.md)

**[`^        back to top        ^`](#overview)**

Your contributions and suggestions are heartily welcome. Please, check the [Guide](CONTRIBUTING.md) for more details.

If you want to propose changes, just open an [issue](https://github.com/kraloveckey/venom/issues) or a [pull request](https://github.com/kraloveckey/venom/pulls).

------