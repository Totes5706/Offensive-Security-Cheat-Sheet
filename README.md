# Offensive Security Tools

***

<br />

Here you will find a useful collection of commands and file resource locations used in Pentesting operations. This reference is will go hand in hand with Kali Linux.

<br />

***
<br />
<br />

# General Enumeration

***
 
## NMAP

<br />

**OVERVIEW**
 
|   |  	 | 
| :-----------: | :-----------: |
| Description | 	  A network scanning tool that identifies devices, ports, services, and operating systems  | 
| Download | Pre-installed on Kali Linux  |   

<br />

**USAGE**

<br />

```bash
nmap -p- --min-rate 5000 -sC -sV {IP ADDRESS}
```

<br />


<br />

## NMAP Automator

<br />

**OVERVIEW**

|   |  	 | 
| :-----------: | :-----------: |
| Description | 	Useful script that automates multiple enumeration scans in succession  | 
| Download | [nmapAutomator.sh](https://github.com/21y4d/nmapAutomator/blob/master/nmapAutomator.sh) |    

<br />

**USAGE**

<br />

```bash
./nmapAutomator.sh --host {IP ADDRESS} --type All
```

<br />

***

# Port Enumeration


## FTP [21]


## SSH [22] 


## DNS [53]


## FINGER [79]


## Web Server [80, 443]


## Kerberos [88] 


## POP3 [110] 


## SNMP [161] 


## LDAP [389]


## SMB [445]


## MSSQL [1433] 


## NFS [2049]


## RDP [3389]

## WINRM [5985, 5986] 

### Linux

<br />

**OVERVIEW**
 
|   |  	 | 
| :-----------: | :-----------: |
| Description | 	  A tool used to hack WINRM from a linux console | 
| Download | Pre-installed on Kali Linux  |   

<br />

**USAGE**

<br />

```bash
evil-winrm -i {IP ADDRESS} -u {USERNAME} -p {PASSWORD}
```

<br />


<br />


### Windows

# Reverse Shell

## Linux

## Windows

# Privilege Escalation

## Linux

## Windows

# Password Cracking
