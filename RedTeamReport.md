# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -ss -sv -Pn -n -0 192.168.1.ø/24
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-19 20:58 PDT
Nmap scan report for 192.168.1.1
Host is up (0.00047s latency).
Not shown: 995 filtered ports
PORT STATE SERVICE VERSION
135/tcp open msrpc Microsoft Windows RPC 
139/tcp open netbios-ssn Microsoft Windows netbios-ssn 
445/tcp open microsoft-ds? 
2179/tcp open vmrdp? 
3389/tcp open ms-wbt-server Microsoft Terminal Services 
MAC Address: 00:15:50:00:04:0D (Microsoft) Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port! Device type: general purpose Running (JUST GUESSING): Microsoft Windows XP 72008 (87%) OS CPE: cpe:/o:microsoft:windows_xp :: sp2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008 :: sp1 cpe:/o:microsoft:windows_serv er_2008:r2 Aggressive os guesses: Microsoft Windows XP SP2 (87%), Microsoft Windows 7 (85%), Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (85%) No exact OS matches for host (test conditions non-ideal). Network Distance: 1 hop Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Nmap scan report for 192.168.1.100 Host is up (0.00055s latency). Not shown: 998 closed ports PORT STATE SERVICE VERSION 22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 9200/tcp open http Elasticsearch REST API 7.6.1 (name: elk; cluster: elasticsearch; Lucene 8.4.0) MAC Address: 4C:EB:42:02:05:07 (Intel Corporate) No exact Os matches for host (If you know what os is running on it, see https://nmap.org/submit/ ). TCP/IP fingerprint: OS:SCAN(VEZ.80%E=4%D=3/19%OT=22%CT=1%CU=37956%PV=Y%DS=1%DC=D%G=Y%M=4CEB42%T OS:M=605572F8%P=x86_64-pc-linux-gnu) SEQTSP=107%GCD=1%ISR=10C%TI=Z%CI=Z%IINI OS:%TS=A) OPS(01=M5B4ST11NW7%02=M5B4ST11NW7%03=M5B4NNT11NW7%04=M5B4ST11NW7%O OS:5=M5B4ST11NW7%06=M5B4ST11) WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6 OS:=FE88 ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=YXQ=)T1(R=Y%DF=Y%T=40%S=0 OS:%A=S+%F=AS%RD=0%Q=)T2(REN)T3(R=N T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RDE OS: 0%Q=) T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%0=%RD=0%Q=)T6 (R=Y%DF=Y%T=40%W=0% OS:S=A%A=ZXF=R%0=%RD=0%Q=)17(R=Y%DF=Y%T=40%W=0%S-Z%AES+%F=AR%0=%RD=0%Q=)U1 OS: R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUDEGIER=Y%DFI= OS:N%T=40%CD=S)
Network Distance: 1 hop Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This scan identifies the services below as potential points of entry:
- Target 1
  - Port 22 OpenSSH 6.7p1 Debian 5+de8u4 (protocol 2.0)
  - Port 80 Apache httpd 2.4.10 ((Debian))
  - Port 111 rpcbind
  - Port 139 Samba smbd 3.x - 4.x
  - Port 445 Samba smbd 3.x - 4.x 

_TODO: Fill out the list below. Include severity, and CVE numbers, if possible._

The following vulnerabilities were identified on each target:
- Target 1
  - Enumerable users
  - Brute forceable SSH password
  - Insecure SQL Password Storage
  - Improper sudoers file configuration

_TODO: Include vulnerability scan results to prove the identified vulnerabilities._

### Exploitation
_TODO: Fill out the details below. Include screenshots where possible._

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: flag1{b9bbcb33e11b80be759c4e844862482d}
    - **wpscan**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
  - `flag2.txt`: flag2{fc3fd58dcdad9ab23faca6e9a36e581c}
    - **Brute forceable SSH password**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
  - `flag3.txt`: flag3{afc01ab56b5091e7dccf93122770cd2}
    - **Insecure Password Storage**
      - The password to the Wordpress server's SQL database is stored in plaintext in wp-config.php
      - nano /var/www/html/wordpress/wp-config.php
  - `flag4.txt`: flag4{715dea6c055b9fe3337544932f2941ce}
    - **Improper sudoers file configuration**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_