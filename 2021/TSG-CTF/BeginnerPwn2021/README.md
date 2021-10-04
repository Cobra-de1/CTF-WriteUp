# Beginner's Pwn 2021

![](/2021/TSG-CTF/BeginnerPwn2021/images/1.png)

The challenges give me 3 file chall, chall.c, flag (fake flag)

Look at source code of chall.c

The program read 64 byte of flag and stored it in flag buffer

I see that function win will give me a shell, and I need to pass the strncmp(your_try, flag, length).

This is a defination of strncmp in cplusplus.com

![](/2021/TSG-CTF/BeginnerPwn2021/images/2.png)

So it with compare each charracter one by one until reach the null or size num. Size num here is length with is the length of hold flag.

## The bug

The bug here is at `scanf(“%64s”, your_try)`;

Your_try have length 64 and scanf will add a NULL byte after last charracter input, so if we input full 64 charracter, it will add one NULL behind and so that it out of buffer and we have one NULL byte overflow.

I think that it would overwrite the flag array, the first character of the flag array to NULL, so when strncmp run, it only compare the first character of the two arrays.

Check the buffer with IDA

![](/2021/TSG-CTF/BeginnerPwn2021/images/3.png)

The distance between of two array is 64, so the above thinking is correct. We just need to push the first charracter of your_try to be a NULL, and fill all 63 remaining characters. Because program use scanf, it eazy.

File [solve.py](/2021/TSG-CTF/BeginnerPwn2021/solve.py)

```python
from pwn import *
#s = process('./chall')
s = remote('34.146.101.4', 30007)
s.sendline(p64(0) * 8)
s.interactive()
```

`flag: TSGCTF{just_a_simple_off_by_one-chall_isnt_it}`
