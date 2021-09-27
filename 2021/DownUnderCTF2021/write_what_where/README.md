# write what where

![](/2021/DownUnderCTF2021/write_what_where/Images/1.png)

Check the ELF

![](/2021/DownUnderCTF2021/write_what_where/Images/2.png)

Let reverse it

![](/2021/DownUnderCTF2021/write_what_where/Images/3.png)

The challenge is really insteresting. They allow us to write 4 byte on some address we can choose, but we can only write one time. 

Checking the ELF, we find that the PIE is not turn on. Mean that we all address in ELF file include function address, plt address, got address will be fixed. And RELRO is Partial RELRO, so we can write to the GOT table.

If you don't know anything about GOT, you can search google Global offset tabble. I will summarize it as follows. When the program is dynamically compiled. It does not include the entire source code of the library functions. (Example scanf, gets, printf, puts, exit, ...) but generates the function plt (produce link table). Plt function is responsible for jumping to the value set at a certain position in the GOT. When the program runs, the operating system places the actual addresses of libc (plus the libc base via the aslr mechanism) into the GOT table so that the PLT function can jump to and execute code.

So with the GOT, we can: leak the libc or change the value point to another place to change the flow of the program. 

One important thing you have to know that is GOT tabble is not fill when program starting, it fill when the funtion call the first time by the program. Before it, it point to ELF code with call a special function to find that address in libc. I mention here for ease of explanation later.

## So how we use it to get the shell?

First thing we need to do, of courcse, is change the exit GOT to another function, to prevent the program to exit. In this program, I change exit back to main, because we didn’t know anything about libc base, so we cannot use one gadget. I can change it to main because the exit function didn’t call in program before, so the value in GOT table now point to code to call special function I mentioned above. It really importtant because you can write only 4 byte, not 8 byte. And if the address alreaydy loaded before you change, it will have 2 high byte and it will cause segment fault.

After change the exit GOT to main, we have the infinity loop of main function. So we can overwrite as many times as we want.

My direction in this chall is to change atoi function to system, then put the string "/bin/sh" into the nptr variable, then when calling atoi("/bin/sh"), the program will do system(" /bin/sh")

Because the GOT already have the real address of function in libc, if we want to change to another function at libc, we don’t need to leak hole libc address, just overwrite 2 or 3 last byte of the address.

Checking the libc they gave, I found one thing

![](/2021/DownUnderCTF2021/write_what_where/Images/4.png)

The offset of atoi and system is different only 2 last byte, since 1.5 last byte alwayls fixed. So the success rate is 1/16 per attemp. For example, if libcbase is 0x7ffff7dc2000 then the real address is

```
System: 0x7ffff7dc2000 + 0x4fa60 = 0x7ffff7e11a60
Atoi: 0x7ffff7dc2000 + 0x421f0 = 0x7ffff7e041f0
```

You can see it only different in 2 last byte, but 1.5 last byte of aslr base always 0, so we just only have 0.5 byte random. We will bypass this by bruteforce 1 value until it correct. It special because both offset have 0x40000 prefix, so we don’t need to change the 3th last byte in the real address. If you want to change atoi to some function have offset 0x50000. You will have 1.5 byte random and the sucessrate is 1/4096 per attemp.

## Final payload

  - First, we change the exit GOT to main to recall the main function

  - Secone, we change 2 last byte of Atoi function to system function

  - Final, we put the “/bin/sh” to the nptr and call system(“/bin/sh”) to get a shell

File [solve.py](/2021/DownUnderCTF2021/write_what_where/solve.py)

```python
from pwn import *
s = remote('pwn-2021.duc.tf', 31920)
#s = process('./write-what-where')
#raw_input('DEBUG')
system = 0xfa600000
main = 0x4011a9
exit_plt = 0x000000404038
atoi_plt = 0x000000404030
s.sendafter(b'what?\n', p32(main))
payload = bytes(str(exit_plt), 'utf-8')
s.sendlineafter(b'where?\n', b'0' * (8 - len(payload)) + payload)
s.sendafter(b'what?\n', p32(system))
payload = bytes(str(atoi_plt - 2), 'utf-8')
s.sendlineafter(b'where?\n', b'0' * (8 - len(payload)) + payload)
s.sendafter(b'what?\n', b'A')
s.sendlineafter(b'where?\n', b'/bin/sh\x00')
s.interactive()
```

It not always work, but I you lucky (1/16), You will get the shell

`Flag: DUCTF{arb1tr4ry_wr1t3_1s_str0ng_www}`


