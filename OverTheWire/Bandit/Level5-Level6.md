## Goal
The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:
- human-readable
- 1033 bytes in size
- not executable

## Solution
This level is pretty the same as the last one, but there are some more things:
- 1033 bytes in size: We use `-size 1033c` option. Here `c` specifies bytes.
- not executable: We can use `! -executable`.

```bash
bandit5@bandit:~$ find . -type f -size 1033c ! -executable -exec file {} +| grep ASCII
./inhere/maybehere07/.file2: ASCII text, with very long lines
bandit5@bandit:~$ cat ./inhere/maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```
> Flag: `DXjZPULLxYr17uwoI01bNLQbtFemEgo7`
