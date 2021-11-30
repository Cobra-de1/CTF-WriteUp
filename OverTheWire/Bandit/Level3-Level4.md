## Goal
The password for the next level is stored in a hidden file in the **inhere** directory.

## Solution
To `ls` all files and directories, we can use the `-a` option to list **all**.
```bash
bandit3@bandit:~$ ls -a ./inhere/
.  ..  .hidden
bandit3@bandit:~$ cat ./inhere/.hidden 
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```
> Flag: `pIwrPrtPN36QITSp3EQaw936yaFoFgAB`
