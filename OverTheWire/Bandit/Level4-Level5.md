## Goal
The password for the next level is stored in the only human-readable file in the **inhere** directory.
> **Tip:** if your terminal is messed up, try the “reset” command.

## Solution
To find a file in Linux, we can use the `find` command since it is powerful.  
- To find a file in the **inhere** directory, we specify the starting point `./inhere`
- To find a file, we use the `-type f` option to specify that we want to find regular files.
- To find a human-readable file, we can execute the `file` command and `grep` for ASCII since human-readable files will be of ASCII encoding. The filename from the `find` command will replace the `{}` and become the argument of the `file` command.
```bash
bandit4@bandit:~$ find ./inhere -type f -exec file {} + | grep ASCII
./inhere/-file07: ASCII text
bandit4@bandit:~$ cat ./inhere/'-file07'
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```
> Password: `koReBOKuIDDepwhWk7jZC0RTdopnAYKh`
