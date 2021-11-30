## Goal
The password for the next level is stored in a file called `-` located in the home directory
## Solution
To read a file with special characters, we can wrap the filename in a pair of quotes to make it a literal string.
```bash
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat ./'-'
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```
> Password: `CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9`
