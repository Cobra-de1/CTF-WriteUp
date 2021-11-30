## Goal
The password for the next level is stored in the file `data.txt` and is the only line of text that occurs only once.

## Solution
As the password is the text that occurs only once, we can use the `uniq` command. This command groups **adjacent** matching lines into a single group, in other words, it removes **adjacent duplicate** lines.  

To get the password, we first need to sort the content of `data.txt` to make matching lines **adjacent**, then we issue `uniq -u` to print the unique line.
```
bandit8@bandit:~$ cat ./data.txt | sort | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```
> Flag: `UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR`
