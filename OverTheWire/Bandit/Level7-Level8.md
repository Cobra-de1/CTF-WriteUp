## Goal
The password for the next level is stored in the file `data.txt` next to the word **millionth**.

## Solution
The password is next to the word **millionth**, which means they are of the same line. Therefore, we can use the `grep` command to find the word **millionth**.
```sh
bandit7@bandit:~$ grep millionth ./data.txt 
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```
> Flag: `cvX2JJa4CFALtqS87jk27qwqGhBM9plV`
