## Goal
The password for the next level is stored in the file `data.txt`, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions.

## Solution
The content of `data.txt` is encoded in ROT13. To decode the text, we just need to *unshift* letters by 13 positions. To do that we can use the `tr` command with `SET1` and `SET2` as follows:
- `SET1 = 'n-za-mN-ZA-M'`
- `SET2 = 'a-zA-Z'`

```sh
bandit11@bandit:~$ cat ./data.txt | tr 'n-za-mN-ZA-M' 'a-zA-Z'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```
> Flag: `5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu`
