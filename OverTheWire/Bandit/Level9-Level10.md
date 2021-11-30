## Goal
The password for the next level is stored in the file `data.txt` in one of the few human-readable strings, preceded by several `=` characters.

## Solution
In the `data.txt` file, human-readable and unreadable strings are mixed; therefore, we can use the `strings` command to only print readable (or printable) characters. Then we can `grep` for `=` to get the password.

```sh
bandit9@bandit:~$ strings ./data.txt | grep =
========== the*2i"4
=:G e
========== password
<I=zsGi
Z)========== is
A=|t&E
Zdb=
c^ LAh=3G
*SF=s
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
S=A.H&^
```
> Flag: `truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk`
