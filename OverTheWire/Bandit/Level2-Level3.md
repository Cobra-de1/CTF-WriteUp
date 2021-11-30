## Goal
The password for the next level is stored in a file called **spaces in this filename** located in the home directory

## Solution
In case there are spaces in a filename, we can either use a pair of quotes to make it a literal string or escape whitespace characters with `\`.
```bash
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat ./spaces\ in\ this\ filename 
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
# or
bandit2@bandit:~$ cat ./'spaces in this filename'
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```
> Flag: `UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK`
