## Goal
The password for the next level is stored somewhere on the server and has all of the following properties:
- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

## Solution
```sh
bandit6@bandit:~$ cat `find / -user bandit7 -group bandit6 -size 33c 2> /dev/null`
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

> Flag: `HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs`
