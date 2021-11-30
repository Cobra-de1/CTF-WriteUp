## Goal
The password for the next level is stored in the file `data.txt`, which contains base64 encoded data.

## Solution
To decode base64 encoded data, we can use the `base64` command with `-d` option.
```sh
bandit10@bandit:~$ base64 -d ./data.txt 
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```
> Flag: `IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR`
