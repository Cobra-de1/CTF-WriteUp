## Goal
To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (`/etc/bandit_pass`), after you have used the setuid binary.

## Solution
Login to the server, we see 1 file name `bandit20-do`.  

![image](https://user-images.githubusercontent.com/44528004/136639322-80f98041-9875-4f5d-af0e-95bf330ceb31.png)  

This file have the `s` flag (means `setuid`). Look at the decription of `setuid`.

> The `setudi` binary file can allow us to execuve the file with the permission of the owner (`bandit20`). Any command excute by `bandit20-do` will run as user `bandit20`.  
 
We need permission of `bandit20` to `cat` the flag. So just give the command into the `bandit20-do`.  

![image](https://user-images.githubusercontent.com/44528004/136639379-3c8f373e-971c-433e-b486-0b54efb0f298.png)
> Flag: `GbKksEFF4yrVs6il55v6gwY5aVje5f0j`
