## Goal
The password for the next level is stored in a file `readme` in the homedirectory. Unfortunately, someone has modified `.bashrc` to log you out when you log in with SSH.

## Solution
From the instruction, we know that the `.bashrc` file of the `bandit18` user has been changed and we cannot login with SSH. But what this file is about?  
This file contains configuration for the `bash` shell. Therefore, we can try to login using another shell.  

From `/etc/shells`, we can see all available shells on the machine:
```sh
bandit17@bandit:~$ cat /etc/shells 
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
/usr/bin/screen
/usr/bin/tmux
/usr/bin/showtext
```

The `ssh` command has a `-t` option which is used to force a pseudo-terminal allocation, in other words this option makes the remote machine to open a specify shel. From the `/etc/shells` above, we can see that the `bandit` machine has `/bin/sh`, so let's go with it.
```sh
┌──(kali㉿kali)-[~]
└─$ ssh bandit18@bandit.labs.overthewire.org -p 2220 -t "/bin/sh"
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password: 
$ ls
readme
$ cat readme    
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```
> Flag: `IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x`
