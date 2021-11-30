## Goal
The password for the next level is stored in `/etc/bandit_pass/bandit14` and can only be read by user `bandit14`. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level.  
> **Note:** localhost is a hostname that refers to the machine you are working on.

## Solution
From the [given documentation about SSH], we know that SSH can be used to login to a computer without a password. Furthermore, suppose that we are at **computer A** and we want to login to **computer B**, the **computer B** must have our public key and the **computer A** must have both public and private key.
> "With public key authentication, the authenticating entity has a public key and a private key. Each key is a large number with special mathematical properties. The private key is kept on the computer you log in from, while the public key is stored on the .ssh/authorized_keys file on all the computers you want to log in to."

In this level, we are given a private key `sshkey.private`:
```sh
bandit13@bandit:~$ ls
sshkey.private
```

So we can use this to login to the *localhost* machine as user `bandit14`.
```sh
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
```

And we're in!
```shc
bandit14@bandit:~$ 
```

Let's get our password:
```sh
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```
> Flag: `4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e`
