## Goal
The password for the next level can be retrieved by submitting the password of the current level to `port 30000` on `localhost`.

## Solution
In this level, I tried `nc` but nothing happens.
```sh
bandit14@bandit:~$ nc localhost -p 30000
no port[s] to connect to
```

So I tried `telnet`:
```sh
bandit14@bandit:~$ telnet localhost 30000
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
```

Got a connection. So let's enter the current password.
```sh
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr

Connection closed by foreign host.
```
> Flag: `BfMYroe26WYalil77FoDi9qh59eK5xNr`
