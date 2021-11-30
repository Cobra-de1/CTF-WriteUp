## Goal
The password for the next level can be retrieved by submitting the password of the current level to port `30001` on `localhost` using SSL encryption.

## Soltuion
First, we initiate an SSL connection to `localhost:30001`.
```sh
bandit15@bandit:~$ openssl s_client -connect localhost:30001 -ign_eof
```

And we got a bunch of stuff:
```
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEHxhZ+zANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjEwODA1MjEyMjEzWhcNMjIwODA1MjEyMjEzWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALqNmx6R
csRsPgzRcRsq5oQ4BC9AT/Yu473WbK4SRjHOWwuA4Oqk9w8SLKYZ39FrDEnXSZJw
xqKPR0AH72+l7Itv7X1H07VbeMTQoJVm6NsJm3cuyyxjRwfaIOUFsRtQQyvQlmw7
3CgTbd3wEk1CD+6jlksJj801Vd0uvZh1VVERAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBADjhbe3bTnDWsS4xt8FFg7PJIqNAxF6QjP+7xzJ4yMvWtPP6tVXo
F7SNI52juwH0nFDyM9KOrM/AknWqCYF+yfz6bLD7MaKZ+Kg3DiLaoVJOrVg6Y02+
0vq1rLsqGko5wamCFamx7X9CtFsV0WQjZdA53Na/VwehtlFpf/p20VAi
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 31FEF7D38BECBD57C0F5F79B238A8C69DC21DD04007290A6598C17B87F92610D
    Session-ID-ctx: 
    Master-Key: F266E83569A0E18967DB8133B5FCF7329A97D1EC741161D105AF6C42BB75A16FFEBFD1B75EF576D1F4C10B8360280E77
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 3a a9 fe 3b 12 a1 ed 2b-8d a6 cf aa 23 c9 12 88   :..;...+....#...
    0010 - 38 d4 53 16 c1 dc 9a e5-69 d9 cb 5e 26 b7 96 54   8.S.....i..^&..T
    0020 - 30 c6 b0 7d df 34 02 41-6d 04 41 cd 7c 8a ea a6   0..}.4.Am.A.|...
    0030 - f2 ad 5f 7f 48 06 69 9a-f6 fa a0 42 ef c5 97 e8   .._.H.i....B....
    0040 - 3e 31 36 0e f3 3f c5 ea-62 1c dc 5d 1f 5f 72 45   >16..?..b..]._rE
    0050 - af a8 07 55 44 bc ab 7a-38 c8 38 d4 22 90 35 6f   ...UD..z8.8.".5o
    0060 - f4 a7 ac 88 d9 85 42 f1-d2 02 37 b7 9f 9d 1f e3   ......B...7.....
    0070 - 83 99 93 94 b4 65 7e 46-7e 81 2d b8 ee 2c f6 c9   .....e~F~.-..,..
    0080 - 17 af 09 97 04 07 fe 83-94 ba b4 c1 32 c0 75 a6   ............2.u.
    0090 - 0d 03 0f 25 b2 3c f5 9b-4a d2 36 16 a3 93 2c f7   ...%.<..J.6...,.

    Start Time: 1632475776
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
```

Next, try to enter the current password:
```sh
BfMYroe26WYalil77FoDi9qh59eK5xNr
Correct!                                                                                                                                                                                                        
cluFn7wTiGryunymYOu4RcffSxQluehd                                                                                                                                                                                
                                                                                                                                                                                                                
closed 
```
> Flag: `cluFn7wTiGryunymYOu4RcffSxQluehd`
