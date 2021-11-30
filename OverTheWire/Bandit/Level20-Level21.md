## Goal
There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

## Solution
Login into the server, we see a file name `suconnect`.  

![image](https://user-images.githubusercontent.com/44528004/136639399-6e4e0a42-7e0c-42a5-a11e-11ff6a70ad35.png)  

As the goal tells us how the `suconnect` works. So we need to run `suconnect` with a specify port number that will respond the password of the bandit20.  
But because `nc` is allowed in the chall, so we just need to create a `localhost` netcat listening in a random port and use the `suconnect` connect to it, and then we enter the bandit20 password on the netcat listening, so it will send to the `suconnect`, and the `suconnect` receives the correct password, so it sends the password for the next level to the `nc`.  

![image](https://user-images.githubusercontent.com/44528004/136639440-de69dad4-5a1b-470b-bd05-3c7724f3a310.png)
> Flag: `gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr`
