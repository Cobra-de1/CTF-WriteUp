## Goal
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in `/etc/cron.d/` for the configuration and see what command is being executed.

## Solution
The challenge is same at level 21->22, but change the code in the sh file.  

![image](https://user-images.githubusercontent.com/44528004/136639684-98dce259-d46b-4915-8e23-326ddb177cdd.png)

So the code now still copy the password for next level to a file in `/tmp/`, but the name file is create by the command `$(echo I am user $myname | md5sum | cut -d ' ' -f 1)`.

So I find the result of the command by typing it again.

![image](https://user-images.githubusercontent.com/44528004/136639700-249a7694-6416-44f1-b28e-1aadb186e656.png)

And we know the name of file, just `cat` it.  

![image](https://user-images.githubusercontent.com/44528004/136639710-603e0e34-7199-4391-a8f9-72f725d53af6.png)
> Flag: `jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n`



