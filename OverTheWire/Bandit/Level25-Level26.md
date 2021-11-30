## Goal
Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not `/bin/bash`, but something else. Find out what it is, how it works and how to break out of it.

## Solution
First login to the server.  

![image](https://user-images.githubusercontent.com/44528004/136642821-b13d0707-b130-40d6-86e2-b0e51871ba6b.png)  

We see a ssh key to login to bandit26, let try it.  

![image](https://user-images.githubusercontent.com/44528004/136642833-30f57636-ca30-4ba8-8b37-7e022d672800.png)  

But we fail,  

![image](https://user-images.githubusercontent.com/44528004/136642836-529d301f-45a7-4038-9421-13c515e21752.png)  

Look back to the goal of this chall, the shell using by bandit26 is not `/bin/bash`, so we find what is it. Just go to `/etc/passwd` and find the default shell:  

![image](https://user-images.githubusercontent.com/44528004/136642846-10803fba-180c-4310-9529-fb8183fc08e9.png)  

Look to `/usr/bin/showtext`.  

![image](https://user-images.githubusercontent.com/44528004/136642857-4d998add-7dca-4fb2-9c33-93c8d436e586.png)  

We see the command more `~/text.txt`, search gg for more command, I know that the more command is use to display long (text) files on small screens or in a size limited terminal window. So we try to minimize the terminal to see what happen.  

So we reach the `more` command.  

![image](https://user-images.githubusercontent.com/44528004/136642870-659ecef5-d78b-4d32-a32c-20afe66f9e8d.png)  

In the help menu of more command, we see a `v` option to startup `vi` at current line.  

![image](https://user-images.githubusercontent.com/44528004/136642880-3d6472d8-bc4e-4ef9-9392-95caafd6d0c1.png)  

So just open the vim, in vim, we can start the shell with the command:
```
:set shell=/bin/bash and then type :shell
```

![image](https://user-images.githubusercontent.com/44528004/136642899-d97ae489-95e0-4aaa-900b-630225435129.png)  

So we have the shell of bandit 26 to find password of bandit 27.  

![image](https://user-images.githubusercontent.com/44528004/136642909-e43517c2-2bfc-4117-a577-1d07fd83d850.png)


Get the flag.

![image](https://user-images.githubusercontent.com/44528004/136642917-df908760-5bb1-4df5-9701-d40e8e893458.png)

> Flag: `5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z`


