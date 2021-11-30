## Goal
After all this git stuff its time for another escape. Good luck!  

## Solution
Connect to the server, we have a shell with all upper case.  

![image](https://user-images.githubusercontent.com/44528004/136643194-4992d412-b7d6-40a5-8031-2562c187f93e.png)  

I don’t know how to do next, so I read the command in challenge.  

![image](https://user-images.githubusercontent.com/44528004/136643201-1a0b1b88-6764-47ae-8376-23fca8b3df85.png)  

After googling, I find that the challenge use the Bourne shell, if you type the command `ls`, the shell excute is `sh LS`. After reading `man sh`, I find this.  

![image](https://user-images.githubusercontent.com/44528004/136643211-591decb7-688d-49af-823f-ba535273c68b.png)  

The variable 0 is set to the name of the shell or shell script. In this case it's `$0 = sh`. So if I run `$0`, the shell being excuted is `sh` which is our normal shell.  

![image](https://user-images.githubusercontent.com/44528004/136643229-40ac9f2d-a27e-4ae7-bc12-013e4a79ae37.png)
> Flag: `c9c3199ddf4121b10cf581a98d51caee`






