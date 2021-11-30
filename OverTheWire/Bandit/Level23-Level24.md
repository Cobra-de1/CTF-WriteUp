## Goal
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in `/etc/cron.d/` for the configuration and see what command is being executed.  
**NOTE:** This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!  
**NOTE 2:** Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

## Solution
Let login to the server and check `/etc/cron.d/`.  

![image](https://user-images.githubusercontent.com/44528004/136642597-fdbee296-9f89-4a59-8a44-f6d35030ff61.png)  

The chall is same as 2 previous, we have `/usr/bin/cronjob_bandit24.sh` run every minutes. But the command run in script is different.  

![image](https://user-images.githubusercontent.com/44528004/136642615-dd39325f-93aa-4d08-b00b-def4cfdf56db.png)

We see that, all file in `/var/spool/bandit24` will be excute and delete. So we need to create a solve.sh file and copy it into `/var/spool/` to excute it, and cat the password to a file we can read.  

So first create a folder with all permission ( this is very important that the folder can write by any user). 

![image](https://user-images.githubusercontent.com/44528004/136642639-740c0bb0-11db-4263-ba0b-f78c2ba0c53e.png)  

Go to this folder and create a file `solve.sh` (we can create in this folder because we created it).  

![image](https://user-images.githubusercontent.com/44528004/136642661-5d6a9cbf-5e89-400e-a77e-328c9c3ebd11.png)


In the solve.sh, we write script to cat `/etc/bandit_pass/bandit24 > /tmp/Cobra-de1/password`, the password will cat to a file password in our folder.  

![image](https://user-images.githubusercontent.com/44528004/136642672-0a7bd1f1-5c71-455f-9ee1-0b23b4a1dfcc.png)  

Now copy to the `/var/spool/bandit24/` and wait 1 minutes before seeing `password`.

![image](https://user-images.githubusercontent.com/44528004/136642707-7bf108ac-d35f-4588-ba19-1a021a2880ff.png)

> Flag: `UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ`

