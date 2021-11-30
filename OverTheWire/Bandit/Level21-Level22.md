## Goal
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in `/etc/cron.d/` for the configuration and see what command is being executed.

## Solution
Connect to the server and look in `/etc/cron.d/`.  

![image](https://user-images.githubusercontent.com/44528004/136639493-3e6f7438-a8d1-49a6-92a1-d6aa246d9149.png)

We see a file, named `cronjob_bandit22`, may be our targer, let `cat` this.  

![image](https://user-images.githubusercontent.com/44528004/136639511-8991ebf3-57c0-496c-8ebf-bc513d943bc2.png)


Look at the configuration of `cronjob_bandit22`, I see that the shell script `/usr/bin/cronjon_bandit22.sh &> /dev/null` is excuted at reboot, and at every minute.

![image](https://user-images.githubusercontent.com/44528004/136639624-ef3789d2-4e5e-4612-91f7-62a9ee823db8.png)  

So we need to see what command is in the `/usr/bin/cronjon_bandit22.sh`.  

![image](https://user-images.githubusercontent.com/44528004/136639639-46577e3a-9701-4bf5-aae0-12633158ddae.png)  

We can see that it create a file `t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv` in `/tmp/` and cat the password of net level in it. Because the permission is 644, so we can read it, I use cat to read it.

![image](https://user-images.githubusercontent.com/44528004/136639652-c07ad083-fc2d-4796-8629-72e01ec20ea8.png)

> Flag: `Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI`
