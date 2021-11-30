## Goal
There is a git repository at `ssh://bandit28-git@localhost/home/bandit28-git/repo`. The password for the user `bandit28-git` is the same as for the user bandit28.

## Solution
The challenge is the same with previous, we connect to server, create a folder, clone the repo, and check the repo.  

![image](https://user-images.githubusercontent.com/44528004/136643031-4abda1c1-d306-4c0d-bcca-f41c30032fd9.png)  

But there is no password in `README.md` file. Because there only one file, so I try to check previous version of `README.md` using `git log`.  

![image](https://user-images.githubusercontent.com/44528004/136643043-153c32e4-837c-4861-bd33-2f86d5b08922.png)  

We see that it have 3 version, so let check 2 old version.  

![image](https://user-images.githubusercontent.com/44528004/136643052-9627a6d0-f15b-4316-bb28-e22af642a6ff.png)  

And yeah, we find the password.  

![image](https://user-images.githubusercontent.com/44528004/136643061-ef9a0b92-7888-4e1a-8e57-fa21533cb2d1.png)
> Flag: `bbc96594b4e001778eee9975372716b2`



