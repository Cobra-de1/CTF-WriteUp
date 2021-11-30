## Goal
There is a git repository at `ssh://bandit30-git@localhost/home/bandit30-git/repo`. The password for the user `bandit30-git` is the same as for the user bandit30.

## Solution
The challenge is the same with previous, we connect to server, create a folder, clone the repo, and check the repo.  

![image](https://user-images.githubusercontent.com/44528004/136643121-a1e747b8-46a0-48bf-8dc7-46ba298c9f1f.png)  

After checking the repo, the old version, the branch, I find the secret tag in git repo.  

![image](https://user-images.githubusercontent.com/44528004/136643124-c2b19a91-ed0e-4020-8177-8119b35c3061.png)

> Flag: `47e603bb428404d265f59c42920d81e5`

