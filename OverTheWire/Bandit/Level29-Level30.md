## Goal
There is a git repository at `ssh://bandit29-git@localhost/home/bandit29-git/repo`. The password for the user `bandit29-git` is the same as for the user bandit29.

## Solution
The challenge is the same with previous, we connect to server, create a folder, clone the repo, and check the repo.  

![image](https://user-images.githubusercontent.com/44528004/136643091-faa37ce1-8645-4192-9be5-4b90a129af14.png)  

Check the repo, we cannot find password, check the old version too, so I continues to check at another branch.  

![image](https://user-images.githubusercontent.com/44528004/136643100-b2ac080a-a8f7-4cf4-8623-08fc56a3e807.png)  

Try to switch to dev branch and check, we find the password.  

![image](https://user-images.githubusercontent.com/44528004/136643103-6cf4a244-3443-4491-8a38-05bd84f23323.png)

> Flag: `5b90576bedb2cc04c86a9e924ce42faf`


