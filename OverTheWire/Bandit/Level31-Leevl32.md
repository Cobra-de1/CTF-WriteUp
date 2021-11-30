## Goal
There is a git repository at `ssh://bandit31-git@localhost/home/bandit31-git/repo`. The password for the user `bandit31-git` is the same as for the user bandit31.

## Solution
The challenge is the same with previous, we connect to server, create a folder, clone the repo, and check the repo.  

![image](https://user-images.githubusercontent.com/44528004/136643144-7f9d324b-e66f-4a7f-b9a5-155c26807ae3.png)

Check the repo.  

![image](https://user-images.githubusercontent.com/44528004/136643152-dd57e8e0-ba95-4e02-a064-0ac579014af9.png)  

In this chall, we need to create a file name key.txt and push to the repo. Use `vim` to create `key.txt`.  

![image](https://user-images.githubusercontent.com/44528004/136643158-7b8aee80-8862-4eb1-b7b2-2ceb3dfa7708.png)

Commit and push to repo.  

![image](https://user-images.githubusercontent.com/44528004/136643164-44c925d5-0be5-4070-8fd1-0a978ffc0a45.png)  

Get the password.  

![image](https://user-images.githubusercontent.com/44528004/136643179-756fa21d-d3f6-4b0a-a40c-55105481b26d.png)

> Flag: `56a9bf19c63d650ce78e6ec0354ee45e`
