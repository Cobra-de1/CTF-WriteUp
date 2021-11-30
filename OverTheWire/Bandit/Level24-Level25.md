## Goal
A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

## Solution
The challenge goal is really clear, we need to netcat to port 30002, and send the password of bandit24 and 4 ditgit pincode, no way to find the pincode without bruteforce, so just login and write the srcipts.  

First create a folder with all permission.  

![image](https://user-images.githubusercontent.com/44528004/136642736-a3b724c4-cacb-4056-b759-790c6bbb45b8.png)  

Then create a solve.sh.  

![image](https://user-images.githubusercontent.com/44528004/136642750-5a622f30-c5ca-430d-9789-5801929dd96f.png)  

Save, `chomod` and run.  

![image](https://user-images.githubusercontent.com/44528004/136642762-7fe73666-f8f0-4709-8dd3-e16a6dc2097b.png)  

The solve.sh script will create 10000 line for each I from 0000 to 9999 and save it to bruteforce, then we give the bruteforce file to the input of `nc localhost 30002`. Then when the bruteforce success, we will give the password.  

![image](https://user-images.githubusercontent.com/44528004/136642773-a1988eec-1ebf-4002-ae57-4983638055be.png)  

> Flag: `uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG`


